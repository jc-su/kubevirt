/*
 * This file is part of the KubeVirt project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright The KubeVirt Authors.
 *
 */

package trustd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kubevirt.io/client-go/log"

	v1 "kubevirt.io/api/core/v1"
)

const (
	watchReconnectBackoff              = 2 * time.Second
	defaultHeartbeatIntervalSecs       = 30
	heartbeatTimeoutMultiplier   int32 = 3
	remediationBeginPrefix             = "remediation_begin"
	remediationDonePrefix              = "remediation_done"
	remediationFailedPrefix            = "remediation_failed"
)

// AttestationVerifier is the interface for the external attestation service.
// The collector sends evidence to the verifier and receives a verdict.
type AttestationVerifier interface {
	// VerifyEvidence sends attestation evidence to the verifier and returns a verdict.
	VerifyEvidence(ctx context.Context, evidence *AttestContainerResponse) (*VerificationResult, error)
}

// AuthorityVerdictUpdate carries an authority push update for a subject.
type AuthorityVerdictUpdate struct {
	Subject          string
	CgroupPath       string
	Verdict          v1.ContainerTrustVerdict
	Message          string
	AttestationToken string
	PolicyAction     RemediationAction
	Version          uint64
}

// AttestationVerdictWatcher optionally streams authority verdict updates.
type AttestationVerdictWatcher interface {
	WatchVerdictUpdates(
		ctx context.Context,
		subjects []string,
		afterVersion uint64,
		handler func(AuthorityVerdictUpdate) error,
	) error
}

// VerificationResult is the verdict from the attestation service.
type VerificationResult struct {
	Verdict          v1.ContainerTrustVerdict
	Message          string
	AttestationToken string
	PolicyAction     RemediationAction
}

// RemediationAction describes how trustd should remediate unhealthy containers.
type RemediationAction string

const (
	RemediationActionNone    RemediationAction = "none"
	RemediationActionAlert   RemediationAction = "alert"
	RemediationActionRestart RemediationAction = "restart"
	RemediationActionKill    RemediationAction = "kill"

	defaultRemediationCooldown = 60 * time.Second
)

// RemediationPolicy configures how collector verdicts are enforced.
type RemediationPolicy struct {
	OnUntrusted RemediationAction
	OnStale     RemediationAction
	Cooldown    time.Duration
}

// DefaultRemediationPolicy is conservative and only prevents rapid restart loops.
func DefaultRemediationPolicy() RemediationPolicy {
	return RemediationPolicy{
		OnUntrusted: RemediationActionNone,
		OnStale:     RemediationActionNone,
		Cooldown:    defaultRemediationCooldown,
	}
}

func (p RemediationPolicy) actionForVerdict(verdict v1.ContainerTrustVerdict) RemediationAction {
	switch verdict {
	case v1.ContainerTrustVerdictUntrusted:
		return p.OnUntrusted
	case v1.ContainerTrustVerdictStale:
		return p.OnStale
	default:
		return RemediationActionNone
	}
}

type trustdClient interface {
	ListContainers(ctx context.Context) ([]ContainerState, error)
	WatchContainerEvents(ctx context.Context, handler func(ContainerEvent) error) error
	AttestContainer(ctx context.Context, req *AttestContainerRequest) (*AttestContainerResponse, error)
	RestartContainer(ctx context.Context, cgroupPath string) (*ContainerState, error)
	StartHeartbeatMonitor(ctx context.Context, cgroupPath string, timeoutSeconds uint32) error
	StopHeartbeatMonitor(ctx context.Context, cgroupPath string) error
	ReportHeartbeat(ctx context.Context, cgroupPath string) error
}

// TrustStateCollector keeps VMI trust states synchronized with trustd.
// It performs an initial sweep, then combines event-driven updates with
// optional periodic re-attestation.
type TrustStateCollector struct {
	client               trustdClient
	verifier             AttestationVerifier
	remediationPolicy    RemediationPolicy
	attestationInterval  time.Duration
	heartbeatInterval    time.Duration
	heartbeatTimeoutSecs uint32

	mu                 sync.RWMutex
	stateMap           map[string]v1.ContainerTrustState
	lastRemediation    map[string]time.Time
	heartbeatMonitored map[string]struct{}
	pendingRebootstrap map[string]struct{}
	lastVerdictVersion uint64

	stopCh chan struct{}
	doneCh chan struct{}
}

// NewTrustStateCollector creates a collector that combines event-driven updates
// with optional periodic re-attestation.
func NewTrustStateCollector(
	client trustdClient,
	verifier AttestationVerifier,
	attestationIntervalSeconds *int32,
	heartbeatIntervalSeconds *int32,
	remediationPolicy RemediationPolicy,
) *TrustStateCollector {
	if remediationPolicy.Cooldown <= 0 {
		remediationPolicy.Cooldown = defaultRemediationCooldown
	}

	return &TrustStateCollector{
		client:              client,
		verifier:            verifier,
		remediationPolicy:   remediationPolicy,
		attestationInterval: attestationIntervalDuration(attestationIntervalSeconds),
		heartbeatInterval:   heartbeatIntervalDuration(heartbeatIntervalSeconds),
		heartbeatTimeoutSecs: heartbeatMonitorTimeoutSeconds(
			heartbeatIntervalSeconds,
		),
		stateMap:           make(map[string]v1.ContainerTrustState),
		lastRemediation:    make(map[string]time.Time),
		heartbeatMonitored: make(map[string]struct{}),
		pendingRebootstrap: make(map[string]struct{}),
		lastVerdictVersion: 0,
		stopCh:             make(chan struct{}),
		doneCh:             make(chan struct{}),
	}
}

// Start begins the collector loop in a goroutine.
func (c *TrustStateCollector) Start() {
	go c.run()
}

// Stop signals the collector to stop and waits for it to finish.
func (c *TrustStateCollector) Stop() {
	close(c.stopCh)
	<-c.doneCh
}

// GetStates returns a deterministic snapshot sorted by container ID.
func (c *TrustStateCollector) GetStates() []v1.ContainerTrustState {
	c.mu.RLock()
	states := make([]v1.ContainerTrustState, 0, len(c.stateMap))
	for _, state := range c.stateMap {
		states = append(states, state)
	}
	c.mu.RUnlock()

	sort.SliceStable(states, func(i, j int) bool {
		return states[i].ContainerID < states[j].ContainerID
	})
	return states
}

func (c *TrustStateCollector) run() {
	defer close(c.doneCh)

	c.initialSweep()

	periodicDone := make(chan struct{})
	if c.attestationInterval > 0 {
		go func() {
			defer close(periodicDone)
			c.periodicAttestationLoop()
		}()
	} else {
		close(periodicDone)
	}
	defer func() {
		<-periodicDone
	}()

	heartbeatDone := make(chan struct{})
	if c.heartbeatInterval > 0 && c.heartbeatTimeoutSecs > 0 {
		go func() {
			defer close(heartbeatDone)
			c.livenessHeartbeatLoop()
		}()
	} else {
		close(heartbeatDone)
	}
	defer func() {
		<-heartbeatDone
	}()

	verdictDone := make(chan struct{})
	if watcher, ok := c.verifier.(AttestationVerdictWatcher); ok && watcher != nil {
		go func() {
			defer close(verdictDone)
			c.authorityWatchLoop(watcher)
		}()
	} else {
		close(verdictDone)
	}
	defer func() {
		<-verdictDone
	}()

	for {
		select {
		case <-c.stopCh:
			return
		default:
		}

		watchCtx, cancel := context.WithCancel(context.Background())
		watchDone := make(chan struct{})
		go func() {
			defer close(watchDone)
			select {
			case <-c.stopCh:
				cancel()
			case <-watchCtx.Done():
			}
		}()

		err := c.client.WatchContainerEvents(watchCtx, func(event ContainerEvent) error {
			c.handleEvent(event)
			return nil
		})
		cancel()
		<-watchDone

		select {
		case <-c.stopCh:
			return
		default:
		}

		if err != nil {
			log.DefaultLogger().Warningf("trustd event stream ended: %v", err)
		} else {
			log.DefaultLogger().Warningf("trustd event stream ended; reconnecting")
		}

		select {
		case <-c.stopCh:
			return
		case <-time.After(watchReconnectBackoff):
		}
	}
}

func (c *TrustStateCollector) authorityWatchLoop(watcher AttestationVerdictWatcher) {
	c.mu.RLock()
	afterVersion := c.lastVerdictVersion
	c.mu.RUnlock()

	for {
		select {
		case <-c.stopCh:
			return
		default:
		}

		watchCtx, cancel := context.WithCancel(context.Background())
		watchDone := make(chan struct{})
		go func() {
			defer close(watchDone)
			select {
			case <-c.stopCh:
				cancel()
			case <-watchCtx.Done():
			}
		}()

		err := watcher.WatchVerdictUpdates(
			watchCtx,
			nil,
			afterVersion,
			func(update AuthorityVerdictUpdate) error {
				if update.Version > afterVersion {
					afterVersion = update.Version
					c.recordLastVerdictVersion(update.Version)
				}
				c.handleVerdictUpdate(update)
				return nil
			},
		)
		cancel()
		<-watchDone

		select {
		case <-c.stopCh:
			return
		default:
		}

		if err != nil {
			log.DefaultLogger().Warningf("attestation authority watch stream ended: %v", err)
		} else {
			log.DefaultLogger().Warningf("attestation authority watch stream ended; reconnecting")
		}

		select {
		case <-c.stopCh:
			return
		case <-time.After(watchReconnectBackoff):
		}
	}
}

func (c *TrustStateCollector) recordLastVerdictVersion(version uint64) {
	if version == 0 {
		return
	}
	c.mu.Lock()
	if version > c.lastVerdictVersion {
		c.lastVerdictVersion = version
	}
	c.mu.Unlock()
}

func (c *TrustStateCollector) initialSweep() {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultRequestTimeout)
	defer cancel()

	c.attestAllKnownContainers(ctx)
	if c.heartbeatInterval > 0 && c.heartbeatTimeoutSecs > 0 {
		c.sendLivenessHeartbeats(ctx)
	}
}

func (c *TrustStateCollector) periodicAttestationLoop() {
	ticker := time.NewTicker(c.attestationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), DefaultRequestTimeout)
			c.attestAllKnownContainers(ctx)
			cancel()
		}
	}
}

func (c *TrustStateCollector) livenessHeartbeatLoop() {
	ticker := time.NewTicker(c.heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), DefaultRequestTimeout)
			c.sendLivenessHeartbeats(ctx)
			cancel()
		}
	}
}

func (c *TrustStateCollector) sendLivenessHeartbeats(ctx context.Context) {
	containers, err := c.client.ListContainers(ctx)
	if err != nil {
		log.DefaultLogger().Warningf("Failed to list containers for heartbeat refresh: %v", err)
		return
	}

	current := make(map[string]struct{}, len(containers))
	for _, container := range containers {
		cgroupPath := canonicalCgroupPath(container.CgroupPath)
		if cgroupPath == "" {
			continue
		}
		current[cgroupPath] = struct{}{}
		c.ensureHeartbeatMonitor(ctx, cgroupPath)
		if err := c.client.ReportHeartbeat(ctx, cgroupPath); err != nil {
			log.DefaultLogger().V(4).Infof("Failed to report heartbeat for %s: %v", cgroupPath, err)
		}
	}
	c.pruneAbsentContainers(current)
}

func (c *TrustStateCollector) attestAllKnownContainers(ctx context.Context) {
	containers, err := c.client.ListContainers(ctx)
	if err != nil {
		log.DefaultLogger().Warningf("Failed to list containers from trustd: %v", err)
		return
	}

	current := make(map[string]struct{}, len(containers))
	for _, container := range containers {
		current[container.CgroupPath] = struct{}{}
		c.ensureHeartbeatMonitor(ctx, container.CgroupPath)

		state, action := c.attestContainer(ctx, container.CgroupPath)
		c.maybeRemediate(&state, action)
		if container.LastHeartbeat > 0 {
			hb := metav1.NewTime(time.Unix(container.LastHeartbeat, 0))
			state.LastHeartbeat = &hb
		}
		c.setState(state)
	}

	c.pruneAbsentContainers(current)
}

func (c *TrustStateCollector) handleEvent(event ContainerEvent) {
	switch event.EventType {
	case EventTypeNew, EventTypeMeasurement:
		ctx, cancel := context.WithTimeout(context.Background(), DefaultRequestTimeout)
		c.ensureHeartbeatMonitor(ctx, event.CgroupPath)
		state, action := c.attestContainer(ctx, event.CgroupPath)
		c.maybeRemediate(&state, action)
		cancel()
		c.setState(state)

	case EventTypeHeartbeat:
		c.mu.Lock()
		state, ok := c.stateMap[event.CgroupPath]
		if !ok {
			state = v1.ContainerTrustState{
				ContainerID: event.CgroupPath,
				Verdict:     v1.ContainerTrustVerdictUnknown,
			}
		}
		now := metav1.Now()
		if event.Timestamp > 0 {
			now = metav1.NewTime(time.Unix(event.Timestamp, 0))
		}
		state.LastHeartbeat = &now
		c.stateMap[event.CgroupPath] = state
		c.mu.Unlock()

	case EventTypeHeartbeatMiss:
		state := c.currentStateOrUnknown(event.CgroupPath)
		state.Verdict = v1.ContainerTrustVerdictStale
		if !strings.Contains(state.VerdictMessage, "heartbeat timeout detected by trustd") {
			state.VerdictMessage = appendMessage(state.VerdictMessage, "heartbeat timeout detected by trustd")
		}
		if state.LastHeartbeat == nil && event.Timestamp > 0 {
			hb := metav1.NewTime(time.Unix(event.Timestamp, 0))
			state.LastHeartbeat = &hb
		}
		c.maybeRemediate(&state, RemediationActionNone)
		c.setState(state)

	case EventTypeAttestBegin, EventTypeAttestEnd:
		if c.handleRemediationLifecycleEvent(event) {
			return
		}

	case EventTypeRemoved:
		c.disableHeartbeatMonitor(event.CgroupPath)
		c.mu.Lock()
		delete(c.stateMap, event.CgroupPath)
		delete(c.lastRemediation, event.CgroupPath)
		delete(c.pendingRebootstrap, event.CgroupPath)
		c.mu.Unlock()
	}
}

func (c *TrustStateCollector) handleRemediationLifecycleEvent(event ContainerEvent) bool {
	detail := strings.TrimSpace(event.Detail)
	if detail == "" {
		return false
	}

	switch {
	case strings.HasPrefix(detail, remediationBeginPrefix):
		c.setPendingRebootstrap(event.CgroupPath, true)
		state := c.currentStateOrUnknown(event.CgroupPath)
		state.Verdict = v1.ContainerTrustVerdictStale
		state.VerdictMessage = appendMessage(state.VerdictMessage, "remediation started")
		c.setState(state)
		return true

	case strings.HasPrefix(detail, remediationDonePrefix):
		c.setPendingRebootstrap(event.CgroupPath, true)
		c.forceReattestAfterRemediation(event.CgroupPath)
		return true

	case strings.HasPrefix(detail, remediationFailedPrefix):
		c.setPendingRebootstrap(event.CgroupPath, true)
		state := c.currentStateOrUnknown(event.CgroupPath)
		state.Verdict = v1.ContainerTrustVerdictUntrusted
		state.VerdictMessage = appendMessage(state.VerdictMessage, detail)
		c.setState(state)
		return true

	default:
		return false
	}
}

func (c *TrustStateCollector) forceReattestAfterRemediation(cgroupPath string) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultRequestTimeout)
	defer cancel()

	state, action := c.attestContainer(ctx, cgroupPath)
	if state.Verdict == v1.ContainerTrustVerdictUnknown {
		state.Verdict = v1.ContainerTrustVerdictStale
		state.VerdictMessage = appendMessage(state.VerdictMessage, "post-remediation attestation pending")
	}
	c.maybeRemediate(&state, action)
	c.setState(state)
}

func (c *TrustStateCollector) handleVerdictUpdate(update AuthorityVerdictUpdate) {
	cgroupPath := canonicalCgroupPath(update.CgroupPath)
	if cgroupPath == "" {
		cgroupPath = cgroupPathFromSubject(update.Subject)
	}
	if cgroupPath == "" {
		return
	}

	c.mu.RLock()
	state, exists := c.stateMap[cgroupPath]
	_, monitored := c.heartbeatMonitored[cgroupPath]
	c.mu.RUnlock()
	if !exists && !monitored {
		return
	}
	if !exists {
		state = v1.ContainerTrustState{
			ContainerID: cgroupPath,
			Verdict:     v1.ContainerTrustVerdictUnknown,
		}
	}

	state.ContainerID = cgroupPath
	state.Verdict = update.Verdict
	if update.Message != "" {
		state.VerdictMessage = update.Message
	}
	if update.AttestationToken != "" {
		state.AttestationToken = update.AttestationToken
	}

	c.maybeRemediate(&state, normalizeRemediationAction(update.PolicyAction))
	c.setState(state)
}

func (c *TrustStateCollector) currentStateOrUnknown(containerID string) v1.ContainerTrustState {
	c.mu.RLock()
	state, ok := c.stateMap[containerID]
	c.mu.RUnlock()
	if ok {
		return state
	}
	return v1.ContainerTrustState{
		ContainerID: containerID,
		Verdict:     v1.ContainerTrustVerdictUnknown,
	}
}

func (c *TrustStateCollector) attestContainer(ctx context.Context, cgroupPath string) (v1.ContainerTrustState, RemediationAction) {
	now := metav1.Now()
	state := v1.ContainerTrustState{
		ContainerID: cgroupPath,
		Verdict:     v1.ContainerTrustVerdictUnknown,
	}
	action := RemediationActionNone

	nonceHex, err := newCollectorNonceHex()
	if err != nil {
		state.VerdictMessage = fmt.Sprintf("nonce generation failed: %v", err)
		return state, action
	}

	evidence, err := c.client.AttestContainer(ctx, &AttestContainerRequest{
		CgroupPath:     cgroupPath,
		NonceHex:       nonceHex,
		IncludeTDQuote: true,
	})
	if err != nil {
		state.VerdictMessage = fmt.Sprintf("attestation failed: %v", err)
		return state, action
	}

	state.RTMR3 = evidence.RTMR3
	state.MeasurementCount = evidence.MeasurementCount
	state.LastAttestation = &now

	if c.verifier != nil {
		result, err := c.verifier.VerifyEvidence(ctx, evidence)
		if err != nil {
			state.VerdictMessage = fmt.Sprintf("verification failed: %v", err)
		} else {
			state.Verdict = result.Verdict
			state.VerdictMessage = result.Message
			state.AttestationToken = result.AttestationToken
			action = normalizeRemediationAction(result.PolicyAction)
		}
	}

	return state, action
}

func (c *TrustStateCollector) setState(state v1.ContainerTrustState) {
	state = c.enforcePendingRebootstrap(state)
	c.mu.Lock()
	c.stateMap[state.ContainerID] = state
	c.mu.Unlock()
}

func (c *TrustStateCollector) setPendingRebootstrap(containerID string, pending bool) {
	if containerID == "" {
		return
	}
	c.mu.Lock()
	if pending {
		c.pendingRebootstrap[containerID] = struct{}{}
	} else {
		delete(c.pendingRebootstrap, containerID)
	}
	c.mu.Unlock()
}

func (c *TrustStateCollector) enforcePendingRebootstrap(state v1.ContainerTrustState) v1.ContainerTrustState {
	if state.ContainerID == "" {
		return state
	}

	c.mu.Lock()
	_, pending := c.pendingRebootstrap[state.ContainerID]
	if !pending {
		c.mu.Unlock()
		return state
	}

	if state.Verdict == v1.ContainerTrustVerdictTrusted {
		delete(c.pendingRebootstrap, state.ContainerID)
		c.mu.Unlock()
		if !strings.Contains(state.VerdictMessage, "rebootstrap complete") {
			state.VerdictMessage = appendMessage(state.VerdictMessage, "rebootstrap complete")
		}
		return state
	}
	c.mu.Unlock()

	if state.Verdict == v1.ContainerTrustVerdictUnknown {
		state.Verdict = v1.ContainerTrustVerdictStale
	}
	if !strings.Contains(state.VerdictMessage, "pending rebootstrap") {
		state.VerdictMessage = appendMessage(state.VerdictMessage, "pending rebootstrap")
	}
	return state
}

func (c *TrustStateCollector) ensureHeartbeatMonitor(ctx context.Context, cgroupPath string) {
	if c.heartbeatTimeoutSecs == 0 {
		return
	}

	c.mu.RLock()
	_, monitored := c.heartbeatMonitored[cgroupPath]
	c.mu.RUnlock()
	if monitored {
		return
	}

	if err := c.client.StartHeartbeatMonitor(ctx, cgroupPath, c.heartbeatTimeoutSecs); err != nil {
		log.DefaultLogger().Warningf(
			"Failed to enable heartbeat monitor for %s: %v",
			cgroupPath,
			err,
		)
		return
	}

	c.mu.Lock()
	c.heartbeatMonitored[cgroupPath] = struct{}{}
	c.mu.Unlock()
}

func (c *TrustStateCollector) disableHeartbeatMonitor(cgroupPath string) {
	c.mu.Lock()
	_, monitored := c.heartbeatMonitored[cgroupPath]
	if monitored {
		delete(c.heartbeatMonitored, cgroupPath)
	}
	c.mu.Unlock()
	if !monitored {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), DefaultRequestTimeout)
	defer cancel()
	if err := c.client.StopHeartbeatMonitor(ctx, cgroupPath); err != nil {
		log.DefaultLogger().V(4).Infof(
			"Failed to disable heartbeat monitor for %s: %v",
			cgroupPath,
			err,
		)
	}
}

func (c *TrustStateCollector) pruneAbsentContainers(current map[string]struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for containerID := range c.stateMap {
		if _, ok := current[containerID]; ok {
			continue
		}
		delete(c.stateMap, containerID)
		delete(c.lastRemediation, containerID)
		delete(c.heartbeatMonitored, containerID)
		delete(c.pendingRebootstrap, containerID)
	}
}

func (c *TrustStateCollector) maybeRemediate(state *v1.ContainerTrustState, recommended RemediationAction) {
	if state == nil {
		return
	}

	action := normalizeRemediationAction(recommended)
	if action == RemediationActionNone {
		action = c.remediationPolicy.actionForVerdict(state.Verdict)
	}
	if action == RemediationActionNone {
		return
	}

	if action == RemediationActionAlert {
		state.VerdictMessage = appendMessage(state.VerdictMessage, "policy requested alert (no restart action)")
		return
	}

	if action == RemediationActionKill {
		// trustd currently exposes restart as the remediation primitive.
		state.VerdictMessage = appendMessage(state.VerdictMessage, "policy requested kill; mapped to restart remediation")
		action = RemediationActionRestart
	}

	now := time.Now()
	if !c.markRemediationIfDue(state.ContainerID, now) {
		state.VerdictMessage = appendMessage(state.VerdictMessage, "remediation suppressed by cooldown")
		return
	}

	switch action {
	case RemediationActionRestart:
		c.setPendingRebootstrap(state.ContainerID, true)
		ctx, cancel := context.WithTimeout(context.Background(), DefaultRequestTimeout)
		_, err := c.client.RestartContainer(ctx, state.ContainerID)
		cancel()
		if err != nil {
			log.DefaultLogger().Warningf("Failed to remediate container %s with restart: %v", state.ContainerID, err)
			state.VerdictMessage = appendMessage(state.VerdictMessage, fmt.Sprintf("remediation restart failed: %v", err))
		} else {
			log.DefaultLogger().Infof("Requested restart remediation for container %s due to verdict %s", state.ContainerID, state.Verdict)
			state.VerdictMessage = appendMessage(state.VerdictMessage, "remediation action restart requested")
		}
	}
}

func normalizeRemediationAction(action RemediationAction) RemediationAction {
	switch action {
	case RemediationActionNone, RemediationActionAlert, RemediationActionRestart, RemediationActionKill:
		return action
	default:
		return RemediationActionNone
	}
}

func (c *TrustStateCollector) markRemediationIfDue(containerID string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	last, exists := c.lastRemediation[containerID]
	if exists && now.Sub(last) < c.remediationPolicy.Cooldown {
		return false
	}

	c.lastRemediation[containerID] = now
	return true
}

func appendMessage(base, extra string) string {
	if base == "" {
		return extra
	}
	return fmt.Sprintf("%s; %s", base, extra)
}

func newCollectorNonceHex() (string, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce), nil
}

func attestationIntervalDuration(raw *int32) time.Duration {
	if raw == nil || *raw <= 0 {
		return 0
	}
	return time.Duration(*raw) * time.Second
}

func heartbeatMonitorTimeoutSeconds(raw *int32) uint32 {
	heartbeatInterval := int32(defaultHeartbeatIntervalSecs)
	if raw != nil && *raw > 0 {
		heartbeatInterval = *raw
	}

	timeout := heartbeatInterval * heartbeatTimeoutMultiplier
	if timeout <= 0 {
		timeout = 1
	}
	return uint32(timeout)
}

func heartbeatIntervalDuration(raw *int32) time.Duration {
	interval := int32(defaultHeartbeatIntervalSecs)
	if raw != nil && *raw > 0 {
		interval = *raw
	}
	if interval <= 0 {
		return 0
	}
	return time.Duration(interval) * time.Second
}

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

package virthandler

import (
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	k8sv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kubevirt.io/client-go/log"

	v1 "kubevirt.io/api/core/v1"

	"kubevirt.io/kubevirt/pkg/controller"
	"kubevirt.io/kubevirt/pkg/util"
	trustd "kubevirt.io/kubevirt/pkg/virt-handler/trustd"
)

// cvmTrustManager keeps one trustd client connection per TDX VMI and runs
// a canonical drift subscriber on each. The subscriber's job is to react
// to trustd-published PhaseChange events (Trusted → Untrusted, produced by
// trustd's in-guest drift detector) and call trustd.RestartContainer for
// the configured RemediationAction.
//
// Host-side verdict reporting (ContainerTrustStates on VMI.Status) now
// comes from attestation-service.WatchVerdictUpdates, not from a polling
// collector. That wiring is orthogonal and lives outside this manager.
type cvmTrustManager struct {
	mu       sync.RWMutex
	clients  map[string]*trustd.Client     // key: vmi.UID
	cancels  map[string]context.CancelFunc // key: vmi.UID — cancels drift subscriber
	policy   cvmDriftPolicy
	cooldown time.Duration
	// Track which container specs have been delivered to avoid re-sending
	// on every reconcile tick. Key: vmi.UID, value: set of container names.
	deliveredSpecs map[string]map[string]bool
	// Per-VMI list of workload_ids for the attestation verdict mirror
	// (VMI.Status.ContainerTrustStates is built from this).
	workloadIDs map[string][]string

	// One process-wide attestation-service verdict subscriber. nil when
	// TRUSTFNCALL_ATTESTATION_SERVICE_ADDR is unset — the drift subscriber
	// still enforces without it, but VMI.Status.ContainerTrustStates stays
	// empty.
	asClient   *trustd.ASClient
	mirror     *trustd.VerdictMirror
	mirrorCtx  context.Context
	mirrorStop context.CancelFunc
}

// cvmDriftPolicy is a static RemediationAction applied on every Untrusted
// transition. Distinct values for Untrusted vs Stale let operators be
// strict about drift but lenient about stale TCB collateral, which is a
// normal production distinction.
type cvmDriftPolicy struct {
	OnUntrusted trustd.RemediationAction
	OnStale     trustd.RemediationAction
}

// ActionFor implements trustd.PolicyLookup. The event log drift detector
// in trustd only publishes Untrusted transitions today (Stale is an AS-side
// verdict for expired quote collateral, pushed via UpdateLatestVerdict),
// so we map Untrusted here. The Stale path is reserved for a future AS
// subscriber that pushes Stale verdicts into the DriftSubscriber loop.
func (p cvmDriftPolicy) ActionFor(_ context.Context, _, _ string) trustd.RemediationAction {
	return p.OnUntrusted
}

// cvmTrustdNeeded decides whether virt-handler should maintain a trustd
// vsock connection + drift subscriber for this VMI.
//
//  1. TDX attestation is requested → need drift enforcement.
//  2. The VMI carries a trustd.ContainerSpecAnnotation → trustd is the
//     *delivery channel* for container specs, even on non-TDX VMIs
//     (used for cold-start benchmarking where attestation is off-path).
func cvmTrustdNeeded(vmi *v1.VirtualMachineInstance) bool {
	if util.IsTDXAttestationRequested(vmi) {
		return true
	}
	if vmi == nil || vmi.Annotations == nil {
		return false
	}
	_, has := vmi.Annotations[trustd.ContainerSpecAnnotation]
	return has
}

func newCVMTrustManager() *cvmTrustManager {
	policy, cooldown := remediationPolicyFromEnv()
	m := &cvmTrustManager{
		clients:        make(map[string]*trustd.Client),
		cancels:        make(map[string]context.CancelFunc),
		deliveredSpecs: make(map[string]map[string]bool),
		workloadIDs:    make(map[string][]string),
		policy:         policy,
		cooldown:       cooldown,
	}

	// Best-effort: spin up the verdict mirror subscriber. Missing env =
	// mirror disabled (silent no-op). Connection errors are non-fatal —
	// drift enforcement via trustd still works without the authority.
	asClient, err := trustd.NewASClientFromEnv()
	if err != nil {
		log.DefaultLogger().Warningf("attestation-service client init failed; VMI trust states will be empty: %v", err)
	} else if asClient != nil {
		m.asClient = asClient
		m.mirror = trustd.NewVerdictMirror()
		m.mirrorCtx, m.mirrorStop = context.WithCancel(context.Background())
		// Empty `subjects` = watch all verdicts; we filter per VMI on read.
		go m.mirror.Run(m.mirrorCtx, asClient, nil)
		log.DefaultLogger().Info("verdict mirror subscriber started")
	}
	return m
}

// ensureClient opens a trustd client for the VMI if needed and launches
// the drift subscriber. Returns true once trustd is reachable.
func (m *cvmTrustManager) ensureClient(vmi *v1.VirtualMachineInstance) bool {
	if !cvmTrustdNeeded(vmi) {
		return false
	}
	if !vmi.IsRunning() || vmi.IsFinal() || vmi.IsMarkedForDeletion() {
		return false
	}
	if vmi.Status.VSOCKCID == nil {
		log.DefaultLogger().V(5).Object(vmi).Info("trustd needed but no VSOCK CID allocated yet")
		return false
	}

	uid := string(vmi.UID)
	m.mu.RLock()
	existingClient := m.clients[uid]
	_, hasCancel := m.cancels[uid]
	m.mu.RUnlock()

	if existingClient != nil && existingClient.IsReachable() && hasCancel {
		return true
	}
	if existingClient != nil {
		log.DefaultLogger().V(4).Object(vmi).Info("trustd client exists but is not reachable; recreating")
		m.stopClient(vmi)
	}

	client := trustd.NewClient(*vmi.Status.VSOCKCID)
	if !client.IsReachable() {
		reachable := false
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			time.Sleep(500 * time.Millisecond)
			if client.IsReachable() {
				reachable = true
				break
			}
		}
		if !reachable {
			return false
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	subscriber := trustd.NewDriftSubscriber(client, m.policy, m.cooldown)
	go func() {
		for {
			if err := subscriber.Run(ctx); err != nil && ctx.Err() == nil {
				log.DefaultLogger().Object(vmi).Warningf("drift subscriber disconnected (will retry): %v", err)
				time.Sleep(2 * time.Second)
				continue
			}
			return
		}
	}()

	m.mu.Lock()
	m.clients[uid] = client
	m.cancels[uid] = cancel
	m.mu.Unlock()

	log.DefaultLogger().Object(vmi).Infof("Started trustd drift subscriber (policy=%s)", m.policy.OnUntrusted)
	return true
}

// stopClient cancels the drift subscriber and drops the trustd client.
func (m *cvmTrustManager) stopClient(vmi *v1.VirtualMachineInstance) {
	uid := string(vmi.UID)
	m.mu.Lock()
	cancel, hadCancel := m.cancels[uid]
	delete(m.cancels, uid)
	delete(m.clients, uid)
	delete(m.deliveredSpecs, uid)
	delete(m.workloadIDs, uid)
	m.mu.Unlock()
	if hadCancel {
		cancel()
		log.DefaultLogger().Object(vmi).Info("Stopped trustd drift subscriber")
	}
}

// getStates returns mirrored trust states for the VMI's workloads, or
// nil when the verdict mirror is disabled (no AS endpoint configured).
func (m *cvmTrustManager) getStates(vmi *v1.VirtualMachineInstance) []v1.ContainerTrustState {
	if m.mirror == nil {
		return nil
	}
	uid := string(vmi.UID)
	m.mu.RLock()
	ids := append([]string(nil), m.workloadIDs[uid]...)
	m.mu.RUnlock()
	if len(ids) == 0 {
		return nil
	}
	return m.mirror.States(ids)
}

// getClient returns the trustd client for a VMI, or nil if not connected.
func (m *cvmTrustManager) getClient(vmi *v1.VirtualMachineInstance) *trustd.Client {
	uid := string(vmi.UID)
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.clients[uid]
}

// deliverContainerSpecs reads the VMI annotation, parses container specs,
// and calls trustd.StartContainer for each spec not yet delivered. This is
// the wiring that replaces cloud-init runcmd — containers are now started
// by the host-side virt-handler through trustd's lifecycle RPCs.
func (m *cvmTrustManager) deliverContainerSpecs(vmi *v1.VirtualMachineInstance) {
	uid := string(vmi.UID)
	client := m.getClient(vmi)
	if client == nil {
		return
	}

	specs, err := trustd.ParseContainerSpecs(vmi)
	if err != nil {
		log.DefaultLogger().Object(vmi).Warningf("Failed to parse container specs from annotation: %v", err)
		return
	}
	if len(specs) == 0 {
		return
	}

	m.mu.Lock()
	if m.deliveredSpecs[uid] == nil {
		m.deliveredSpecs[uid] = make(map[string]bool)
	}
	delivered := m.deliveredSpecs[uid]
	// Update the per-VMI workload_id list so the verdict mirror knows
	// which subjects to report for this VMI.
	ids := make([]string, 0, len(specs))
	for _, s := range specs {
		if s.Name != "" {
			ids = append(ids, s.Name)
		}
	}
	m.workloadIDs[uid] = ids
	m.mu.Unlock()

	ctx := context.Background()
	for _, spec := range specs {
		if delivered[spec.Name] {
			continue
		}

		req := spec.ToStartContainerRequest()
		log.DefaultLogger().Object(vmi).Infof("Delivering container spec to trustd: %s (image=%s)", req.Name, req.Image)
		resp, err := client.StartContainer(ctx, req)
		if err != nil {
			log.DefaultLogger().Object(vmi).Warningf("StartContainer %s failed: %v", req.Name, err)
			continue
		}
		if !resp.Started {
			log.DefaultLogger().Object(vmi).Warningf("StartContainer %s returned started=false: %s", req.Name, resp.Error)
			continue
		}

		log.DefaultLogger().Object(vmi).Infof("Container %s started in CVM (cgroup=%s, id=%s)", req.Name, resp.CgroupPath, resp.ContainerID)
		m.mu.Lock()
		m.deliveredSpecs[uid][spec.Name] = true
		m.mu.Unlock()
	}
}

// stopAll cancels every drift subscriber and drops every client. Called
// during controller shutdown.
func (m *cvmTrustManager) stopAll() {
	m.mu.Lock()
	cancels := make([]context.CancelFunc, 0, len(m.cancels))
	for _, c := range m.cancels {
		cancels = append(cancels, c)
	}
	m.clients = make(map[string]*trustd.Client)
	m.cancels = make(map[string]context.CancelFunc)
	m.workloadIDs = make(map[string][]string)
	m.mu.Unlock()

	for _, cancel := range cancels {
		cancel()
	}
	if m.mirrorStop != nil {
		m.mirrorStop()
	}
	if m.asClient != nil {
		_ = m.asClient.Close()
	}
}

// updateCVMTrustConditions updates the CVMAgentConnected condition on a
// VMI based on the current trustd client connectivity.
//
// The ContainersTrusted condition previously computed from a polling
// collector is intentionally not set here. After the AttestWorkload /
// VerifyWorkload migration, host-side verdict aggregation belongs to
// attestation-service.WatchVerdictUpdates; a separate subscriber should
// mirror those verdicts onto vmi.Status.ContainerTrustStates. Until that
// mirror exists, the condition stays absent (rather than lying).
func updateCVMTrustConditions(vmi *v1.VirtualMachineInstance, trustMgr *cvmTrustManager, condManager *controller.VirtualMachineInstanceConditionManager) {
	if !cvmTrustdNeeded(vmi) || !vmi.IsRunning() || vmi.IsFinal() || vmi.IsMarkedForDeletion() {
		trustMgr.stopClient(vmi)
		vmi.Status.ContainerTrustStates = nil
		condManager.RemoveCondition(vmi, v1.VirtualMachineInstanceCVMAgentConnected)
		condManager.RemoveCondition(vmi, v1.VirtualMachineInstanceContainersTrusted)
		return
	}

	connected := trustMgr.ensureClient(vmi)
	if connected {
		trustMgr.deliverContainerSpecs(vmi)
	}

	if connected && !condManager.HasCondition(vmi, v1.VirtualMachineInstanceCVMAgentConnected) {
		vmi.Status.Conditions = append(vmi.Status.Conditions, v1.VirtualMachineInstanceCondition{
			Type:          v1.VirtualMachineInstanceCVMAgentConnected,
			LastProbeTime: metav1.Now(),
			Status:        k8sv1.ConditionTrue,
		})
	} else if !connected {
		condManager.RemoveCondition(vmi, v1.VirtualMachineInstanceCVMAgentConnected)
	}

	// Mirror attestation verdicts onto VMI.Status.ContainerTrustStates and
	// derive the ContainersTrusted condition from them. When the verdict
	// mirror is disabled (no AS endpoint configured), states stays nil and
	// the condition is removed — we report nothing rather than lying.
	states := trustMgr.getStates(vmi)
	vmi.Status.ContainerTrustStates = states
	condManager.RemoveCondition(vmi, v1.VirtualMachineInstanceContainersTrusted)
	if len(states) > 0 {
		allTrusted := true
		for _, s := range states {
			if s.Verdict != v1.ContainerTrustVerdictTrusted {
				allTrusted = false
				break
			}
		}
		status := k8sv1.ConditionFalse
		if allTrusted {
			status = k8sv1.ConditionTrue
		}
		vmi.Status.Conditions = append(vmi.Status.Conditions, v1.VirtualMachineInstanceCondition{
			Type:          v1.VirtualMachineInstanceContainersTrusted,
			LastProbeTime: metav1.Now(),
			Status:        status,
		})
	}
}

const (
	remediateOnUntrustedEnv = "TRUSTFNCALL_REMEDIATE_ON_UNTRUSTED"
	remediateOnStaleEnv     = "TRUSTFNCALL_REMEDIATE_ON_STALE"
	remediationCooldownEnv  = "TRUSTFNCALL_REMEDIATION_COOLDOWN_SECONDS"
)

func remediationPolicyFromEnv() (cvmDriftPolicy, time.Duration) {
	policy := cvmDriftPolicy{
		OnUntrusted: parseRemediationAction(os.Getenv(remediateOnUntrustedEnv)),
		OnStale:     parseRemediationAction(os.Getenv(remediateOnStaleEnv)),
	}
	cooldown := 60 * time.Second
	if raw := strings.TrimSpace(os.Getenv(remediationCooldownEnv)); raw != "" {
		seconds, err := strconv.Atoi(raw)
		if err != nil || seconds <= 0 {
			log.DefaultLogger().Warningf(
				"Ignoring invalid %s=%q; expected positive integer seconds",
				remediationCooldownEnv,
				raw,
			)
		} else {
			cooldown = time.Duration(seconds) * time.Second
		}
	}

	if policy.OnUntrusted != trustd.RemediationActionNone || policy.OnStale != trustd.RemediationActionNone {
		log.DefaultLogger().Infof(
			"Container remediation enabled (on_untrusted=%s, on_stale=%s, cooldown=%s)",
			policy.OnUntrusted,
			policy.OnStale,
			cooldown,
		)
	}

	return policy, cooldown
}

func parseRemediationAction(raw string) trustd.RemediationAction {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "none", "off", "disabled":
		return trustd.RemediationActionNone
	case "alert":
		return trustd.RemediationActionAlert
	case "restart":
		return trustd.RemediationActionRestart
	case "kill":
		return trustd.RemediationActionKill
	default:
		log.DefaultLogger().Warningf(
			"Ignoring invalid remediation action %q; supported values: none, alert, restart, kill",
			raw,
		)
		return trustd.RemediationActionNone
	}
}

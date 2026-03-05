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

// cvmTrustManager manages trustd connections and trust state collectors
// for TDX VMIs that have container attestation enabled.
type cvmTrustManager struct {
	mu                sync.RWMutex
	collectors        map[string]*trustd.TrustStateCollector // key: vmi.UID
	clients           map[string]*trustd.Client              // key: vmi.UID
	verifier          trustd.AttestationVerifier
	remediationPolicy trustd.RemediationPolicy
}

func newCVMTrustManager() *cvmTrustManager {
	return &cvmTrustManager{
		collectors:        make(map[string]*trustd.TrustStateCollector),
		clients:           make(map[string]*trustd.Client),
		verifier:          newAttestationVerifierFromEnv(),
		remediationPolicy: remediationPolicyFromEnv(),
	}
}

// ensureCollector creates and starts a collector for a VMI if needed.
// Returns true if trustd is connected.
func (m *cvmTrustManager) ensureCollector(vmi *v1.VirtualMachineInstance, verifier trustd.AttestationVerifier) bool {
	if !util.IsTDXAttestationRequested(vmi) {
		return false
	}
	if !vmi.IsRunning() || vmi.IsFinal() || vmi.IsMarkedForDeletion() {
		return false
	}
	if vmi.Status.VSOCKCID == nil {
		log.DefaultLogger().V(5).Object(vmi).Info("TDX attestation requested but no VSOCK CID allocated yet")
		return false
	}

	uid := string(vmi.UID)
	m.mu.RLock()
	_, exists := m.collectors[uid]
	existingClient := m.clients[uid]
	m.mu.RUnlock()

	if exists {
		if existingClient != nil && existingClient.IsReachable() {
			return true
		}
		log.DefaultLogger().V(4).Object(vmi).Info("trustd collector exists but is not reachable; recreating")
		m.stopCollector(vmi)
	}

	// Create client and check reachability
	client := trustd.NewClient(*vmi.Status.VSOCKCID)
	if !client.IsReachable() {
		return false
	}

	// Get attestation/heartbeat intervals from spec.
	var attestationInterval *int32
	var heartbeatInterval *int32
	if vmi.Spec.Domain.LaunchSecurity != nil &&
		vmi.Spec.Domain.LaunchSecurity.TDX != nil &&
		vmi.Spec.Domain.LaunchSecurity.TDX.Attestation != nil {
		attestationInterval = vmi.Spec.Domain.LaunchSecurity.TDX.Attestation.AttestationIntervalSeconds
		heartbeatInterval = vmi.Spec.Domain.LaunchSecurity.TDX.Attestation.HeartbeatIntervalSeconds
	}

	collector := trustd.NewTrustStateCollector(client, verifier, attestationInterval, heartbeatInterval, m.remediationPolicy)
	collector.Start()

	m.mu.Lock()
	m.collectors[uid] = collector
	m.clients[uid] = client
	m.mu.Unlock()

	log.DefaultLogger().Object(vmi).Info("Started trustd state collector")
	return true
}

// stopCollector stops and removes the collector for a VMI.
func (m *cvmTrustManager) stopCollector(vmi *v1.VirtualMachineInstance) {
	uid := string(vmi.UID)
	m.mu.Lock()
	collector, exists := m.collectors[uid]
	if exists {
		delete(m.collectors, uid)
		delete(m.clients, uid)
	}
	m.mu.Unlock()

	if exists {
		collector.Stop()
		log.DefaultLogger().Object(vmi).Info("Stopped trustd state collector")
	}
}

// getStates returns the latest trust states for a VMI.
func (m *cvmTrustManager) getStates(vmi *v1.VirtualMachineInstance) []v1.ContainerTrustState {
	uid := string(vmi.UID)
	m.mu.RLock()
	collector, exists := m.collectors[uid]
	m.mu.RUnlock()

	if !exists {
		return nil
	}
	return collector.GetStates()
}

// getClient returns the trustd client for a VMI, or nil if not connected.
func (m *cvmTrustManager) getClient(vmi *v1.VirtualMachineInstance) *trustd.Client {
	uid := string(vmi.UID)
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.clients[uid]
}

// stopAll stops all collectors. Called during controller shutdown.
func (m *cvmTrustManager) stopAll() {
	m.mu.Lock()
	collectors := make(map[string]*trustd.TrustStateCollector, len(m.collectors))
	for k, v := range m.collectors {
		collectors[k] = v
	}
	m.collectors = make(map[string]*trustd.TrustStateCollector)
	m.clients = make(map[string]*trustd.Client)
	m.mu.Unlock()

	for _, collector := range collectors {
		collector.Stop()
	}
}

// updateCVMTrustConditions updates the CVMAgentConnected and ContainersTrusted
// conditions on a VMI based on the current collector state.
func updateCVMTrustConditions(vmi *v1.VirtualMachineInstance, trustMgr *cvmTrustManager, condManager *controller.VirtualMachineInstanceConditionManager) {
	if !util.IsTDXAttestationRequested(vmi) || !vmi.IsRunning() || vmi.IsFinal() || vmi.IsMarkedForDeletion() {
		trustMgr.stopCollector(vmi)
		vmi.Status.ContainerTrustStates = nil
		condManager.RemoveCondition(vmi, v1.VirtualMachineInstanceCVMAgentConnected)
		condManager.RemoveCondition(vmi, v1.VirtualMachineInstanceContainersTrusted)
		return
	}

	connected := trustMgr.ensureCollector(vmi, trustMgr.verifier)

	// Update CVMAgentConnected condition
	if connected && !condManager.HasCondition(vmi, v1.VirtualMachineInstanceCVMAgentConnected) {
		vmi.Status.Conditions = append(vmi.Status.Conditions, v1.VirtualMachineInstanceCondition{
			Type:          v1.VirtualMachineInstanceCVMAgentConnected,
			LastProbeTime: metav1.Now(),
			Status:        k8sv1.ConditionTrue,
		})
	} else if !connected {
		condManager.RemoveCondition(vmi, v1.VirtualMachineInstanceCVMAgentConnected)
	}

	// Update trust states on VMI status
	states := trustMgr.getStates(vmi)
	vmi.Status.ContainerTrustStates = states

	// Update ContainersTrusted condition based on verdicts
	if len(states) > 0 {
		allTrusted := true
		for _, s := range states {
			if s.Verdict != v1.ContainerTrustVerdictTrusted {
				allTrusted = false
				break
			}
		}
		condManager.RemoveCondition(vmi, v1.VirtualMachineInstanceContainersTrusted)
		status := k8sv1.ConditionFalse
		if allTrusted {
			status = k8sv1.ConditionTrue
		}
		vmi.Status.Conditions = append(vmi.Status.Conditions, v1.VirtualMachineInstanceCondition{
			Type:          v1.VirtualMachineInstanceContainersTrusted,
			LastProbeTime: metav1.Now(),
			Status:        status,
		})
	} else {
		condManager.RemoveCondition(vmi, v1.VirtualMachineInstanceContainersTrusted)
	}
}

const (
	attestationServiceAddrEnv = "TRUSTFNCALL_ATTESTATION_SERVICE_ADDR"
	remediateOnUntrustedEnv   = "TRUSTFNCALL_REMEDIATE_ON_UNTRUSTED"
	remediateOnStaleEnv       = "TRUSTFNCALL_REMEDIATE_ON_STALE"
	remediationCooldownEnv    = "TRUSTFNCALL_REMEDIATION_COOLDOWN_SECONDS"
)

func newAttestationVerifierFromEnv() trustd.AttestationVerifier {
	address := strings.TrimSpace(os.Getenv(attestationServiceAddrEnv))
	if address == "" {
		return nil
	}
	log.DefaultLogger().Infof("Using attestation verifier at %s", address)
	return trustd.NewRemoteAttestationVerifier(address)
}

func remediationPolicyFromEnv() trustd.RemediationPolicy {
	policy := trustd.DefaultRemediationPolicy()
	policy.OnUntrusted = parseRemediationAction(os.Getenv(remediateOnUntrustedEnv))
	policy.OnStale = parseRemediationAction(os.Getenv(remediateOnStaleEnv))

	if raw := strings.TrimSpace(os.Getenv(remediationCooldownEnv)); raw != "" {
		seconds, err := strconv.Atoi(raw)
		if err != nil || seconds <= 0 {
			log.DefaultLogger().Warningf(
				"Ignoring invalid %s=%q; expected positive integer seconds",
				remediationCooldownEnv,
				raw,
			)
		} else {
			policy.Cooldown = time.Duration(seconds) * time.Second
		}
	}

	if policy.OnUntrusted != trustd.RemediationActionNone || policy.OnStale != trustd.RemediationActionNone {
		log.DefaultLogger().Infof(
			"Container remediation enabled (on_untrusted=%s, on_stale=%s, cooldown=%s)",
			policy.OnUntrusted,
			policy.OnStale,
			policy.Cooldown,
		)
	}

	return policy
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

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

package watch

import (
	"fmt"
	"strings"
	"sync"
	"time"

	k8sv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"

	v1 "kubevirt.io/api/core/v1"

	"kubevirt.io/kubevirt/pkg/util"
	virtconfig "kubevirt.io/kubevirt/pkg/virt-config"
)

const (
	// TrustControllerName is the name of this controller.
	TrustControllerName = "trust-controller"

	// Event reasons
	reasonContainerUntrusted = "ContainerUntrusted"
	reasonHeartbeatStale     = "HeartbeatStale"
	reasonCVMAgentConnected  = "CVMAgentConnected"
	reasonCVMAgentLost       = "CVMAgentDisconnected"
)

// TrustController watches VMIs with TDX attestation enabled and emits
// transition-based trust events from VMI status.
type TrustController struct {
	vmiInformer   cache.SharedIndexInformer
	recorder      record.EventRecorder
	clusterConfig *virtconfig.ClusterConfig
	mu            sync.Mutex
	// key: <vmiUID>/<containerID>, value: state fingerprint
	lastContainerState map[string]string
	// key: <vmiUID>, value: last seen CVMAgentConnected condition
	lastAgentConnected map[string]k8sv1.ConditionStatus
}

// NewTrustController creates a new TrustController.
func NewTrustController(
	vmiInformer cache.SharedIndexInformer,
	recorder record.EventRecorder,
	clusterConfig *virtconfig.ClusterConfig,
) *TrustController {
	return &TrustController{
		vmiInformer:        vmiInformer,
		recorder:           recorder,
		clusterConfig:      clusterConfig,
		lastContainerState: make(map[string]string),
		lastAgentConnected: make(map[string]k8sv1.ConditionStatus),
	}
}

// ProcessVMI evaluates trust states for a VMI and emits events/actions as needed.
// This is called from the VMI controller's reconcile loop rather than running
// as a separate controller, to avoid duplication.
func (tc *TrustController) ProcessVMI(vmi *v1.VirtualMachineInstance) {
	vmiUID := string(vmi.UID)
	if !tc.clusterConfig.ContainerAttestationEnabled() {
		tc.clearStateForVMI(vmiUID)
		return
	}
	if !util.IsTDXAttestationRequested(vmi) {
		tc.clearStateForVMI(vmiUID)
		return
	}

	tc.emitAgentConnectivityEvents(vmi)
	tc.emitTrustEvents(vmi)
}

// emitTrustEvents emits Kubernetes events only on trust-state transitions.
func (tc *TrustController) emitTrustEvents(vmi *v1.VirtualMachineInstance) {
	vmiUID := string(vmi.UID)
	activeKeys := make(map[string]struct{}, len(vmi.Status.ContainerTrustStates))

	for _, state := range vmi.Status.ContainerTrustStates {
		key := containerStateKey(vmiUID, state.ContainerID)
		activeKeys[key] = struct{}{}
		fingerprint := stateFingerprint(state)
		if !tc.shouldEmitContainerEvent(key, fingerprint) {
			continue
		}

		switch state.Verdict {
		case v1.ContainerTrustVerdictUntrusted:
			tc.recorder.Eventf(vmi, k8sv1.EventTypeWarning, reasonContainerUntrusted,
				"Container %s is untrusted: %s", state.ContainerID, state.VerdictMessage)
		case v1.ContainerTrustVerdictStale:
			tc.recorder.Eventf(vmi, k8sv1.EventTypeWarning, reasonHeartbeatStale,
				"Container %s trust state is stale (last attestation: %v)",
				state.ContainerID, formatTimeOrNever(state.LastAttestation))
		case v1.ContainerTrustVerdictTrusted:
			// Trusted transitions are reflected in VMI status conditions;
			// avoid generating noisy normal events for steady-state updates.
		}
	}

	tc.forgetMissingContainers(vmiUID, activeKeys)
}

func (tc *TrustController) emitAgentConnectivityEvents(vmi *v1.VirtualMachineInstance) {
	vmiUID := string(vmi.UID)
	current := k8sv1.ConditionFalse
	for _, condition := range vmi.Status.Conditions {
		if condition.Type == v1.VirtualMachineInstanceCVMAgentConnected {
			current = condition.Status
			break
		}
	}

	tc.mu.Lock()
	previous, seen := tc.lastAgentConnected[vmiUID]
	tc.lastAgentConnected[vmiUID] = current
	tc.mu.Unlock()

	if current == k8sv1.ConditionTrue && (!seen || previous != k8sv1.ConditionTrue) {
		tc.recorder.Eventf(vmi, k8sv1.EventTypeNormal, reasonCVMAgentConnected,
			"CVM attestation agent is connected")
		return
	}
	if seen && previous == k8sv1.ConditionTrue && current != k8sv1.ConditionTrue {
		tc.recorder.Eventf(vmi, k8sv1.EventTypeWarning, reasonCVMAgentLost,
			"CVM attestation agent connectivity lost")
	}
}

func (tc *TrustController) shouldEmitContainerEvent(key, fingerprint string) bool {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	prev, exists := tc.lastContainerState[key]
	if exists && prev == fingerprint {
		return false
	}
	tc.lastContainerState[key] = fingerprint
	return true
}

func (tc *TrustController) forgetMissingContainers(vmiUID string, activeKeys map[string]struct{}) {
	prefix := vmiUID + "/"
	tc.mu.Lock()
	defer tc.mu.Unlock()

	for key := range tc.lastContainerState {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if _, ok := activeKeys[key]; ok {
			continue
		}
		delete(tc.lastContainerState, key)
	}
}

func (tc *TrustController) clearStateForVMI(vmiUID string) {
	prefix := vmiUID + "/"
	tc.mu.Lock()
	defer tc.mu.Unlock()

	for key := range tc.lastContainerState {
		if strings.HasPrefix(key, prefix) {
			delete(tc.lastContainerState, key)
		}
	}
	delete(tc.lastAgentConnected, vmiUID)
}

func containerStateKey(vmiUID, containerID string) string {
	return fmt.Sprintf("%s/%s", vmiUID, containerID)
}

func stateFingerprint(state v1.ContainerTrustState) string {
	return fmt.Sprintf(
		"%s|%s|%s|%s",
		state.Verdict,
		state.VerdictMessage,
		timestampOrNever(state.LastAttestation),
		timestampOrNever(state.LastHeartbeat),
	)
}

func timestampOrNever(t *metav1.Time) string {
	if t == nil {
		return "never"
	}
	return t.Format(time.RFC3339Nano)
}

func formatTimeOrNever(t *metav1.Time) string {
	if t == nil {
		return "never"
	}
	return fmt.Sprintf("%s (%s ago)", t.Format(time.RFC3339), time.Since(t.Time).Round(time.Second))
}

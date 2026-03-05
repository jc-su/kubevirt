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
	"errors"
	"strings"
	"testing"
	"time"

	v1 "kubevirt.io/api/core/v1"
)

type fakeCollectorClient struct {
	listContainers []ContainerState
	listErr        error
	attestResponse AttestContainerResponse
	attestErr      error
	attestCalls    []string
	restartErr     error
	restartCalls   []string
	startHBCalls   []string
	stopHBCalls    []string
	reportHBCalls  []string
	reportHBErr    error
}

func (f *fakeCollectorClient) ListContainers(context.Context) ([]ContainerState, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listContainers == nil {
		return []ContainerState{}, nil
	}
	out := make([]ContainerState, 0, len(f.listContainers))
	out = append(out, f.listContainers...)
	return out, nil
}

func (f *fakeCollectorClient) WatchContainerEvents(context.Context, func(ContainerEvent) error) error {
	return nil
}

func (f *fakeCollectorClient) AttestContainer(_ context.Context, req *AttestContainerRequest) (*AttestContainerResponse, error) {
	f.attestCalls = append(f.attestCalls, req.CgroupPath)
	if f.attestErr != nil {
		return nil, f.attestErr
	}

	resp := f.attestResponse
	resp.CgroupPath = req.CgroupPath
	return &resp, nil
}

func (f *fakeCollectorClient) RestartContainer(_ context.Context, cgroupPath string) (*ContainerState, error) {
	f.restartCalls = append(f.restartCalls, cgroupPath)
	if f.restartErr != nil {
		return nil, f.restartErr
	}
	return &ContainerState{CgroupPath: cgroupPath}, nil
}

func (f *fakeCollectorClient) StartHeartbeatMonitor(_ context.Context, cgroupPath string, _ uint32) error {
	f.startHBCalls = append(f.startHBCalls, cgroupPath)
	return nil
}

func (f *fakeCollectorClient) StopHeartbeatMonitor(_ context.Context, cgroupPath string) error {
	f.stopHBCalls = append(f.stopHBCalls, cgroupPath)
	return nil
}

func (f *fakeCollectorClient) ReportHeartbeat(_ context.Context, cgroupPath string) error {
	f.reportHBCalls = append(f.reportHBCalls, cgroupPath)
	return f.reportHBErr
}

type fakeVerifier struct {
	result VerificationResult
	err    error
}

func (f *fakeVerifier) VerifyEvidence(context.Context, *AttestContainerResponse) (*VerificationResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	result := f.result
	return &result, nil
}

func TestCollectorRequestsRestartForUntrustedVerdict(t *testing.T) {
	client := &fakeCollectorClient{
		attestResponse: AttestContainerResponse{
			RTMR3:            "rtmr3",
			InitialRTMR3:     "init",
			MeasurementCount: 3,
			ReportData:       "abcd",
			Nonce:            "1234",
		},
	}
	verifier := &fakeVerifier{
		result: VerificationResult{
			Verdict: v1.ContainerTrustVerdictUntrusted,
			Message: "digest mismatch",
		},
	}

	policy := DefaultRemediationPolicy()
	policy.OnUntrusted = RemediationActionRestart

	collector := NewTrustStateCollector(client, verifier, nil, nil, policy)
	collector.handleEvent(ContainerEvent{
		EventType:  EventTypeMeasurement,
		CgroupPath: "cg1",
	})

	if len(client.restartCalls) != 1 {
		t.Fatalf("expected one restart call, got %d", len(client.restartCalls))
	}
	if client.restartCalls[0] != "cg1" {
		t.Fatalf("unexpected restart target: %s", client.restartCalls[0])
	}

	states := collector.GetStates()
	if len(states) != 1 {
		t.Fatalf("expected one state entry, got %d", len(states))
	}
	if !strings.Contains(states[0].VerdictMessage, "remediation action restart requested") {
		t.Fatalf("expected remediation message, got %q", states[0].VerdictMessage)
	}
}

func TestCollectorRemediationCooldownSuppressesRepeatedRestart(t *testing.T) {
	client := &fakeCollectorClient{
		attestResponse: AttestContainerResponse{
			RTMR3:            "rtmr3",
			InitialRTMR3:     "init",
			MeasurementCount: 3,
			ReportData:       "abcd",
			Nonce:            "1234",
		},
	}
	verifier := &fakeVerifier{
		result: VerificationResult{
			Verdict: v1.ContainerTrustVerdictUntrusted,
			Message: "digest mismatch",
		},
	}

	policy := DefaultRemediationPolicy()
	policy.OnUntrusted = RemediationActionRestart
	policy.Cooldown = 10 * time.Minute

	collector := NewTrustStateCollector(client, verifier, nil, nil, policy)
	collector.handleEvent(ContainerEvent{
		EventType:  EventTypeMeasurement,
		CgroupPath: "cg1",
	})
	collector.handleEvent(ContainerEvent{
		EventType:  EventTypeMeasurement,
		CgroupPath: "cg1",
	})

	if len(client.restartCalls) != 1 {
		t.Fatalf("expected cooldown to suppress restart, got %d calls", len(client.restartCalls))
	}
}

func TestCollectorSkipsRestartWhenStaleActionDisabled(t *testing.T) {
	client := &fakeCollectorClient{
		attestResponse: AttestContainerResponse{
			RTMR3:            "rtmr3",
			InitialRTMR3:     "init",
			MeasurementCount: 3,
			ReportData:       "abcd",
			Nonce:            "1234",
		},
	}
	verifier := &fakeVerifier{
		result: VerificationResult{
			Verdict: v1.ContainerTrustVerdictStale,
			Message: "heartbeat timeout",
		},
	}

	policy := DefaultRemediationPolicy()
	collector := NewTrustStateCollector(client, verifier, nil, nil, policy)
	collector.handleEvent(ContainerEvent{
		EventType:  EventTypeMeasurement,
		CgroupPath: "cg1",
	})

	if len(client.restartCalls) != 0 {
		t.Fatalf("expected no restart calls, got %d", len(client.restartCalls))
	}
}

func TestCollectorUsesVerifierPolicyActionOverFallback(t *testing.T) {
	client := &fakeCollectorClient{
		attestResponse: AttestContainerResponse{
			RTMR3:            "rtmr3",
			InitialRTMR3:     "init",
			MeasurementCount: 3,
			ReportData:       "abcd",
			Nonce:            "1234",
		},
	}
	verifier := &fakeVerifier{
		result: VerificationResult{
			Verdict:      v1.ContainerTrustVerdictUntrusted,
			Message:      "digest mismatch",
			PolicyAction: RemediationActionAlert,
		},
	}

	policy := DefaultRemediationPolicy()
	policy.OnUntrusted = RemediationActionRestart

	collector := NewTrustStateCollector(client, verifier, nil, nil, policy)
	collector.handleEvent(ContainerEvent{
		EventType:  EventTypeMeasurement,
		CgroupPath: "cg1",
	})

	if len(client.restartCalls) != 0 {
		t.Fatalf("expected verifier action to suppress restart, got %d calls", len(client.restartCalls))
	}
}

func TestCollectorAppliesStalePolicyOnHeartbeatMiss(t *testing.T) {
	client := &fakeCollectorClient{}
	policy := DefaultRemediationPolicy()
	policy.OnStale = RemediationActionRestart

	collector := NewTrustStateCollector(client, nil, nil, nil, policy)
	collector.handleEvent(ContainerEvent{
		EventType:  EventTypeHeartbeatMiss,
		CgroupPath: "cg1",
	})

	if len(client.restartCalls) != 1 || client.restartCalls[0] != "cg1" {
		t.Fatalf("expected restart remediation for stale heartbeat miss, got %#v", client.restartCalls)
	}

	states := collector.GetStates()
	if len(states) != 1 || states[0].Verdict != v1.ContainerTrustVerdictStale {
		t.Fatalf("expected stale state entry, got %#v", states)
	}
}

func TestCollectorAppliesAuthorityUpdateAndRemediates(t *testing.T) {
	client := &fakeCollectorClient{}
	policy := DefaultRemediationPolicy()
	policy.OnUntrusted = RemediationActionRestart

	collector := NewTrustStateCollector(client, nil, nil, nil, policy)
	collector.setState(v1.ContainerTrustState{
		ContainerID: "/cg1",
		Verdict:     v1.ContainerTrustVerdictTrusted,
	})

	collector.handleVerdictUpdate(AuthorityVerdictUpdate{
		Subject:      "cgroup:///cg1",
		Verdict:      v1.ContainerTrustVerdictUntrusted,
		Message:      "revoked by authority",
		PolicyAction: RemediationActionRestart,
		Version:      11,
	})

	if len(client.restartCalls) != 1 || client.restartCalls[0] != "/cg1" {
		t.Fatalf("expected restart remediation for authority update, got %#v", client.restartCalls)
	}

	states := collector.GetStates()
	if len(states) != 1 {
		t.Fatalf("expected one state entry, got %d", len(states))
	}
	if states[0].Verdict != v1.ContainerTrustVerdictUntrusted {
		t.Fatalf("expected untrusted verdict, got %s", states[0].Verdict)
	}
	if !strings.Contains(states[0].VerdictMessage, "revoked by authority") {
		t.Fatalf("expected authority verdict message, got %q", states[0].VerdictMessage)
	}
}

func TestCollectorIgnoresAuthorityUpdateForUnknownContainer(t *testing.T) {
	client := &fakeCollectorClient{}
	collector := NewTrustStateCollector(client, nil, nil, nil, DefaultRemediationPolicy())

	collector.handleVerdictUpdate(AuthorityVerdictUpdate{
		Subject:      "cgroup:///unknown",
		Verdict:      v1.ContainerTrustVerdictUntrusted,
		Message:      "revoked by authority",
		PolicyAction: RemediationActionRestart,
		Version:      3,
	})

	if len(client.restartCalls) != 0 {
		t.Fatalf("expected no remediation for unknown container, got %#v", client.restartCalls)
	}
	if len(collector.GetStates()) != 0 {
		t.Fatalf("expected no state updates for unknown container")
	}
}

func TestCollectorRemediationLifecycleForcesReattestationAndClearsPendingOnTrusted(t *testing.T) {
	client := &fakeCollectorClient{
		attestResponse: AttestContainerResponse{
			RTMR3:            "rtmr3",
			InitialRTMR3:     "init",
			MeasurementCount: 2,
			ReportData:       "abcd",
			Nonce:            "1234",
		},
	}
	verifier := &fakeVerifier{
		result: VerificationResult{
			Verdict: v1.ContainerTrustVerdictTrusted,
			Message: "trusted after remediation",
		},
	}

	collector := NewTrustStateCollector(client, verifier, nil, nil, DefaultRemediationPolicy())
	collector.setState(v1.ContainerTrustState{
		ContainerID: "cg1",
		Verdict:     v1.ContainerTrustVerdictUntrusted,
	})

	collector.handleEvent(ContainerEvent{
		EventType:  EventTypeAttestBegin,
		CgroupPath: "cg1",
		Detail:     "remediation_begin action=restart",
	})

	collector.handleEvent(ContainerEvent{
		EventType:  EventTypeAttestEnd,
		CgroupPath: "cg1",
		Detail:     "remediation_done action=restart",
	})

	if len(client.attestCalls) == 0 {
		t.Fatalf("expected forced post-remediation attestation")
	}

	states := collector.GetStates()
	if len(states) != 1 {
		t.Fatalf("expected one state, got %d", len(states))
	}
	if states[0].Verdict != v1.ContainerTrustVerdictTrusted {
		t.Fatalf("expected trusted verdict after re-attestation, got %s", states[0].Verdict)
	}
	if strings.Contains(states[0].VerdictMessage, "pending rebootstrap") {
		t.Fatalf("pending rebootstrap should be cleared on trusted verdict, got %q", states[0].VerdictMessage)
	}
}

func TestCollectorRemediationLifecycleKeepsFailClosedWhenReattestationFails(t *testing.T) {
	client := &fakeCollectorClient{
		attestErr: errors.New("attestor timeout"),
	}
	collector := NewTrustStateCollector(client, nil, nil, nil, DefaultRemediationPolicy())
	collector.setState(v1.ContainerTrustState{
		ContainerID: "cg1",
		Verdict:     v1.ContainerTrustVerdictTrusted,
	})

	collector.handleEvent(ContainerEvent{
		EventType:  EventTypeAttestBegin,
		CgroupPath: "cg1",
		Detail:     "remediation_begin action=restart",
	})
	collector.handleEvent(ContainerEvent{
		EventType:  EventTypeAttestEnd,
		CgroupPath: "cg1",
		Detail:     "remediation_done action=restart",
	})

	states := collector.GetStates()
	if len(states) != 1 {
		t.Fatalf("expected one state, got %d", len(states))
	}
	if states[0].Verdict != v1.ContainerTrustVerdictStale {
		t.Fatalf("expected stale verdict while pending rebootstrap, got %s", states[0].Verdict)
	}
	if !strings.Contains(states[0].VerdictMessage, "pending rebootstrap") {
		t.Fatalf("expected pending rebootstrap marker, got %q", states[0].VerdictMessage)
	}
}

func TestCollectorSendLivenessHeartbeatsReportsForKnownContainers(t *testing.T) {
	client := &fakeCollectorClient{
		listContainers: []ContainerState{
			{CgroupPath: "cg1"},
			{CgroupPath: "cg2"},
		},
	}
	collector := NewTrustStateCollector(client, nil, nil, nil, DefaultRemediationPolicy())

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	collector.sendLivenessHeartbeats(ctx)

	if len(client.startHBCalls) != 2 {
		t.Fatalf("expected heartbeat monitor enabled for two containers, got %d", len(client.startHBCalls))
	}
	if len(client.reportHBCalls) != 2 {
		t.Fatalf("expected two heartbeat reports, got %d", len(client.reportHBCalls))
	}
}

func TestCollectorSendLivenessHeartbeatsPrunesAbsentContainers(t *testing.T) {
	client := &fakeCollectorClient{
		listContainers: []ContainerState{},
	}
	collector := NewTrustStateCollector(client, nil, nil, nil, DefaultRemediationPolicy())
	collector.setState(v1.ContainerTrustState{
		ContainerID: "cg1",
		Verdict:     v1.ContainerTrustVerdictTrusted,
	})
	collector.mu.Lock()
	collector.heartbeatMonitored["cg1"] = struct{}{}
	collector.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	collector.sendLivenessHeartbeats(ctx)

	if len(collector.GetStates()) != 0 {
		t.Fatalf("expected stale state to be pruned when container list is empty")
	}
	collector.mu.RLock()
	_, monitored := collector.heartbeatMonitored["cg1"]
	collector.mu.RUnlock()
	if monitored {
		t.Fatalf("expected heartbeat monitor tracking to be pruned for removed container")
	}
}

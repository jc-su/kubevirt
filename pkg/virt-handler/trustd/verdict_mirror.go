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

// verdict_mirror.go — subscribes to AS.WatchVerdictUpdates and caches
// verdicts in memory, keyed by workload_id (stripped from the subject
// URL). Kubevirt's reconcile loop reads from this cache to populate
// VMI.Status.ContainerTrustStates — no polling, no direct AS calls on
// the reconcile hot path.
//
// Rationale: the old polling TrustStateCollector produced verdicts
// locally by calling AttestContainer + verifier.VerifyEvidence on a
// timer. With the canonical model, verdicts live in attestation-service
// (the Verifier in RATS terms), and the host just mirrors them for
// display.

package trustd

import (
	"context"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kubevirt.io/client-go/log"

	v1 "kubevirt.io/api/core/v1"
	attestationv1 "kubevirt.io/kubevirt/pkg/virt-handler/trustd/attestationproto/v1"
)

const workloadSubjectPrefix = "workload://"

// VerdictMirror caches the latest AS verdict for each workload_id the
// mirror has been told about. Safe for concurrent reads / writes.
type VerdictMirror struct {
	mu        sync.RWMutex
	byID      map[string]v1.ContainerTrustState
	versions  map[string]uint64 // drop stale updates
	lastError string
}

// NewVerdictMirror returns an empty mirror. Call Run to start the
// subscription loop.
func NewVerdictMirror() *VerdictMirror {
	return &VerdictMirror{
		byID:     make(map[string]v1.ContainerTrustState),
		versions: make(map[string]uint64),
	}
}

// Run opens a WatchVerdictUpdates stream against `client` and blocks
// until ctx is cancelled. On stream error, retries with exponential
// backoff (capped at 10s) so a flapping attestation-service doesn't
// tear down the mirror. Returns only when ctx is Done.
//
// `subjects` filters the stream — pass the full list of workload:// URLs
// this mirror should track. Empty = all subjects.
func (m *VerdictMirror) Run(ctx context.Context, client *ASClient, subjects []string) {
	if client == nil {
		log.DefaultLogger().V(2).Info("verdict mirror disabled (no AS client)")
		return
	}
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		handler := func(u ASVerdict) error {
			m.apply(u)
			return nil
		}
		err := client.WatchVerdictUpdates(ctx, subjects, 0, handler)
		if ctx.Err() != nil {
			return
		}
		m.setError(err.Error())
		log.DefaultLogger().Warningf("verdict mirror: stream failed, retrying in %s: %v", backoff, err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 10*time.Second {
			backoff *= 2
		}
	}
}

func (m *VerdictMirror) apply(u ASVerdict) {
	workloadID := strings.TrimPrefix(u.Subject, workloadSubjectPrefix)
	if workloadID == u.Subject {
		// Not a workload:// subject — ignore (e.g. legacy cgroup:// leftover).
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if prev, ok := m.versions[workloadID]; ok && u.Version <= prev {
		return // stale
	}
	m.versions[workloadID] = u.Version

	state := v1.ContainerTrustState{
		ContainerID:      workloadID,
		ContainerName:    workloadID,
		Verdict:          mapVerdict(u.Verdict),
		VerdictMessage:   u.Message,
		AttestationToken: u.AttestationToken,
	}
	if u.VerifiedAt > 0 {
		t := metav1.NewTime(time.Unix(u.VerifiedAt, 0))
		state.LastAttestation = &t
	}
	m.byID[workloadID] = state
}

// States returns the mirrored verdicts for the given workload_ids, in
// the same order. Missing entries are reported with Verdict=Unknown so
// the caller always has one state per requested id.
func (m *VerdictMirror) States(workloadIDs []string) []v1.ContainerTrustState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]v1.ContainerTrustState, 0, len(workloadIDs))
	for _, id := range workloadIDs {
		if state, ok := m.byID[id]; ok {
			out = append(out, state)
			continue
		}
		out = append(out, v1.ContainerTrustState{
			ContainerID:   id,
			ContainerName: id,
			Verdict:       v1.ContainerTrustVerdictUnknown,
		})
	}
	return out
}

func (m *VerdictMirror) setError(msg string) {
	m.mu.Lock()
	m.lastError = msg
	m.mu.Unlock()
}

func mapVerdict(v attestationv1.Verdict) v1.ContainerTrustVerdict {
	switch v {
	case attestationv1.Verdict_VERDICT_TRUSTED:
		return v1.ContainerTrustVerdictTrusted
	case attestationv1.Verdict_VERDICT_UNTRUSTED:
		return v1.ContainerTrustVerdictUntrusted
	case attestationv1.Verdict_VERDICT_STALE:
		return v1.ContainerTrustVerdictStale
	default:
		return v1.ContainerTrustVerdictUnknown
	}
}

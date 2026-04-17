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

// Package-level: drift_subscriber.go is the canonical event-driven
// enforcement path. trustd publishes a PhaseChange event when its
// in-guest drift detector promotes a container from Trusted→Untrusted
// (see trustd/src/main.rs:run_drift_detector). This subscriber sits
// on the host, filters for those transitions, consults the configured
// policy, and triggers in-guest remediation through trustd.
//
// Design notes:
//   - Decision (policy lookup) happens here on the host so a compromised
//     in-guest trustd cannot silence enforcement.
//   - Execution (the actual cgroup kill+restart) happens in trustd so
//     kubevirt does not need container-runtime access inside the CVM.
//   - Subscriber is cheap: one long-lived gRPC stream per CVM. No polling,
//     no per-container state on the host.
//
// This replaces the old polling TrustStateCollector's enforcement side;
// the collector's attestation-producing side (AttestContainer → Verify)
// is being migrated to AttestWorkload → VerifyWorkload in parallel.

package trustd

import (
	"context"
	"fmt"
	"time"

	"kubevirt.io/client-go/log"

	trustdv1 "kubevirt.io/kubevirt/pkg/virt-handler/trustd/proto/v1"
)

// PolicyLookup resolves a remediation action for an Untrusted verdict.
// Implementations can consult the attestation-service authority
// (AttestationService.GetLatestVerdict), a cached PolicyAction map, or a
// static default. Returning RemediationActionNone is an explicit "observe
// only" decision and skips enforcement.
type PolicyLookup interface {
	ActionFor(ctx context.Context, workloadID, cgroupPath string) RemediationAction
}

// StaticPolicy always returns the same action regardless of subject.
type StaticPolicy struct{ Action RemediationAction }

func (p StaticPolicy) ActionFor(_ context.Context, _, _ string) RemediationAction {
	return p.Action
}

// DriftSubscriber runs the canonical flow: WatchContainerEvents on trustd,
// filter PhaseChange→Untrusted, resolve policy, call RestartContainer.
type DriftSubscriber struct {
	client   *Client
	policy   PolicyLookup
	cooldown time.Duration

	// lastAction tracks when we last remediated a given cgroup so a rapid
	// sequence of drift events doesn't cause a restart storm. Keyed by
	// cgroup_path.
	lastAction map[string]time.Time
}

// NewDriftSubscriber wires a subscriber against a trustd client. The policy
// is consulted on every Untrusted transition.
func NewDriftSubscriber(client *Client, policy PolicyLookup, cooldown time.Duration) *DriftSubscriber {
	if cooldown <= 0 {
		cooldown = defaultRemediationCooldown
	}
	return &DriftSubscriber{
		client:     client,
		policy:     policy,
		cooldown:   cooldown,
		lastAction: make(map[string]time.Time),
	}
}

// Run blocks until ctx is cancelled or the trustd stream returns an error.
// Caller is responsible for reconnecting on error; the subscriber is
// stateless across reconnects (any ongoing remediation cooldown is
// preserved in-process, which is intentional — restart after reconnect
// would be acceptable but slightly noisy).
func (s *DriftSubscriber) Run(ctx context.Context) error {
	return s.client.WatchContainerEvents(ctx, func(event ContainerEvent) error {
		// Only the drift transition matters. Measurement events fire during
		// normal container startup; we don't act on those, trustd's own
		// lifecycle layer does (Ready→Trusted after first attest).
		if event.EventType != EventTypePhaseChange {
			return nil
		}
		if int32(event.Phase) != int32(trustdv1.ContainerPhase_CONTAINER_PHASE_UNTRUSTED) {
			return nil
		}

		workloadID := event.ContainerName
		cgroup := event.CgroupPath
		if cgroup == "" && workloadID == "" {
			log.DefaultLogger().V(2).Info("drift_subscriber: untrusted event with no cgroup/workload_id; skipping")
			return nil
		}

		if last, ok := s.lastAction[cgroup]; ok {
			if time.Since(last) < s.cooldown {
				log.DefaultLogger().V(3).Infof(
					"drift_subscriber: cooldown active for %s (%.1fs remaining); skipping",
					cgroup, (s.cooldown - time.Since(last)).Seconds(),
				)
				return nil
			}
		}

		action := s.policy.ActionFor(ctx, workloadID, cgroup)
		log.DefaultLogger().Infof(
			"drift_subscriber: untrusted verdict for workload=%s cgroup=%s policy=%s",
			workloadID, cgroup, action,
		)

		switch action {
		case RemediationActionNone, RemediationActionAlert:
			// Observe only. The verdict is already on VMI status; no
			// execution.
			return nil
		case RemediationActionRestart, RemediationActionKill:
			if cgroup == "" {
				return fmt.Errorf(
					"drift_subscriber: cannot remediate workload=%s: trustd did not supply cgroup_path in PhaseChange event",
					workloadID,
				)
			}
			reqCtx, cancel := context.WithTimeout(ctx, DefaultRequestTimeout)
			defer cancel()
			if _, err := s.client.RestartContainer(reqCtx, cgroup); err != nil {
				return fmt.Errorf(
					"drift_subscriber: RestartContainer(%s) for workload=%s failed: %w",
					cgroup, workloadID, err,
				)
			}
			s.lastAction[cgroup] = time.Now()
			log.DefaultLogger().Infof(
				"drift_subscriber: remediated workload=%s cgroup=%s (%s)",
				workloadID, cgroup, action,
			)
		default:
			return fmt.Errorf(
				"drift_subscriber: unknown remediation action %q for workload=%s",
				action, workloadID,
			)
		}
		return nil
	})
}

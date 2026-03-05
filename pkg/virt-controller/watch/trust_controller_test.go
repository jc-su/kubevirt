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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"

	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/kubevirt/pkg/testutils"

	"kubevirt.io/kubevirt/pkg/virt-config/featuregate"
)

var _ = Describe("TrustController", func() {
	var (
		recorder *record.FakeRecorder
		tc       *TrustController
	)

	newTDXVMI := func() *v1.VirtualMachineInstance {
		vmi := &v1.VirtualMachineInstance{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tdx-test",
				Namespace: "default",
			},
			Spec: v1.VirtualMachineInstanceSpec{
				Domain: v1.DomainSpec{
					LaunchSecurity: &v1.LaunchSecurity{
						TDX: &v1.TDX{
							Attestation: &v1.TDXAttestation{
								Enabled: true,
							},
						},
					},
				},
			},
		}
		return vmi
	}

	BeforeEach(func() {
		recorder = record.NewFakeRecorder(100)
		kvConfig := &v1.KubeVirtConfiguration{
			DeveloperConfiguration: &v1.DeveloperConfiguration{
				FeatureGates: []string{featuregate.ContainerAttestation},
			},
		}
		config, _, _ := testutils.NewFakeClusterConfigUsingKVConfig(kvConfig)
		tc = NewTrustController(nil, recorder, config)
	})

	It("should emit warning event for untrusted container", func() {
		vmi := newTDXVMI()
		vmi.Status.ContainerTrustStates = []v1.ContainerTrustState{
			{
				ContainerID:    "/kubepods/pod123/container456",
				Verdict:        v1.ContainerTrustVerdictUntrusted,
				VerdictMessage: "RTMR3 mismatch",
			},
		}
		tc.ProcessVMI(vmi)

		var event string
		Eventually(recorder.Events).Should(Receive(&event))
		Expect(event).To(ContainSubstring(reasonContainerUntrusted))
		Expect(event).To(ContainSubstring("RTMR3 mismatch"))
	})

	It("should emit warning event for stale container", func() {
		vmi := newTDXVMI()
		lastAttest := metav1.NewTime(time.Now().Add(-5 * time.Minute))
		vmi.Status.ContainerTrustStates = []v1.ContainerTrustState{
			{
				ContainerID:     "/kubepods/pod123/container456",
				Verdict:         v1.ContainerTrustVerdictStale,
				LastAttestation: &lastAttest,
			},
		}
		tc.ProcessVMI(vmi)

		var event string
		Eventually(recorder.Events).Should(Receive(&event))
		Expect(event).To(ContainSubstring(reasonHeartbeatStale))
	})

	It("should not emit event for trusted container", func() {
		vmi := newTDXVMI()
		vmi.Status.ContainerTrustStates = []v1.ContainerTrustState{
			{
				ContainerID: "/kubepods/pod123/container456",
				Verdict:     v1.ContainerTrustVerdictTrusted,
			},
		}
		tc.ProcessVMI(vmi)

		Consistently(recorder.Events).ShouldNot(Receive())
	})

	It("should not process VMI without TDX attestation", func() {
		vmi := &v1.VirtualMachineInstance{
			ObjectMeta: metav1.ObjectMeta{Name: "no-tdx", Namespace: "default"},
			Spec: v1.VirtualMachineInstanceSpec{
				Domain: v1.DomainSpec{},
			},
			Status: v1.VirtualMachineInstanceStatus{
				ContainerTrustStates: []v1.ContainerTrustState{
					{
						ContainerID:    "/test",
						Verdict:        v1.ContainerTrustVerdictUntrusted,
						VerdictMessage: "should not trigger",
					},
				},
			},
		}
		tc.ProcessVMI(vmi)

		Consistently(recorder.Events).ShouldNot(Receive())
	})

	It("should not process when ContainerAttestation gate is disabled", func() {
		kvConfigNoGate := &v1.KubeVirtConfiguration{}
		configNoGate, _, _ := testutils.NewFakeClusterConfigUsingKVConfig(kvConfigNoGate)
		tcNoGate := NewTrustController(nil, recorder, configNoGate)

		vmi := newTDXVMI()
		vmi.Status.ContainerTrustStates = []v1.ContainerTrustState{
			{
				ContainerID:    "/test",
				Verdict:        v1.ContainerTrustVerdictUntrusted,
				VerdictMessage: "should not trigger",
			},
		}
		tcNoGate.ProcessVMI(vmi)

		Consistently(recorder.Events).ShouldNot(Receive())
	})

	It("should emit events for multiple containers with different verdicts", func() {
		vmi := newTDXVMI()
		vmi.Status.ContainerTrustStates = []v1.ContainerTrustState{
			{
				ContainerID:    "/kubepods/pod/c1",
				Verdict:        v1.ContainerTrustVerdictUntrusted,
				VerdictMessage: "bad binary",
			},
			{
				ContainerID: "/kubepods/pod/c2",
				Verdict:     v1.ContainerTrustVerdictTrusted,
			},
			{
				ContainerID: "/kubepods/pod/c3",
				Verdict:     v1.ContainerTrustVerdictStale,
			},
		}
		tc.ProcessVMI(vmi)

		// Should get exactly 2 events (untrusted + stale), not trusted
		var events []string
		Eventually(recorder.Events).Should(Receive(ContainSubstring(reasonContainerUntrusted)))
		Eventually(recorder.Events).Should(Receive(ContainSubstring(reasonHeartbeatStale)))
		Consistently(recorder.Events).ShouldNot(Receive())
		_ = events
	})

	Describe("formatTimeOrNever", func() {
		It("should return 'never' for nil time", func() {
			Expect(formatTimeOrNever(nil)).To(Equal("never"))
		})

		It("should format a valid time", func() {
			t := metav1.NewTime(time.Now().Add(-2 * time.Minute))
			result := formatTimeOrNever(&t)
			Expect(result).To(ContainSubstring("ago"))
		})
	})
})

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

package launchsecurity

import (
	v1 "kubevirt.io/api/core/v1"
)

const (
	// Per Intel TDX Module spec, the 64-bit ATTRIBUTES field in the TD's
	// TDREPORT is a bitmask. Two bits matter here:
	//   bit  0 (0x1)          DEBUG           — set ⇒ TD is a debug TD
	//   bit 28 (0x10000000)   SEPT_VE_DISABLE — set ⇒ guest does not fault on
	//                         Secure-EPT violations (required for modern
	//                         Linux TDX guests; KVM rejects TDs without it
	//                         on most production platforms)
	//
	// Production TDs (noDebug=true) MUST leave bit 0 clear; debug TDs set
	// it. SEPT_VE_DISABLE is set in both cases.
	//
	// The previous definitions here had the two values swapped — which
	// caused `launchSecurity.tdx.policy.noDebug: true` to actually request
	// a debug TD, and QEMU aborted with
	// "Invalid attributes 0x10000001 for TDX VM (KVM supported: 0x10000000)"
	// on hosts whose TDX module denies debug creation.
	TDXPolicyNoDebug = "0x10000000"
	TDXPolicyDebug   = "0x10000001"
)

// TDXPolicyFromSpec computes the TDX policy string from the API spec.
// NoDebug defaults to true (debugging disabled) for security.
func TDXPolicyFromSpec(policy *v1.TDXPolicy) string {
	if policy != nil && policy.NoDebug != nil && !*policy.NoDebug {
		return TDXPolicyDebug
	}
	return TDXPolicyNoDebug
}

// TDXPolicy returns the default TDX security policy (no debug).
func TDXPolicy() string {
	return TDXPolicyNoDebug
}

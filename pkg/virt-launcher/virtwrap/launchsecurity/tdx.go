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
	// TDXPolicyNoDebug is the TDX policy value that disables debugging.
	// Bit 0: NoDebug (set), Bit 28: TDX-specific marker.
	TDXPolicyNoDebug = "0x10000001"
	// TDXPolicyDebug is the TDX policy value that allows debugging (bit 0 clear).
	TDXPolicyDebug = "0x10000000"
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

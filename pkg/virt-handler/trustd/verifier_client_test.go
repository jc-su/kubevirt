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

import "testing"

func TestMapVerifierPolicyAction(t *testing.T) {
	tests := []struct {
		name           string
		policyAction   string
		expectedAction RemediationAction
	}{
		{
			name:           "restart action",
			policyAction:   "restart",
			expectedAction: RemediationActionRestart,
		},
		{
			name:           "alert action",
			policyAction:   "alert",
			expectedAction: RemediationActionAlert,
		},
		{
			name:           "none action",
			policyAction:   "none",
			expectedAction: RemediationActionNone,
		},
		{
			name:           "normalized action",
			policyAction:   "  ReStArT ",
			expectedAction: RemediationActionRestart,
		},
		{
			name:           "unknown action defaults none",
			policyAction:   "unexpected",
			expectedAction: RemediationActionNone,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			action := mapVerifierPolicyAction(tc.policyAction)
			if action != tc.expectedAction {
				t.Fatalf("expected action %q, got %q", tc.expectedAction, action)
			}
		})
	}
}

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

package rest

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/emicklei/go-restful/v3"

	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/log"

	kutil "kubevirt.io/kubevirt/pkg/util"
	trustd "kubevirt.io/kubevirt/pkg/virt-handler/trustd"
)

// TDXContainerListHandler returns all containers tracked by trustd inside a TDX CVM.
func (lh *LifecycleHandler) TDXContainerListHandler(request *restful.Request, response *restful.Response) {
	vmi, code, err := getVMI(request, lh.vmiStore)
	if err != nil {
		log.Log.Reason(err).Error(failedRetrieveVMI)
		response.WriteError(code, err)
		return
	}

	if !kutil.IsTDXAttestationRequested(vmi) {
		response.WriteError(http.StatusBadRequest, fmt.Errorf("TDX container attestation not enabled for this VMI"))
		return
	}

	client, err := getTrustdClient(vmi)
	if err != nil {
		log.Log.Object(vmi).Reason(err).Error("Failed to create trustd client")
		response.WriteError(http.StatusServiceUnavailable, err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	containers, err := client.ListContainers(ctx)
	if err != nil {
		log.Log.Object(vmi).Reason(err).Error("Failed to list containers from trustd")
		response.WriteError(http.StatusInternalServerError, err)
		return
	}

	// Convert to API types
	result := v1.TDXContainerListInfo{
		Containers: make([]v1.ContainerTrustState, 0, len(containers)),
	}
	for _, c := range containers {
		state := v1.ContainerTrustState{
			ContainerID:      c.CgroupPath,
			RTMR3:            c.RTMR3,
			MeasurementCount: c.MeasurementCount,
		}
		result.Containers = append(result.Containers, state)
	}

	response.WriteAsJson(result)
}

// getTrustdClient creates a trustd vsock client for the given VMI.
func getTrustdClient(vmi *v1.VirtualMachineInstance) (*trustd.Client, error) {
	if vmi.Status.VSOCKCID == nil {
		return nil, fmt.Errorf("VMI %s has no VSOCK CID allocated", vmi.Name)
	}
	return trustd.NewClient(*vmi.Status.VSOCKCID), nil
}

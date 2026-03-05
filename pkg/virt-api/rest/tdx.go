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
	"fmt"

	"github.com/emicklei/go-restful/v3"

	"k8s.io/apimachinery/pkg/api/errors"
	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"

	kutil "kubevirt.io/kubevirt/pkg/util"
)

const (
	tdxNoAttestationErr = "TDX container attestation not enabled for this VMI"
)

func (app *SubresourceAPIApp) ensureContainerAttestationEnabled(response *restful.Response) bool {
	if !app.clusterConfig.ContainerAttestationEnabled() {
		writeError(errors.NewBadRequest(fmt.Sprintf(featureGateDisabledErrFmt, "ContainerAttestation")), response)
		return false
	}
	return true
}

// TDXContainerListHandler returns the list of containers and their trust states
// inside a TDX CVM.
func (app *SubresourceAPIApp) TDXContainerListHandler(request *restful.Request, response *restful.Response) {
	if !app.ensureContainerAttestationEnabled(response) {
		return
	}

	validate := func(vmi *v1.VirtualMachineInstance) *errors.StatusError {
		if !vmi.IsRunning() {
			return errors.NewConflict(v1.Resource("virtualmachineinstance"), vmi.Name, fmt.Errorf(vmiNotRunning))
		}
		if !kutil.IsTDXAttestationRequested(vmi) {
			return errors.NewConflict(v1.Resource("virtualmachineinstance"), vmi.Name, fmt.Errorf(tdxNoAttestationErr))
		}
		return nil
	}

	getURL := func(vmi *v1.VirtualMachineInstance, conn kubecli.VirtHandlerConn) (string, error) {
		return conn.TDXContainerListURI(vmi)
	}

	app.httpGetRequestHandler(request, response, validate, getURL, v1.TDXContainerListInfo{})
}

// TDXContainerAttestHandler triggers attestation of a specific container inside a TDX CVM.
func (app *SubresourceAPIApp) TDXContainerAttestHandler(request *restful.Request, response *restful.Response) {
	if !app.ensureContainerAttestationEnabled(response) {
		return
	}

	if request.Request.Body == nil {
		writeError(errors.NewBadRequest("Request body required: specify containerID to attest"), response)
		return
	}

	validate := func(vmi *v1.VirtualMachineInstance) *errors.StatusError {
		if !vmi.IsRunning() {
			return errors.NewConflict(v1.Resource("virtualmachineinstance"), vmi.Name, fmt.Errorf(vmiNotRunning))
		}
		if !kutil.IsTDXAttestationRequested(vmi) {
			return errors.NewConflict(v1.Resource("virtualmachineinstance"), vmi.Name, fmt.Errorf(tdxNoAttestationErr))
		}
		return nil
	}

	getURL := func(vmi *v1.VirtualMachineInstance, conn kubecli.VirtHandlerConn) (string, error) {
		return conn.TDXContainerAttestURI(vmi)
	}

	app.putRequestHandler(request, response, validate, getURL, false)
}

// TDXTrustStatesHandler returns the ContainerTrustStates from the VMI status.
// This is a convenience endpoint that reads directly from the VMI status
// rather than proxying to virt-handler.
func (app *SubresourceAPIApp) TDXTrustStatesHandler(request *restful.Request, response *restful.Response) {
	if !app.ensureContainerAttestationEnabled(response) {
		return
	}

	validate := func(vmi *v1.VirtualMachineInstance) *errors.StatusError {
		if !kutil.IsTDXAttestationRequested(vmi) {
			return errors.NewConflict(v1.Resource("virtualmachineinstance"), vmi.Name, fmt.Errorf(tdxNoAttestationErr))
		}
		return nil
	}

	name := request.PathParameter("name")
	namespace := request.PathParameter("namespace")
	vmi, statusError := app.fetchAndValidateVirtualMachineInstance(namespace, name, validate)
	if statusError != nil {
		writeError(statusError, response)
		return
	}

	result := v1.TDXContainerListInfo{
		Containers: vmi.Status.ContainerTrustStates,
	}
	if err := response.WriteAsJson(result); err != nil {
		writeError(errors.NewInternalError(err), response)
	}
}

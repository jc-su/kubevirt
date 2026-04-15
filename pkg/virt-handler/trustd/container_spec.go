/*
 * Container spec parsing for VMI annotation-driven container lifecycle.
 *
 * virt-handler reads container specs from the VMI annotation
 * `trustd.trustweave.io/containers` and calls trustd.StartContainer
 * for each after CVMAgentConnected flips true.
 *
 * Example annotation value (JSON array of container specs):
 *
 *   [
 *     {
 *       "name": "trustweave-mcp-0",
 *       "image": "trustweave/sequentialthink-ready:latest",
 *       "env": ["TRUSTWEAVE_READY_PORT=8443", "TRUSTWEAVE_CONTAINER_ID=trustweave-mcp-0"],
 *       "ports": [8443],
 *       "network_host": true,
 *       "ready_marker": "TRUSTWEAVE_READY"
 *     }
 *   ]
 */

package trustd

import (
	"encoding/json"
	"fmt"

	v1 "kubevirt.io/api/core/v1"
)

const (
	// ContainerSpecAnnotation is the VMI annotation key that carries the
	// list of containers to start inside the CVM via trustd.
	ContainerSpecAnnotation = "trustd.trustweave.io/containers"
)

// AnnotationContainerSpec mirrors the proto StartContainerRequest but
// is JSON-serializable for use in VMI annotations.
type AnnotationContainerSpec struct {
	Name        string            `json:"name"`
	Image       string            `json:"image"`
	Env         []string          `json:"env,omitempty"`
	Ports       []int32           `json:"ports,omitempty"`
	NetworkHost bool              `json:"network_host,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	ReadyMarker string            `json:"ready_marker,omitempty"`
}

// ParseContainerSpecs reads the VMI annotation and returns the list of
// container specs. Returns nil (not an error) if the annotation is absent.
func ParseContainerSpecs(vmi *v1.VirtualMachineInstance) ([]AnnotationContainerSpec, error) {
	raw, ok := vmi.Annotations[ContainerSpecAnnotation]
	if !ok || raw == "" {
		return nil, nil
	}

	var specs []AnnotationContainerSpec
	if err := json.Unmarshal([]byte(raw), &specs); err != nil {
		return nil, fmt.Errorf("parse %s annotation: %w", ContainerSpecAnnotation, err)
	}

	for i := range specs {
		if specs[i].Name == "" {
			return nil, fmt.Errorf("container spec %d: name is required", i)
		}
		if specs[i].Image == "" {
			return nil, fmt.Errorf("container spec %d (%s): image is required", i, specs[i].Name)
		}
		if specs[i].ReadyMarker == "" {
			specs[i].ReadyMarker = "TRUSTWEAVE_READY"
		}
	}

	return specs, nil
}

// ToStartContainerRequest converts an annotation spec to the gRPC request
// that the trustd client expects.
func (s *AnnotationContainerSpec) ToStartContainerRequest() *StartContainerRequest {
	return &StartContainerRequest{
		Name:        s.Name,
		Image:       s.Image,
		Env:         s.Env,
		Ports:       s.Ports,
		NetworkHost: s.NetworkHost,
		Labels:      s.Labels,
		ReadyMarker: s.ReadyMarker,
	}
}

// StartContainerRequest is the Go-side struct matching the proto message.
// Used by client.go's StartContainer method.
type StartContainerRequest struct {
	Name        string
	Image       string
	Env         []string
	Ports       []int32
	NetworkHost bool
	Labels      map[string]string
	ReadyMarker string
}

// StartContainerResponse is the Go-side struct matching the proto response.
type StartContainerResponse struct {
	CgroupPath  string
	ContainerID string
	Started     bool
	Error       string
	Phase       int32
}

// StopContainerRequest is the Go-side struct for stopping a container.
type StopContainerRequest struct {
	Name           string
	CgroupPath     string
	TimeoutSeconds int32
}

// StopContainerResponse is the Go-side struct for the stop response.
type StopContainerResponse struct {
	Stopped bool
	Error   string
}

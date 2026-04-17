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

// as_client.go — minimal gRPC client for the attestation-service verdict
// surface. Kubevirt doesn't call VerifyWorkload itself (that's the MCP
// fork's responsibility); it only needs to *observe* verdicts so it can
// mirror them onto VMI.Status.ContainerTrustStates and surface them to
// `kubectl get vmi -o yaml`.

package trustd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	attestationv1 "kubevirt.io/kubevirt/pkg/virt-handler/trustd/attestationproto/v1"
)

const (
	// AttestationServiceAddrEnv is the TCP address of the host-side
	// attestation-service (verifier), e.g. "10.0.0.1:50051" or
	// "attestation-service.kube-system.svc.cluster.local:50051". When
	// unset, the verdict mirror is disabled (verdicts never appear on
	// VMI.Status.ContainerTrustStates); the drift subscriber still
	// enforces without needing the authority.
	AttestationServiceAddrEnv = "TRUSTFNCALL_ATTESTATION_SERVICE_ADDR"

	asDialTimeout    = 5 * time.Second
	asRequestTimeout = 30 * time.Second
)

// ASVerdict is the subset of attestation.v1.VerdictUpdate the mirror needs.
type ASVerdict struct {
	Subject          string // "workload://<id>"
	Verdict          attestationv1.Verdict
	Message          string
	PolicyAction     string
	AttestationToken string
	VerifiedAt       int64 // unix seconds
	ExpiresAt        int64
	Version          uint64
}

// ASClient wraps a grpc.ClientConn to attestation-service. Cheap to create
// (one per subscriber); the underlying HTTP/2 connection is reused across
// streams.
type ASClient struct {
	address string
	conn    *grpc.ClientConn
}

// NewASClientFromEnv builds an ASClient from the configured environment.
// Returns (nil, nil) when the env var is unset — callers should treat
// that as "verdict mirror disabled" and continue without one.
func NewASClientFromEnv() (*ASClient, error) {
	addr := strings.TrimSpace(os.Getenv(AttestationServiceAddrEnv))
	if addr == "" {
		return nil, nil
	}
	return NewASClient(addr)
}

func NewASClient(address string) (*ASClient, error) {
	dialCtx, cancel := context.WithTimeout(context.Background(), asDialTimeout)
	defer cancel()
	conn, err := grpc.DialContext(
		dialCtx,
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("dial attestation-service %s: %w", address, err)
	}
	return &ASClient{address: address, conn: conn}, nil
}

func (c *ASClient) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// WatchVerdictUpdates opens a server-stream and invokes `handler` for
// every verdict update filtered by subjects. Blocks until ctx is
// cancelled or the stream errors. Callers are responsible for
// reconnecting on error.
func (c *ASClient) WatchVerdictUpdates(
	ctx context.Context,
	subjects []string,
	afterVersion uint64,
	handler func(ASVerdict) error,
) error {
	if c == nil || c.conn == nil {
		return fmt.Errorf("attestation-service client is not initialized")
	}
	streamDesc := &grpc.StreamDesc{ServerStreams: true}
	stream, err := c.conn.NewStream(ctx, streamDesc,
		"/attestation.v1.AttestationService/WatchVerdictUpdates")
	if err != nil {
		return fmt.Errorf("open watch stream: %w", err)
	}
	req := &attestationv1.WatchVerdictUpdatesRequest{
		Subjects:     subjects,
		AfterVersion: afterVersion,
	}
	if err := stream.SendMsg(req); err != nil {
		return fmt.Errorf("send watch request: %w", err)
	}
	if err := stream.CloseSend(); err != nil {
		return fmt.Errorf("close watch send: %w", err)
	}

	for {
		msg := &attestationv1.VerdictUpdate{}
		if err := stream.RecvMsg(msg); err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("receive verdict: %w", err)
		}
		update := ASVerdict{
			Subject:          msg.GetSubject(),
			Verdict:          msg.GetVerdict(),
			Message:          msg.GetMessage(),
			PolicyAction:     msg.GetPolicyAction(),
			AttestationToken: msg.GetAttestationToken(),
			VerifiedAt:       msg.GetVerifiedAt(),
			ExpiresAt:        msg.GetExpiresAt(),
			Version:          msg.GetVersion(),
		}
		if err := handler(update); err != nil {
			return err
		}
	}
}

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

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	v1 "kubevirt.io/api/core/v1"
	attestationv1 "kubevirt.io/kubevirt/pkg/virt-handler/trustd/attestationproto/v1"
)

const (
	methodVerifyContainerEvidence = "/attestation.v1.AttestationService/VerifyContainerEvidence"
	methodWatchVerdictUpdates     = "/attestation.v1.AttestationService/WatchVerdictUpdates"
)

const (
	defaultVerifierDialTimeout    = 5 * time.Second
	defaultVerifierRequestTimeout = 30 * time.Second
)

const (
	attestationTLSEnabledEnv    = "TEE_MCP_ATTESTATION_TLS"
	attestationTLSCACertEnv     = "TEE_MCP_ATTESTATION_CA_CERT"
	attestationTLSClientCertEnv = "TEE_MCP_ATTESTATION_CLIENT_CERT"
	attestationTLSClientKeyEnv  = "TEE_MCP_ATTESTATION_CLIENT_KEY"
	attestationTLSServerNameEnv = "TEE_MCP_ATTESTATION_SERVER_NAME"
)

// RemoteAttestationVerifier calls the external attestation-service over gRPC.
type RemoteAttestationVerifier struct {
	address string

	mu   sync.Mutex
	conn *grpc.ClientConn
}

func NewRemoteAttestationVerifier(address string) *RemoteAttestationVerifier {
	return &RemoteAttestationVerifier{address: address}
}

func envBool(name string) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	switch raw {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func canonicalCgroupPath(cgroupPath string) string {
	normalized := strings.TrimSpace(cgroupPath)
	if normalized == "" {
		return ""
	}
	normalized = strings.TrimPrefix(normalized, "cgroup://")
	if !strings.HasPrefix(normalized, "/") {
		normalized = "/" + normalized
	}
	return normalized
}

func cgroupPathFromSubject(subject string) string {
	normalized := strings.TrimSpace(subject)
	if normalized == "" {
		return ""
	}
	if strings.HasPrefix(normalized, "cgroup://") {
		return canonicalCgroupPath(normalized)
	}
	return ""
}

func (v *RemoteAttestationVerifier) transportCredentials() (credentials.TransportCredentials, error) {
	if !envBool(attestationTLSEnabledEnv) {
		return insecure.NewCredentials(), nil
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if caPath := strings.TrimSpace(os.Getenv(attestationTLSCACertEnv)); caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert %q: %w", caPath, err)
		}
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(pem); !ok {
			return nil, fmt.Errorf("parse CA cert %q", caPath)
		}
		tlsConfig.RootCAs = pool
	}

	if serverName := strings.TrimSpace(os.Getenv(attestationTLSServerNameEnv)); serverName != "" {
		tlsConfig.ServerName = serverName
	}

	clientCertPath := strings.TrimSpace(os.Getenv(attestationTLSClientCertEnv))
	clientKeyPath := strings.TrimSpace(os.Getenv(attestationTLSClientKeyEnv))
	if clientCertPath != "" || clientKeyPath != "" {
		if clientCertPath == "" || clientKeyPath == "" {
			return nil, fmt.Errorf(
				"both %s and %s must be set for mTLS",
				attestationTLSClientCertEnv,
				attestationTLSClientKeyEnv,
			)
		}
		cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			return nil, fmt.Errorf(
				"load mTLS keypair cert=%q key=%q: %w",
				clientCertPath,
				clientKeyPath,
				err,
			)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return credentials.NewTLS(tlsConfig), nil
}

func (v *RemoteAttestationVerifier) dialContext(ctx context.Context) (*grpc.ClientConn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, defaultVerifierDialTimeout)
	defer cancel()

	creds, err := v.transportCredentials()
	if err != nil {
		return nil, err
	}

	return grpc.DialContext(
		dialCtx,
		v.address,
		grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
		grpc.WithContextDialer(func(ctx context.Context, address string) (net.Conn, error) {
			dialer := &net.Dialer{}
			return dialer.DialContext(ctx, "tcp", address)
		}),
	)
}

func (v *RemoteAttestationVerifier) getConn(ctx context.Context) (*grpc.ClientConn, error) {
	v.mu.Lock()
	if v.conn != nil {
		conn := v.conn
		v.mu.Unlock()
		return conn, nil
	}
	v.mu.Unlock()

	conn, err := v.dialContext(ctx)
	if err != nil {
		return nil, err
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.conn != nil {
		_ = conn.Close()
		return v.conn, nil
	}
	v.conn = conn
	return v.conn, nil
}

func (v *RemoteAttestationVerifier) resetConn() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.conn != nil {
		_ = v.conn.Close()
		v.conn = nil
	}
}

func shouldResetVerifierConn(err error) bool {
	switch status.Code(err) {
	case codes.Unavailable, codes.Canceled, codes.DeadlineExceeded, codes.Internal, codes.Unknown:
		return true
	default:
		return false
	}
}

func (v *RemoteAttestationVerifier) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.conn == nil {
		return nil
	}
	err := v.conn.Close()
	v.conn = nil
	return err
}

func verifierRequestContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, defaultVerifierRequestTimeout)
}

func (v *RemoteAttestationVerifier) VerifyEvidence(ctx context.Context, evidence *AttestContainerResponse) (*VerificationResult, error) {
	if evidence == nil {
		return nil, fmt.Errorf("evidence is nil")
	}

	reqCtx, cancel := verifierRequestContext(ctx)
	defer cancel()

	conn, err := v.getConn(reqCtx)
	if err != nil {
		return nil, fmt.Errorf("dial attestation-service %s: %w", v.address, err)
	}

	tdQuote := []byte(nil)
	if evidence.TDQuote != "" {
		decoded, err := base64.StdEncoding.DecodeString(evidence.TDQuote)
		if err != nil {
			return nil, fmt.Errorf("decode td quote: %w", err)
		}
		tdQuote = decoded
	}

	measurements := make([]*attestationv1.MeasurementEntry, 0, len(evidence.Measurements))
	for _, measurement := range evidence.Measurements {
		measurements = append(measurements, &attestationv1.MeasurementEntry{
			Digest: measurement.Digest,
			File:   measurement.File,
		})
	}

	normalizedCgroupPath := canonicalCgroupPath(evidence.CgroupPath)
	// Keep identity semantics explicit: cgroup_path carries container identity here.
	// Do not overload container_image with cgroup subjects.
	req := &attestationv1.VerifyRequest{
		CgroupPath:     normalizedCgroupPath,
		Rtmr3:          evidence.RTMR3,
		InitialRtmr3:   evidence.InitialRTMR3,
		Measurements:   measurements,
		Nonce:          evidence.Nonce,
		ReportData:     evidence.ReportData,
		TdQuote:        tdQuote,
		ContainerImage: "",
	}
	resp := &attestationv1.VerifyResponse{}

	if err := conn.Invoke(reqCtx, methodVerifyContainerEvidence, req, resp); err != nil {
		if shouldResetVerifierConn(err) {
			v.resetConn()
		}
		return nil, fmt.Errorf("verify evidence: %w", err)
	}

	return &VerificationResult{
		Verdict:          mapVerifierVerdict(resp.GetVerdict()),
		Message:          resp.GetMessage(),
		AttestationToken: resp.GetAttestationToken(),
		PolicyAction:     mapVerifierPolicyAction(resp.GetPolicyAction()),
	}, nil
}

func (v *RemoteAttestationVerifier) WatchVerdictUpdates(
	ctx context.Context,
	subjects []string,
	afterVersion uint64,
	handler func(AuthorityVerdictUpdate) error,
) error {
	if handler == nil {
		return fmt.Errorf("verdict handler is nil")
	}

	conn, err := v.getConn(ctx)
	if err != nil {
		return fmt.Errorf("dial attestation-service %s: %w", v.address, err)
	}

	streamDesc := &grpc.StreamDesc{ServerStreams: true}
	stream, err := conn.NewStream(ctx, streamDesc, methodWatchVerdictUpdates)
	if err != nil {
		if shouldResetVerifierConn(err) {
			v.resetConn()
		}
		return fmt.Errorf("watch verdict updates: %w", err)
	}
	watchReq := &attestationv1.WatchVerdictUpdatesRequest{
		Subjects:     subjects,
		AfterVersion: afterVersion,
	}
	if err := stream.SendMsg(watchReq); err != nil {
		if shouldResetVerifierConn(err) {
			v.resetConn()
		}
		return fmt.Errorf("send verdict watch request: %w", err)
	}
	if err := stream.CloseSend(); err != nil {
		if shouldResetVerifierConn(err) {
			v.resetConn()
		}
		return fmt.Errorf("close verdict watch request stream: %w", err)
	}

	for {
		record := &attestationv1.VerdictUpdate{}
		err := stream.RecvMsg(record)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			if shouldResetVerifierConn(err) {
				v.resetConn()
			}
			return fmt.Errorf("receive verdict update: %w", err)
		}

		if err := handler(AuthorityVerdictUpdate{
			Subject:          record.GetSubject(),
			CgroupPath:       cgroupPathFromSubject(record.GetSubject()),
			Verdict:          mapVerifierVerdict(record.GetVerdict()),
			Message:          record.GetMessage(),
			AttestationToken: record.GetAttestationToken(),
			PolicyAction:     mapVerifierPolicyAction(record.GetPolicyAction()),
			Version:          record.GetVersion(),
		}); err != nil {
			return err
		}
	}
}

func mapVerifierVerdict(verdict attestationv1.Verdict) v1.ContainerTrustVerdict {
	switch verdict {
	case attestationv1.Verdict_VERDICT_TRUSTED:
		return v1.ContainerTrustVerdictTrusted
	case attestationv1.Verdict_VERDICT_UNTRUSTED:
		return v1.ContainerTrustVerdictUntrusted
	case attestationv1.Verdict_VERDICT_STALE:
		return v1.ContainerTrustVerdictStale
	case attestationv1.Verdict_VERDICT_UNKNOWN:
		return v1.ContainerTrustVerdictUnknown
	default:
		return v1.ContainerTrustVerdictUnknown
	}
}

func mapVerifierPolicyAction(action string) RemediationAction {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "none":
		return RemediationActionNone
	case "alert":
		return RemediationActionAlert
	case "restart":
		return RemediationActionRestart
	case "kill":
		return RemediationActionKill
	default:
		return RemediationActionNone
	}
}

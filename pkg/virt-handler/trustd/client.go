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
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/mdlayher/vsock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"kubevirt.io/client-go/log"

	trustdv1 "kubevirt.io/kubevirt/pkg/virt-handler/trustd/proto/v1"
)

const (
	// DefaultTrustdPort is the default vsock port trustd listens on.
	DefaultTrustdPort = 1235

	// DefaultDialTimeout is the timeout for connecting to trustd.
	DefaultDialTimeout = 5 * time.Second

	// DefaultRequestTimeout is the timeout for a single RPC request.
	DefaultRequestTimeout = 30 * time.Second

	nonceSize = 32
)

const (
	methodAttestContainer   = "/trustd.v1.Trustd/AttestContainer"
	methodListContainers    = "/trustd.v1.Trustd/ListContainers"
	methodWatchEvents       = "/trustd.v1.Trustd/WatchContainerEvents"
	methodGetTDQuote        = "/trustd.v1.Trustd/GetTDQuote"
	methodPing              = "/trustd.v1.Trustd/Ping"
	methodGetContainerState = "/trustd.v1.Trustd/GetContainerState"
	methodRestartContainer  = "/trustd.v1.Trustd/RestartContainer"
	methodStartHeartbeat    = "/trustd.v1.Trustd/StartHeartbeatMonitor"
	methodStopHeartbeat     = "/trustd.v1.Trustd/StopHeartbeatMonitor"
	methodReportHeartbeat   = "/trustd.v1.Trustd/ReportHeartbeat"
)

// Client communicates with trustd inside a TDX CVM via gRPC-over-vsock.
type Client struct {
	cid  uint32
	port uint32
}

// NewClient creates a new trustd client for the given vsock CID.
func NewClient(cid uint32) *Client {
	return &Client{cid: cid, port: DefaultTrustdPort}
}

// NewClientWithPort creates a client with a custom port.
func NewClientWithPort(cid, port uint32) *Client {
	return &Client{cid: cid, port: port}
}

// AttestContainerRequest is the request for container attestation.
type AttestContainerRequest struct {
	CgroupPath     string
	NonceHex       string
	IncludeTDQuote bool
}

// AttestContainerResponse is the attestation evidence for one container.
type AttestContainerResponse struct {
	CgroupPath       string
	RTMR3            string
	InitialRTMR3     string
	MeasurementCount int64
	Measurements     []ContainerMeasurement
	ReportData       string
	Nonce            string
	TDQuote          string // base64
	Timestamp        int64
}

// ContainerMeasurement is a single IMA file measurement.
type ContainerMeasurement struct {
	Digest string
	File   string
}

// ContainerState is the current state of a tracked container.
type ContainerState struct {
	CgroupPath          string
	RTMR3               string
	InitialRTMR3        string
	MeasurementCount    int64
	LastHeartbeat       int64
	HeartbeatCount      int64
	HeartbeatMonitoring bool
}

// ContainerEventType maps to trustd.v1.EventType.
type ContainerEventType int32

const (
	EventTypeUnspecified   ContainerEventType = ContainerEventType(trustdv1.EventType_EVENT_TYPE_UNSPECIFIED)
	EventTypeNew           ContainerEventType = ContainerEventType(trustdv1.EventType_EVENT_TYPE_NEW)
	EventTypeMeasurement   ContainerEventType = ContainerEventType(trustdv1.EventType_EVENT_TYPE_MEASUREMENT)
	EventTypeHeartbeat     ContainerEventType = ContainerEventType(trustdv1.EventType_EVENT_TYPE_HEARTBEAT)
	EventTypeHeartbeatMiss ContainerEventType = ContainerEventType(trustdv1.EventType_EVENT_TYPE_HEARTBEAT_MISS)
	EventTypeRemoved       ContainerEventType = ContainerEventType(trustdv1.EventType_EVENT_TYPE_REMOVED)
	EventTypeAttestBegin   ContainerEventType = ContainerEventType(trustdv1.EventType_EVENT_TYPE_ATTEST_BEGIN)
	EventTypeAttestEnd     ContainerEventType = ContainerEventType(trustdv1.EventType_EVENT_TYPE_ATTEST_END)
)

// ContainerEvent is emitted by trustd watch stream.
type ContainerEvent struct {
	EventType        ContainerEventType
	CgroupPath       string
	Timestamp        int64
	Digest           string
	Filename         string
	Detail           string
	RTMR3            string
	MeasurementCount int64
}

// PingResponse is the trustd liveness response.
type PingResponse struct {
	Version           string
	UptimeSeconds     int64
	ContainersTracked int64
}

func (c *Client) dialContext(ctx context.Context) (*grpc.ClientConn, error) {
	connCtx, cancel := context.WithTimeout(ctx, DefaultDialTimeout)
	defer cancel()

	return grpc.DialContext(
		connCtx,
		"passthrough:///trustd-vsock",
		grpc.WithBlock(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return vsock.Dial(c.cid, c.port, nil)
		}),
	)
}

func requestContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, DefaultRequestTimeout)
}

func newNonceHex() (string, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce), nil
}

// Ping checks if trustd is alive and returns version info.
func (c *Client) Ping(ctx context.Context) (*PingResponse, error) {
	reqCtx, cancel := requestContext(ctx)
	defer cancel()

	conn, err := c.dialContext(reqCtx)
	if err != nil {
		return nil, fmt.Errorf("dial trustd %d:%d: %w", c.cid, c.port, err)
	}
	defer conn.Close()

	req := &trustdv1.PingRequest{}
	resp := &trustdv1.PingResponse{}
	if err := conn.Invoke(reqCtx, methodPing, req, resp); err != nil {
		return nil, fmt.Errorf("ping trustd: %w", err)
	}

	return &PingResponse{
		Version:           resp.GetVersion(),
		UptimeSeconds:     resp.GetUptimeSeconds(),
		ContainersTracked: resp.GetContainersTracked(),
	}, nil
}

// ListContainers returns all tracked containers inside the CVM.
func (c *Client) ListContainers(ctx context.Context) ([]ContainerState, error) {
	reqCtx, cancel := requestContext(ctx)
	defer cancel()

	conn, err := c.dialContext(reqCtx)
	if err != nil {
		return nil, fmt.Errorf("dial trustd %d:%d: %w", c.cid, c.port, err)
	}
	defer conn.Close()

	req := &trustdv1.ListContainersRequest{}
	resp := &trustdv1.ListContainersResponse{}
	if err := conn.Invoke(reqCtx, methodListContainers, req, resp); err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}

	containers := make([]ContainerState, 0, len(resp.GetContainers()))
	for _, container := range resp.GetContainers() {
		containers = append(containers, ContainerState{
			CgroupPath:          container.GetCgroupPath(),
			RTMR3:               container.GetRtmr3(),
			InitialRTMR3:        container.GetInitialRtmr3(),
			MeasurementCount:    container.GetMeasurementCount(),
			LastHeartbeat:       container.GetLastHeartbeat(),
			HeartbeatCount:      container.GetHeartbeatCount(),
			HeartbeatMonitoring: container.GetHeartbeatMonitoring(),
		})
	}

	return containers, nil
}

// GetContainerState fetches one container state by cgroup path.
func (c *Client) GetContainerState(ctx context.Context, cgroupPath string) (*ContainerState, error) {
	reqCtx, cancel := requestContext(ctx)
	defer cancel()

	conn, err := c.dialContext(reqCtx)
	if err != nil {
		return nil, fmt.Errorf("dial trustd %d:%d: %w", c.cid, c.port, err)
	}
	defer conn.Close()

	req := &trustdv1.GetContainerStateRequest{CgroupPath: cgroupPath}
	resp := &trustdv1.ContainerState{}
	if err := conn.Invoke(reqCtx, methodGetContainerState, req, resp); err != nil {
		return nil, fmt.Errorf("get container state: %w", err)
	}

	return &ContainerState{
		CgroupPath:          resp.GetCgroupPath(),
		RTMR3:               resp.GetRtmr3(),
		InitialRTMR3:        resp.GetInitialRtmr3(),
		MeasurementCount:    resp.GetMeasurementCount(),
		LastHeartbeat:       resp.GetLastHeartbeat(),
		HeartbeatCount:      resp.GetHeartbeatCount(),
		HeartbeatMonitoring: resp.GetHeartbeatMonitoring(),
	}, nil
}

// RestartContainer requests in-guest remediation by restarting processes in a container cgroup.
func (c *Client) RestartContainer(ctx context.Context, cgroupPath string) (*ContainerState, error) {
	if cgroupPath == "" {
		return nil, fmt.Errorf("cgroup path is required")
	}

	reqCtx, cancel := requestContext(ctx)
	defer cancel()

	conn, err := c.dialContext(reqCtx)
	if err != nil {
		return nil, fmt.Errorf("dial trustd %d:%d: %w", c.cid, c.port, err)
	}
	defer conn.Close()

	req := &trustdv1.GetContainerStateRequest{CgroupPath: cgroupPath}
	resp := &trustdv1.ContainerState{}
	if err := conn.Invoke(reqCtx, methodRestartContainer, req, resp); err != nil {
		return nil, fmt.Errorf("restart container: %w", err)
	}

	return &ContainerState{
		CgroupPath:          resp.GetCgroupPath(),
		RTMR3:               resp.GetRtmr3(),
		InitialRTMR3:        resp.GetInitialRtmr3(),
		MeasurementCount:    resp.GetMeasurementCount(),
		LastHeartbeat:       resp.GetLastHeartbeat(),
		HeartbeatCount:      resp.GetHeartbeatCount(),
		HeartbeatMonitoring: resp.GetHeartbeatMonitoring(),
	}, nil
}

// StartHeartbeatMonitor enables heartbeat timeout monitoring for a container.
func (c *Client) StartHeartbeatMonitor(ctx context.Context, cgroupPath string, timeoutSeconds uint32) error {
	if cgroupPath == "" {
		return fmt.Errorf("cgroup path is required")
	}

	reqCtx, cancel := requestContext(ctx)
	defer cancel()

	conn, err := c.dialContext(reqCtx)
	if err != nil {
		return fmt.Errorf("dial trustd %d:%d: %w", c.cid, c.port, err)
	}
	defer conn.Close()

	req := &trustdv1.HeartbeatMonitorRequest{
		CgroupPath:     cgroupPath,
		TimeoutSeconds: timeoutSeconds,
	}
	resp := &trustdv1.HeartbeatMonitorResponse{}
	if err := conn.Invoke(reqCtx, methodStartHeartbeat, req, resp); err != nil {
		return fmt.Errorf("start heartbeat monitor: %w", err)
	}
	return nil
}

// StopHeartbeatMonitor disables heartbeat timeout monitoring for a container.
func (c *Client) StopHeartbeatMonitor(ctx context.Context, cgroupPath string) error {
	if cgroupPath == "" {
		return fmt.Errorf("cgroup path is required")
	}

	reqCtx, cancel := requestContext(ctx)
	defer cancel()

	conn, err := c.dialContext(reqCtx)
	if err != nil {
		return fmt.Errorf("dial trustd %d:%d: %w", c.cid, c.port, err)
	}
	defer conn.Close()

	req := &trustdv1.HeartbeatMonitorStopRequest{CgroupPath: cgroupPath}
	resp := &trustdv1.HeartbeatMonitorStopResponse{}
	if err := conn.Invoke(reqCtx, methodStopHeartbeat, req, resp); err != nil {
		return fmt.Errorf("stop heartbeat monitor: %w", err)
	}
	return nil
}

// ReportHeartbeat reports one liveness heartbeat for a container.
func (c *Client) ReportHeartbeat(ctx context.Context, cgroupPath string) error {
	if cgroupPath == "" {
		return fmt.Errorf("cgroup path is required")
	}

	reqCtx, cancel := requestContext(ctx)
	defer cancel()

	conn, err := c.dialContext(reqCtx)
	if err != nil {
		return fmt.Errorf("dial trustd %d:%d: %w", c.cid, c.port, err)
	}
	defer conn.Close()

	req := &trustdv1.HeartbeatReportRequest{CgroupPath: cgroupPath}
	resp := &trustdv1.HeartbeatReportResponse{}
	if err := conn.Invoke(reqCtx, methodReportHeartbeat, req, resp); err != nil {
		return fmt.Errorf("report heartbeat: %w", err)
	}
	return nil
}

// AttestContainer performs attestation of a specific container.
func (c *Client) AttestContainer(ctx context.Context, req *AttestContainerRequest) (*AttestContainerResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("attest request is nil")
	}
	if req.CgroupPath == "" {
		return nil, fmt.Errorf("cgroup path is required")
	}
	if req.NonceHex == "" {
		nonceHex, err := newNonceHex()
		if err != nil {
			return nil, fmt.Errorf("generate nonce: %w", err)
		}
		req.NonceHex = nonceHex
	}

	reqCtx, cancel := requestContext(ctx)
	defer cancel()

	conn, err := c.dialContext(reqCtx)
	if err != nil {
		return nil, fmt.Errorf("dial trustd %d:%d: %w", c.cid, c.port, err)
	}
	defer conn.Close()

	msg := &trustdv1.AttestContainerRequest{
		CgroupPath:     req.CgroupPath,
		NonceHex:       req.NonceHex,
		IncludeTdQuote: req.IncludeTDQuote,
	}
	resp := &trustdv1.AttestContainerResponse{}
	if err := conn.Invoke(reqCtx, methodAttestContainer, msg, resp); err != nil {
		return nil, fmt.Errorf("attest container: %w", err)
	}

	measurements := make([]ContainerMeasurement, 0, len(resp.GetMeasurements()))
	for _, measurement := range resp.GetMeasurements() {
		measurements = append(measurements, ContainerMeasurement{
			Digest: measurement.GetDigest(),
			File:   measurement.GetFile(),
		})
	}

	encodedQuote := ""
	if quote := resp.GetTdQuote(); len(quote) > 0 {
		encodedQuote = base64.StdEncoding.EncodeToString(quote)
	}

	return &AttestContainerResponse{
		CgroupPath:       resp.GetCgroupPath(),
		RTMR3:            resp.GetRtmr3(),
		InitialRTMR3:     resp.GetInitialRtmr3(),
		MeasurementCount: resp.GetMeasurementCount(),
		Measurements:     measurements,
		ReportData:       resp.GetReportData(),
		Nonce:            resp.GetNonce(),
		TDQuote:          encodedQuote,
		Timestamp:        resp.GetTimestamp(),
	}, nil
}

// GetTDQuote requests a TDX TD Quote for the given report data.
func (c *Client) GetTDQuote(ctx context.Context, reportData []byte) ([]byte, error) {
	reqCtx, cancel := requestContext(ctx)
	defer cancel()

	conn, err := c.dialContext(reqCtx)
	if err != nil {
		return nil, fmt.Errorf("dial trustd %d:%d: %w", c.cid, c.port, err)
	}
	defer conn.Close()

	req := &trustdv1.GetTDQuoteRequest{ReportData: reportData}
	resp := &trustdv1.GetTDQuoteResponse{}
	if err := conn.Invoke(reqCtx, methodGetTDQuote, req, resp); err != nil {
		return nil, fmt.Errorf("get TD quote: %w", err)
	}

	return resp.GetTdQuote(), nil
}

// WatchContainerEvents streams events from trustd and invokes handler for each event.
func (c *Client) WatchContainerEvents(ctx context.Context, handler func(ContainerEvent) error) error {
	if handler == nil {
		return fmt.Errorf("event handler is nil")
	}

	conn, err := c.dialContext(ctx)
	if err != nil {
		return fmt.Errorf("dial trustd %d:%d: %w", c.cid, c.port, err)
	}
	defer conn.Close()

	streamDesc := &grpc.StreamDesc{ServerStreams: true}
	stream, err := conn.NewStream(ctx, streamDesc, methodWatchEvents)
	if err != nil {
		return fmt.Errorf("open watch stream: %w", err)
	}

	watchReq := &trustdv1.WatchEventsRequest{}
	if err := stream.SendMsg(watchReq); err != nil {
		return fmt.Errorf("send watch request: %w", err)
	}
	if err := stream.CloseSend(); err != nil {
		return fmt.Errorf("close watch request stream: %w", err)
	}

	for {
		msg := &trustdv1.ContainerEvent{}
		if err := stream.RecvMsg(msg); err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("receive watch event: %w", err)
		}

		event := ContainerEvent{
			EventType:        ContainerEventType(msg.GetEventType()),
			CgroupPath:       msg.GetCgroupPath(),
			Timestamp:        msg.GetTimestamp(),
			Digest:           msg.GetDigest(),
			Filename:         msg.GetFilename(),
			Detail:           msg.GetDetail(),
			RTMR3:            msg.GetRtmr3(),
			MeasurementCount: msg.GetMeasurementCount(),
		}

		if err := handler(event); err != nil {
			return err
		}
	}
}

// IsReachable performs a quick ping check with a short timeout.
func (c *Client) IsReachable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := c.Ping(ctx)
	if err != nil {
		log.DefaultLogger().V(5).Infof("trustd not reachable at vsock %d:%d: %v", c.cid, c.port, err)
		return false
	}
	return true
}

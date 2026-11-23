package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"
	"time"
)

const (
	engineTimeout       = 15 * time.Millisecond
	maxEngineLineBytes  = 32 << 20
	defaultSocketPath   = "/run/proxygo/engine.sock"
	maxInspectBodyBytes = 1 << 20
)

var ErrEngineUnavailable = errors.New("inspection engine unavailable")

type FailurePolicy string

const (
	FailOpen   FailurePolicy = "FAIL_OPEN"
	FailClosed FailurePolicy = "FAIL_CLOSED"
)

type InspectionRequest struct {
	ID           string            `json:"id"`
	Method       string            `json:"method"`
	Host         string            `json:"host"`
	Path         string            `json:"path,omitempty"`
	Body         string            `json:"body"`
	Headers      map[string]string `json:"headers,omitempty"`
	Direction    string            `json:"direction,omitempty"`
	ConnectionID string            `json:"connection_id,omitempty"`
	ClientID     string            `json:"client_id,omitempty"`
	ContentType  string            `json:"content_type,omitempty"`
}

type Finding struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

type InspectionResponse struct {
	ID               string            `json:"id"`
	Category         string            `json:"category"`
	RiskLevel        string            `json:"risk_level"`
	Findings         []Finding         `json:"findings"`
	SanitizedBody    string            `json:"sanitized_body"`
	SanitizedHeaders map[string]string `json:"sanitized_headers,omitempty"`
}

type udsClient struct {
	socketPath string
	policy     FailurePolicy
	timeout    time.Duration
	logger     *log.Logger
	sequence   atomic.Uint64
}

func newUDSClient(socketPath string, policy FailurePolicy, logger *log.Logger) *udsClient {
	return newUDSClientWithTimeout(socketPath, policy, engineTimeout, logger)
}

func newUDSClientWithTimeout(socketPath string, policy FailurePolicy, timeout time.Duration, logger *log.Logger) *udsClient {
	if logger == nil {
		logger = log.Default()
	}
	return &udsClient{socketPath: socketPath, policy: policy, timeout: timeout, logger: logger}
}

// Inspect sends one NDJSON request over a dedicated Unix socket connection.
// A fresh connection avoids sharing framed request/response streams across callers.
func (c *udsClient) Inspect(ctx context.Context, request InspectionRequest) (*InspectionResponse, error) {
	if len(request.Body) > maxInspectBodyBytes {
		return nil, fmt.Errorf("inspection body exceeds %d-byte engine limit", maxInspectBodyBytes)
	}

	response, err := c.roundTrip(ctx, request)
	if err != nil {
		if c.policy == FailOpen {
			c.logger.Printf("SYSTEM ALERT: DLP inspection bypassed for request %s: %v", request.ID, err)
			return nil, nil
		}
		return nil, fmt.Errorf("%w: %v", ErrEngineUnavailable, err)
	}
	return response, nil
}

func (c *udsClient) roundTrip(parent context.Context, request InspectionRequest) (*InspectionResponse, error) {
	ctx, cancel := context.WithTimeout(parent, c.timeout)
	defer cancel()

	dialer := net.Dialer{Timeout: c.timeout}
	conn, err := dialer.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}

	line, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	line = append(line, '\n')
	if err := writeAll(conn, line); err != nil {
		return nil, err
	}

	responseLine, err := readNDJSONLine(bufio.NewReader(conn), maxEngineLineBytes)
	if err != nil {
		return nil, err
	}
	var response InspectionResponse
	if err := json.Unmarshal(responseLine, &response); err != nil {
		return nil, fmt.Errorf("decode engine response: %w", err)
	}
	if response.ID != request.ID {
		return nil, fmt.Errorf("engine response ID mismatch")
	}
	return &response, nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func readNDJSONLine(reader *bufio.Reader, maxBytes int) ([]byte, error) {
	var line []byte
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(line)+len(fragment) > maxBytes {
			return nil, fmt.Errorf("engine response exceeds %d bytes", maxBytes)
		}
		line = append(line, fragment...)
		if err == nil {
			return bytes.TrimSuffix(line, []byte{'\n'}), nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			if errors.Is(err, io.EOF) && len(line) > 0 {
				return line, nil
			}
			return nil, err
		}
	}
}

// Package winrmclient provides a thin WinRM wrapper for executing PowerShell
// commands on remote Windows hosts via WinRM (PowerShell Remoting).
package winrmclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"time"
	"unicode/utf16"

	"github.com/masterzen/winrm"
)

// Executor is the interface consumed by epamatrix for executing remote PowerShell.
type Executor interface {
	RunPowerShell(ctx context.Context, script string) (stdout, stderr string, err error)
}

// Config holds WinRM connection parameters.
type Config struct {
	Host      string
	Port      int
	Username  string // DOMAIN\user or user@domain
	Password  string
	UseHTTPS  bool
	UseBasic  bool // Use Basic auth instead of NTLM
	Timeout   time.Duration
}

// Client wraps a WinRM connection to a remote Windows host.
type Client struct {
	client *winrm.Client
}

// New creates a WinRM client. The connection is established lazily on first command.
func New(cfg Config) (*Client, error) {
	port := cfg.Port
	if port == 0 {
		if cfg.UseHTTPS {
			port = 5986
		} else {
			port = 5985
		}
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 90 * time.Second
	}

	endpoint := winrm.NewEndpoint(cfg.Host, port, cfg.UseHTTPS, true, nil, nil, nil, timeout)

	var wc *winrm.Client
	var err error

	if cfg.UseBasic {
		wc, err = winrm.NewClient(endpoint, cfg.Username, cfg.Password)
	} else {
		params := winrm.DefaultParameters
		params.TransportDecorator = func() winrm.Transporter {
			return &winrm.ClientNTLM{}
		}
		wc, err = winrm.NewClientWithParameters(endpoint, cfg.Username, cfg.Password, params)
	}
	if err != nil {
		return nil, fmt.Errorf("create WinRM client: %w", err)
	}

	return &Client{client: wc}, nil
}

// RunPowerShell executes a PowerShell script on the remote host.
// Returns stdout, stderr, and any error (including non-zero exit codes).
func (c *Client) RunPowerShell(ctx context.Context, script string) (string, string, error) {
	encoded := encodePowerShellCommand(script)
	cmd := fmt.Sprintf("powershell.exe -NoProfile -NonInteractive -EncodedCommand %s", encoded)

	var stdout, stderr bytes.Buffer
	exitCode, err := c.client.RunWithContext(ctx, cmd, &stdout, &stderr)
	if err != nil {
		return stdout.String(), stderr.String(), fmt.Errorf("WinRM command failed: %w", err)
	}
	if exitCode != 0 {
		return stdout.String(), stderr.String(), fmt.Errorf("PowerShell exited with code %d: %s", exitCode, stderr.String())
	}
	return stdout.String(), stderr.String(), nil
}

// encodePowerShellCommand encodes a script as base64 UTF-16LE for -EncodedCommand.
func encodePowerShellCommand(script string) string {
	// Convert to UTF-16LE
	runes := utf16.Encode([]rune(script))
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		b[i*2] = byte(r)
		b[i*2+1] = byte(r >> 8)
	}
	return base64.StdEncoding.EncodeToString(b)
}

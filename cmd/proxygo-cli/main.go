package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	engineService = "proxygo-engine.service"
	proxyService  = "proxygo-proxy.service"
	defaultSocket = "/run/proxygo/engine.sock"
	defaultCADir  = "/var/lib/proxygo/ca"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "proxygo-cli:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	switch args[0] {
	case "start":
		if len(args) != 1 {
			return usageError()
		}
		return runSystemctl(ctx, stdout, stderr, "start", engineService, proxyService)
	case "stop":
		if len(args) != 1 {
			return usageError()
		}
		return runSystemctl(ctx, stdout, stderr, "stop", proxyService, engineService)
	case "restart":
		if len(args) == 1 {
			return runSystemctl(ctx, stdout, stderr, "restart", engineService, proxyService)
		}
		if len(args) != 2 {
			return usageError()
		}
		switch args[1] {
		case "engine":
			return runSystemctl(ctx, stdout, stderr, "restart", engineService)
		case "proxy":
			return runSystemctl(ctx, stdout, stderr, "restart", proxyService)
		default:
			return usageError()
		}
	case "status":
		if len(args) != 1 {
			return usageError()
		}
		return printStatus(ctx, stdout)
	case "ca-export":
		if len(args) > 2 {
			return usageError()
		}
		return exportCA(args[1:], stdout)
	case "tui":
		if len(args) != 1 {
			return usageError()
		}
		return runTUI()
	default:
		return usageError()
	}
}

func runSystemctl(ctx context.Context, stdout, stderr io.Writer, args ...string) error {
	command := exec.CommandContext(ctx, "systemctl", args...)
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("systemctl %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

func printStatus(ctx context.Context, stdout io.Writer) error {
	services := []string{engineService, proxyService}
	allActive := true
	for _, service := range services {
		command := exec.CommandContext(ctx, "systemctl", "is-active", service)
		output, err := command.Output()
		state := strings.TrimSpace(string(output))
		if state == "" {
			state = "inactive"
		}
		if err != nil {
			allActive = false
		}
		if _, writeErr := fmt.Fprintf(stdout, "%-30s %s\n", service, state); writeErr != nil {
			return writeErr
		}
	}

	socketPath := os.Getenv("PROXYGO_SOCK_PATH")
	if socketPath == "" {
		socketPath = defaultSocket
	}
	socketState := "missing"
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket != 0 {
			connection, dialErr := net.DialTimeout("unix", socketPath, 200*time.Millisecond)
			if dialErr != nil {
				socketState = "unreachable: " + dialErr.Error()
			} else {
				_ = connection.Close()
				socketState = fmt.Sprintf("ready (%04o)", info.Mode().Perm())
			}
		} else {
			socketState = "path exists but is not a socket"
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		socketState = "unavailable: " + err.Error()
	}
	if _, err := fmt.Fprintf(stdout, "%-30s %s\n", filepath.Base(socketPath), socketState); err != nil {
		return err
	}
	if !allActive || !strings.HasPrefix(socketState, "ready") {
		return errors.New("one or more ProxyGo components are not ready")
	}
	return nil
}

func exportCA(args []string, stdout io.Writer) error {
	dir := strings.TrimSpace(os.Getenv("PROXYGO_CA_DIR"))
	if dir == "" {
		dir = defaultCADir
	}
	data, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return fmt.Errorf("read CA certificate: %w", err)
	}
	if len(args) == 0 {
		_, err = stdout.Write(data)
		return err
	}
	if err := os.WriteFile(args[0], data, 0o644); err != nil {
		return fmt.Errorf("write CA certificate: %w", err)
	}
	return os.Chmod(args[0], 0o644)
}

func usageError() error {
	return errors.New("usage: proxygo-cli start | stop | restart [engine|proxy] | status | ca-export [ruta] | tui")
}

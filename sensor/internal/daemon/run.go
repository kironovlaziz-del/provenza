// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/kironovlaziz-del/provenza/sensor/internal/cgroups"
	"github.com/kironovlaziz-del/provenza/sensor/internal/config"
	"golang.org/x/sys/unix"
)

// runRequest is what `provenza-sensor run --agent N -- cmd` asks the daemon.
type runRequest struct {
	AgentID int64 `json:"agent_id"`
}

type runResponse struct {
	Cgroup string `json:"cgroup,omitempty"`
	Error  string `json:"error,omitempty"`
}

// RunCommand talks to the running daemon over the unix socket, gets a
// dedicated cgroup, and execs the command inside it.
func RunCommand(ctx context.Context, cfgPath string, agentID int64, argv []string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	conn, err := dialRun(cfg.RunSocket, cfg.RunGroup)
	if err != nil {
		return fmt.Errorf("connect to daemon: %w", err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(runRequest{AgentID: agentID}); err != nil {
		return err
	}
	var resp runResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	if resp.Cgroup == "" {
		return errors.New("daemon returned no cgroup")
	}

	// Enter a fresh cgroup namespace so the child's /sys/fs/cgroup shows
	// its own cgroup at the root, then move ourselves into the run cgroup.
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWCGROUP,
	}
	cmd.Dir = "/"
	if err := cmd.Start(); err != nil {
		return err
	}
	if err := cgroups.Move(cfg.CgroupRoot, resp.Cgroup, cmd.Process.Pid); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("move into %s: %w", resp.Cgroup, err)
	}
	return cmd.Wait()
}

// runServer listens on cfg.RunSocket and answers run requests. Enabled by
// the daemon at startup when cfg.RunSocket is set.
func (d *Daemon) startRunServer() error {
	if d.cfg.RunSocket == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(d.cfg.RunSocket), 0o755); err != nil {
		return err
	}
	_ = os.Remove(d.cfg.RunSocket)
	l, err := net.Listen("unix", d.cfg.RunSocket)
	if err != nil {
		return err
	}
	if d.cfg.RunGroup != "" {
		if err := chownToGroup(d.cfg.RunSocket, d.cfg.RunGroup); err != nil {
			slog.Warn("chown run socket", "err", err)
		}
		_ = os.Chmod(d.cfg.RunSocket, 0o660)
	}
	d.run = &runServer{l: l, d: d}
	go d.run.serve()
	return nil
}

// dialRun connects to the run socket. If a group is configured, the caller
// must be a member of it (the file mode 0660 enforces that).
func dialRun(path, group string) (net.Conn, error) {
	return net.Dial("unix", path)
}

// chownToGroup changes the socket's group to g (name or gid).
func chownToGroup(path, g string) error {
	var gid int
	if n, err := strconv.Atoi(g); err == nil {
		gid = n
	} else {
		grp, err := user.LookupGroup(g)
		if err != nil {
			return err
		}
		n, err := strconv.Atoi(grp.Gid)
		if err != nil {
			return err
		}
		gid = n
	}
	return os.Chown(path, -1, gid)
}

type runServer struct {
	l net.Listener
	d *Daemon
}

func (s *runServer) close() {
	_ = s.l.Close()
	_ = os.Remove(s.d.cfg.RunSocket)
}

func (s *runServer) serve() {
	for {
		conn, err := s.l.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *runServer) handle(conn net.Conn) {
	defer conn.Close()

	// The socket mode (0660 + group) is the first line of defence; the
	// second is SO_PEERCRED, so we know who is asking.
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return
	}
	var cred *unix.Ucred
	_ = raw.Control(func(fd uintptr) {
		cred, _ = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if cred == nil {
		_ = json.NewEncoder(conn).Encode(runResponse{Error: "no peer credentials"})
		return
	}

	var req runRequest
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&req); err != nil {
		return
	}
	if req.AgentID <= 0 {
		_ = json.NewEncoder(conn).Encode(runResponse{Error: "invalid agent id"})
		return
	}
	if _, ok := s.d.workloadForAgent(req.AgentID); !ok {
		_ = json.NewEncoder(conn).Encode(runResponse{Error: fmt.Sprintf("agent %d is not in the current policy", req.AgentID)})
		return
	}

	rel, err := cgroups.NewRun(s.d.cfg.CgroupRoot, "", req.AgentID)
	if err != nil {
		_ = json.NewEncoder(conn).Encode(runResponse{Error: err.Error()})
		return
	}
	_ = json.NewEncoder(conn).Encode(runResponse{Cgroup: rel})
}

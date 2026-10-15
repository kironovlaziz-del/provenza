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
	"strings"
	"syscall"

	"github.com/kironovlaziz-del/provenza/sensor/internal/bpfobj"
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

// RunCommand asks the running daemon for a cgroup and runs the command in it.
//
// The daemon governs the cgroup in the kernel and moves THIS process into it
// before it answers; the command is then exec'd in place. exec keeps the
// cgroup, so there is no moment at which the command or anything it starts
// runs ungoverned, and the caller needs no write access to cgroup.procs.
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

	// This process is already in the governed cgroup (the daemon moved it
	// before answering); exec keeps it there.
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}
	_ = conn.Close()
	// A fresh cgroup namespace, so the command sees its own cgroup as the
	// root. Needs CAP_SYS_ADMIN; without it the command simply sees the
	// full path - containment does not depend on it.
	_ = unix.Unshare(unix.CLONE_NEWCGROUP)
	if err := os.Chdir("/"); err != nil {
		return err
	}
	_ = ctx
	return syscall.Exec(path, argv, os.Environ())
}

// startRunServer listens on cfg.RunSocket and answers run requests. Started
// by the daemon at startup when cfg.RunSocket is set.
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

// dialRun connects to the run socket. The socket mode (0660 + group) is the
// first line of defence; SO_PEERCRED on the server side is the second.
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
	wid, ok := s.d.workloadForAgent(req.AgentID)
	if !ok {
		_ = json.NewEncoder(conn).Encode(runResponse{Error: fmt.Sprintf("agent %d is not in the current policy", req.AgentID)})
		return
	}

	rel, err := cgroups.NewRun(s.d.cfg.CgroupRoot, "", req.AgentID)
	if err != nil {
		_ = json.NewEncoder(conn).Encode(runResponse{Error: err.Error()})
		return
	}
	fail := func(what string, err error) {
		_ = cgroups.Remove(s.d.cfg.CgroupRoot, rel)
		_ = json.NewEncoder(conn).Encode(runResponse{Error: fmt.Sprintf("%s: %v", what, err)})
	}
	id, err := cgroups.ID(filepath.Join(s.d.cfg.CgroupRoot, rel))
	if err != nil {
		fail("cgroup id", err)
		return
	}
	// Governed in the kernel before anything runs in it - not left to the
	// asynchronous cgroup_mkdir event.
	if err := s.d.kernel.SetCgroup(id, bpfobj.CgEntry{Wid: wid, Kind: bpfobj.CgGoverned}); err != nil {
		fail("govern cgroup", err)
		return
	}
	if err := s.d.kernel.BumpEpoch(); err != nil {
		slog.Warn("bump epoch", "err", err)
	}
	// Move the asking process itself; it execs the command afterwards. Check
	// first that the pid is still our client of the same user (a client that
	// exited could have its pid taken by someone else's process).
	if err := peerIsClient(int(cred.Pid), cred.Uid); err != nil {
		_ = s.d.kernel.DeleteCgroup(id)
		fail("peer check", err)
		return
	}
	if err := cgroups.Move(s.d.cfg.CgroupRoot, rel, int(cred.Pid)); err != nil {
		_ = s.d.kernel.DeleteCgroup(id)
		fail("move into cgroup", err)
		return
	}
	slog.Info("run", "agent", req.AgentID, "uid", cred.Uid, "pid", cred.Pid, "cgroup", rel)
	_ = json.NewEncoder(conn).Encode(runResponse{Cgroup: rel})
}

// peerIsClient checks that pid is still a provenza-sensor process of user uid.
func peerIsClient(pid int, uid uint32) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	self, _ = filepath.EvalSymlinks(self)
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return fmt.Errorf("process %d is gone", pid)
	}
	if strings.TrimSuffix(exe, " (deleted)") != self {
		return fmt.Errorf("process %d is not provenza-sensor", pid)
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(status), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "Uid:" {
			if f[1] != strconv.FormatUint(uint64(uid), 10) {
				return fmt.Errorf("process %d belongs to another user", pid)
			}
			return nil
		}
	}
	return fmt.Errorf("process %d: no Uid line", pid)
}

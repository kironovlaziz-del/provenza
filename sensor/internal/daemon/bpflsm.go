// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

// Turning BPF LSM on for the next boot: the sensor's lsm/socket_create hook
// (socket families other than IP) runs only when the kernel was booted with
// "bpf" among its LSMs. Many distributions leave it out.
//
// The change is one GRUB drop-in that adds lsm=<the LSMs active now>,bpf to
// the kernel's boot line, then update-grub. Nothing reboots the host: an
// administrator does that when it suits them.
//
// Privilege separation: the daemon's own unit cannot write /etc/default or
// /boot (ProtectSystem=strict), and is not loosened for this. The work is
// done by `provenza-sensor prepare-bpf-lsm` in its own oneshot unit,
// provenzasensor-bpf-lsm.service, which may write only those places, and
// has no network. The daemon only starts that unit - a fixed action, no
// arguments - and reads the result the unit leaves in /run/provenza-sensor.
//
// It runs as the command "prepare-bpf-lsm" (an administrator signs it with a
// passkey), or by hand: sudo provenza-sensor prepare-bpf-lsm.

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/kironovlaziz-del/provenza/sensor/internal/client"
	"github.com/kironovlaziz-del/provenza/sensor/internal/kern"
)

const (
	// BPFLSMDropIn is the only file prepare-bpf-lsm writes (besides what
	// update-grub regenerates). Removing it and running update-grub undoes it.
	BPFLSMDropIn = "/etc/default/grub.d/99-provenza-bpf-lsm.cfg"
	// BPFLSMUnit runs prepare-bpf-lsm with its own, narrower sandbox.
	BPFLSMUnit = "provenzasensor-bpf-lsm.service"
	// BPFLSMResultFile: what the unit's run came to (BPFLSMResult as JSON).
	BPFLSMResultFile = "/run/provenza-sensor/bpf-lsm.json"

	// bpfLSMPrepared: the heartbeat's state once the drop-in is in place but
	// the host has not rebooted yet.
	bpfLSMPrepared = "prepared"
	// noteLSMPrepared replaces kern.NoteLSMInactive once prepared.
	noteLSMPrepared = "BPF LSM: prepared for the next boot (" + BPFLSMDropIn + "); reboot the host to activate it"

	updateGrubTimeout = 2 * time.Minute
)

// BPFLSMResult is what prepare-bpf-lsm reports (stdout, BPFLSMResultFile,
// and the command's result on the control plane).
type BPFLSMResult struct {
	// "active" (nothing to do), "prepared" (reboot to activate) or "failed"
	Status         string `json:"status"`
	Message        string `json:"message"`
	LSM            string `json:"lsm,omitempty"`  // the lsm= list written
	File           string `json:"file,omitempty"` // the drop-in
	RebootRequired bool   `json:"reboot_required"`
}

// bpfLSMHost: the files and the program prepare-bpf-lsm uses (tests use their own).
type bpfLSMHost struct {
	lsmFile     string // the kernel's active LSMs
	cmdline     string // the running kernel's boot line
	grubDefault string // /etc/default/grub
	grubDir     string // /etc/default/grub.d
	dropIn      string
	// updateGrub regenerates the boot menu; nil: update-grub is not installed
	updateGrub func(ctx context.Context) ([]byte, error)
}

func realBPFLSMHost() bpfLSMHost {
	h := bpfLSMHost{
		lsmFile:     "/sys/kernel/security/lsm",
		cmdline:     "/proc/cmdline",
		grubDefault: "/etc/default/grub",
		grubDir:     filepath.Dir(BPFLSMDropIn),
		dropIn:      BPFLSMDropIn,
	}
	for _, p := range []string{"/usr/sbin/update-grub", "/sbin/update-grub"} {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			path := p
			h.updateGrub = func(ctx context.Context) ([]byte, error) {
				ctx, cancel := context.WithTimeout(ctx, updateGrubTimeout)
				defer cancel()
				return exec.CommandContext(ctx, path).CombinedOutput()
			}
			break
		}
	}
	return h
}

// an LSM's name as the kernel lists it (and as it goes into the boot line)
var lsmName = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)

// PrepareBPFLSM is the subcommand `provenza-sensor prepare-bpf-lsm`: it
// prints the result as JSON, leaves it in BPFLSMResultFile for the daemon,
// and exits non-zero when it failed.
func PrepareBPFLSM(ctx context.Context) int {
	r := realBPFLSMHost().prepare(ctx)
	out, _ := json.MarshalIndent(r, "", "  ")
	fmt.Println(string(out))
	if err := writeFileAtomic(BPFLSMResultFile, append(out, '\n'), 0o644); err != nil {
		slog.Warn("prepare-bpf-lsm: could not leave the result for the daemon", "file", BPFLSMResultFile, "err", err)
	}
	if r.Status == "failed" {
		return 1
	}
	return 0
}

func failed(format string, a ...any) BPFLSMResult {
	return BPFLSMResult{Status: "failed", Message: fmt.Sprintf(format, a...)}
}

// prepare checks the host, writes the drop-in and runs update-grub. It
// changes nothing unless every check passed, and takes the drop-in back
// out if update-grub fails.
func (h bpfLSMHost) prepare(ctx context.Context) BPFLSMResult {
	raw, err := os.ReadFile(h.lsmFile)
	if err != nil {
		return failed("cannot read the kernel's active LSMs (%v): is securityfs mounted?", err)
	}
	var names []string
	for _, n := range strings.Split(strings.TrimSpace(string(raw)), ",") {
		if n == "" {
			continue
		}
		if !lsmName.MatchString(n) {
			return failed("unexpected LSM name %q in %s: nothing changed", n, h.lsmFile)
		}
		if n == "bpf" {
			return BPFLSMResult{Status: "active", Message: "BPF LSM is already active: nothing to do"}
		}
		names = append(names, n)
	}
	if len(names) == 0 {
		return failed("%s lists no LSMs: nothing changed", h.lsmFile)
	}
	list := strings.Join(append(names, "bpf"), ",")
	manual := fmt.Sprintf("add lsm=%s to the kernel's boot parameters by hand, then reboot", list)

	if _, err := os.Stat(h.dropIn); err == nil {
		return BPFLSMResult{Status: bpfLSMPrepared, File: h.dropIn, RebootRequired: true,
			Message: "already prepared (" + h.dropIn + "): reboot the host to activate BPF LSM"}
	}

	// Someone chose the LSMs on this host already: their choice is not ours to rewrite.
	if cl, err := os.ReadFile(h.cmdline); err == nil {
		for _, f := range strings.Fields(string(cl)) {
			if strings.HasPrefix(f, "lsm=") || strings.HasPrefix(f, "security=") {
				return failed("the kernel was booted with %s: this host chooses its LSMs itself; "+
					"add bpf to that list by hand, then reboot (nothing changed)", f)
			}
		}
	}
	if _, err := os.Stat(h.grubDefault); err != nil {
		return failed("%s not found: this host does not boot with GRUB as Debian and Ubuntu set it up; %s "+
			"(nothing changed)", h.grubDefault, manual)
	}
	files := []string{h.grubDefault}
	if more, err := filepath.Glob(filepath.Join(h.grubDir, "*.cfg")); err == nil {
		files = append(files, more...)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return failed("cannot read %s (%v): nothing changed", f, err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") {
				continue
			}
			if strings.Contains(line, "lsm=") || strings.Contains(line, "security=") {
				return failed("%s already sets lsm= or security=: add bpf to that list by hand, run update-grub, "+
					"then reboot (nothing changed)", f)
			}
		}
	}
	if h.updateGrub == nil {
		return failed("update-grub not found (on Fedora or RHEL: grubby --update-kernel=ALL --args=\"lsm=%s\"); "+
			"%s (nothing changed)", list, manual)
	}

	body := "# Written by provenza-sensor prepare-bpf-lsm: turns on BPF LSM (the Provenza\n" +
		"# sensor's hook for socket families other than IP) at the next boot. To undo:\n" +
		"# remove this file, run update-grub, reboot.\n" +
		"GRUB_CMDLINE_LINUX=\"$GRUB_CMDLINE_LINUX lsm=" + list + "\"\n"
	if err := os.MkdirAll(h.grubDir, 0o755); err != nil {
		return failed("cannot create %s (%v): nothing changed", h.grubDir, err)
	}
	if err := writeFileAtomic(h.dropIn, []byte(body), 0o644); err != nil {
		return failed("cannot write %s (%v): nothing changed", h.dropIn, err)
	}
	if out, err := h.updateGrub(ctx); err != nil {
		rmErr := os.Remove(h.dropIn)
		msg := fmt.Sprintf("update-grub failed (%v): %s", err, lastLines(out, 5))
		if rmErr != nil {
			return failed("%s; and %s could not be removed (%v): remove it by hand and run update-grub", msg, h.dropIn, rmErr)
		}
		return failed("%s; %s was removed again (nothing changed)", msg, h.dropIn)
	}
	return BPFLSMResult{Status: bpfLSMPrepared, LSM: list, File: h.dropIn, RebootRequired: true,
		Message: "prepared: reboot the host to activate BPF LSM (lsm=" + list + ")"}
}

func lastLines(b []byte, n int) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	s := strings.Join(lines, " | ")
	if len(s) > 400 {
		s = s[len(s)-400:]
	}
	return s
}

// writeFileAtomic writes a file next to its place, then renames it there.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// ---------------------------------------------------------------- the daemon's side

// bpfLSMState: the heartbeat's bpf_lsm - the kernel's state, or "prepared"
// while the drop-in waits for a reboot.
func (d *Daemon) bpfLSMState() string {
	if d.kernel == nil {
		return ""
	}
	st := d.kernel.LSMState
	if st == kern.LSMInactive && d.bpfLSMDropInExists() {
		return bpfLSMPrepared
	}
	return st
}

func (d *Daemon) bpfLSMDropInExists() bool {
	p := BPFLSMDropIn
	if d.bpfLSMDropIn != "" {
		p = d.bpfLSMDropIn
	}
	_, err := os.Stat(p)
	return err == nil
}

// kernelNotes: the kernel's notes, with the inactive-LSM note replaced once prepared.
func (d *Daemon) kernelNotes() []string {
	if d.kernel == nil {
		return nil
	}
	prepared := d.bpfLSMState() == bpfLSMPrepared
	out := make([]string, 0, len(d.kernel.Notes))
	for _, n := range d.kernel.Notes {
		if prepared && n == kern.NoteLSMInactive {
			n = noteLSMPrepared
		}
		out = append(out, n)
	}
	return out
}

func (d *Daemon) systemctl(ctx context.Context, args ...string) ([]byte, error) {
	if d.runSystemctl != nil {
		return d.runSystemctl(ctx, args...)
	}
	return exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
}

// execPrepareBPFLSM starts the oneshot unit and acks with what it reports.
// The unit can take a minute (update-grub), so this runs beside the
// heartbeat rather than holding it up.
func (d *Daemon) execPrepareBPFLSM(ctx context.Context, c client.Command) error {
	fail := func(why string) error {
		_ = d.client.AckCommand(ctx, c.ID, "failed", nil, why)
		return errors.New(why)
	}
	switch d.bpfLSMState() {
	case kern.LSMActive:
		r := BPFLSMResult{Status: "active", Message: "BPF LSM is already active: nothing to do"}
		return d.client.AckCommand(ctx, c.ID, "done", r, "")
	case kern.LSMInactive, bpfLSMPrepared:
	default:
		return fail("this kernel cannot run the sensor's BPF LSM program (built without CONFIG_BPF_LSM, " +
			"or it could not be attached): the boot line would not help")
	}
	out, err := d.systemctl(ctx, "show", "--property=LoadState", "--value", BPFLSMUnit)
	if err != nil || strings.TrimSpace(string(out)) != "loaded" {
		return fail(BPFLSMUnit + " is not installed on this host: run the sensor's install script again " +
			"(it installs the unit), or on the host: sudo provenza-sensor prepare-bpf-lsm")
	}
	result := BPFLSMResultFile
	if d.bpfLSMResult != "" {
		result = d.bpfLSMResult
	}
	_ = os.Remove(result)
	go func() {
		ctx, cancel := context.WithTimeout(ctx, updateGrubTimeout+time.Minute)
		defer cancel()
		// a oneshot unit: systemctl start returns when it has finished
		out, err := d.systemctl(ctx, "start", BPFLSMUnit)
		var r BPFLSMResult
		raw, rerr := os.ReadFile(result)
		if rerr != nil || json.Unmarshal(bytes.TrimSpace(raw), &r) != nil || r.Status == "" {
			why := "the unit left no result"
			if err != nil {
				why = fmt.Sprintf("%s did not finish (%v): %s", BPFLSMUnit, err, lastLines(out, 3))
			}
			_ = d.client.AckCommand(ctx, c.ID, "failed", nil, why+" (journalctl -u "+BPFLSMUnit+")")
			slog.Warn("prepare-bpf-lsm", "id", c.ID, "err", why)
			return
		}
		if r.Status == "failed" {
			_ = d.client.AckCommand(ctx, c.ID, "failed", r, r.Message)
			slog.Warn("prepare-bpf-lsm", "id", c.ID, "err", r.Message)
			return
		}
		if err := d.client.AckCommand(ctx, c.ID, "done", r, ""); err != nil {
			slog.Warn("ack done", "id", c.ID, "err", err)
		}
		slog.Info("prepare-bpf-lsm", "id", c.ID, "status", r.Status, "lsm", r.LSM)
	}()
	return nil
}

// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza - https://github.com/kironovlaziz-del/provenza

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kironovlaziz-del/provenza/sensor/internal/client"
	"github.com/kironovlaziz-del/provenza/sensor/internal/config"
	"github.com/kironovlaziz-del/provenza/sensor/internal/kern"
)

// a host as Ubuntu leaves it: GRUB, no lsm= anywhere, bpf not among the LSMs
func testBPFLSMHost(t *testing.T) (bpfLSMHost, *int) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	runs := new(int)
	h := bpfLSMHost{
		lsmFile:     write("lsm", "lockdown,capability,landlock,yama,apparmor,ima,evm\n"),
		cmdline:     write("cmdline", "BOOT_IMAGE=/vmlinuz-6.8.0-88-generic root=UUID=0b1c ro console=tty1 console=ttyS0\n"),
		grubDefault: write("default/grub", "GRUB_DEFAULT=0\nGRUB_CMDLINE_LINUX_DEFAULT=\"quiet splash\"\nGRUB_CMDLINE_LINUX=\"\"\n"),
		grubDir:     filepath.Join(dir, "default/grub.d"),
		updateGrub: func(context.Context) ([]byte, error) {
			*runs++
			return []byte("Generating grub configuration file ...\ndone\n"), nil
		},
	}
	write("default/grub.d/50-cloudimg-settings.cfg",
		"# lsm= in a comment does not count\nGRUB_CMDLINE_LINUX_DEFAULT=\"console=tty1 console=ttyS0\"\n")
	h.dropIn = filepath.Join(h.grubDir, "99-provenza-bpf-lsm.cfg")
	return h, runs
}

func TestPrepareBPFLSMWritesTheDropIn(t *testing.T) {
	h, runs := testBPFLSMHost(t)
	r := h.prepare(context.Background())
	if r.Status != "prepared" || !r.RebootRequired || *runs != 1 {
		t.Fatalf("%+v, update-grub ran %d times", r, *runs)
	}
	want := "lockdown,capability,landlock,yama,apparmor,ima,evm,bpf"
	if r.LSM != want {
		t.Fatalf("lsm %q, want %q", r.LSM, want)
	}
	b, err := os.ReadFile(h.dropIn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "\nGRUB_CMDLINE_LINUX=\"$GRUB_CMDLINE_LINUX lsm="+want+"\"\n") {
		t.Fatalf("drop-in:\n%s", b)
	}
	if fi, _ := os.Stat(h.dropIn); fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", fi.Mode())
	}
	// nothing else left in the directory (the temporary file was renamed)
	if ents, _ := os.ReadDir(h.grubDir); len(ents) != 2 {
		t.Fatalf("%d files in grub.d", len(ents))
	}

	// again: already prepared, update-grub not run a second time
	r = h.prepare(context.Background())
	if r.Status != "prepared" || *runs != 1 {
		t.Fatalf("second run: %+v, update-grub ran %d times", r, *runs)
	}
}

func TestPrepareBPFLSMChangesNothingWhenItShouldNot(t *testing.T) {
	cases := map[string]func(t *testing.T, h *bpfLSMHost){
		"already active": func(t *testing.T, h *bpfLSMHost) {
			_ = os.WriteFile(h.lsmFile, []byte("lockdown,capability,yama,apparmor,bpf\n"), 0o644)
		},
		"booted with lsm=": func(t *testing.T, h *bpfLSMHost) {
			_ = os.WriteFile(h.cmdline, []byte("BOOT_IMAGE=/vmlinuz ro lsm=landlock,yama,apparmor\n"), 0o644)
		},
		"booted with security=": func(t *testing.T, h *bpfLSMHost) {
			_ = os.WriteFile(h.cmdline, []byte("BOOT_IMAGE=/vmlinuz ro security=selinux\n"), 0o644)
		},
		"lsm= in /etc/default/grub": func(t *testing.T, h *bpfLSMHost) {
			_ = os.WriteFile(h.grubDefault, []byte("GRUB_CMDLINE_LINUX=\"lsm=yama,apparmor\"\n"), 0o644)
		},
		"lsm= in a grub.d file": func(t *testing.T, h *bpfLSMHost) {
			_ = os.WriteFile(filepath.Join(h.grubDir, "10-mine.cfg"),
				[]byte("GRUB_CMDLINE_LINUX=\"$GRUB_CMDLINE_LINUX lsm=yama\"\n"), 0o644)
		},
		"no GRUB": func(t *testing.T, h *bpfLSMHost) {
			_ = os.Remove(h.grubDefault)
		},
		"no update-grub": func(t *testing.T, h *bpfLSMHost) {
			h.updateGrub = nil
		},
		"an odd LSM name": func(t *testing.T, h *bpfLSMHost) {
			_ = os.WriteFile(h.lsmFile, []byte("lockdown,yama\" init=/bin/sh\n"), 0o644)
		},
		"no securityfs": func(t *testing.T, h *bpfLSMHost) {
			_ = os.Remove(h.lsmFile)
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			h, runs := testBPFLSMHost(t)
			setup(t, &h)
			r := h.prepare(context.Background())
			want := "failed"
			if name == "already active" {
				want = "active"
			}
			if r.Status != want || r.RebootRequired || *runs != 0 {
				t.Fatalf("%+v, update-grub ran %d times", r, *runs)
			}
			if _, err := os.Stat(h.dropIn); !os.IsNotExist(err) {
				t.Fatal("the drop-in was written")
			}
		})
	}
}

func TestPrepareBPFLSMTakesItBackWhenUpdateGrubFails(t *testing.T) {
	h, _ := testBPFLSMHost(t)
	h.updateGrub = func(context.Context) ([]byte, error) {
		return []byte("/usr/sbin/grub-probe: error: failed to get canonical path of `overlay'.\n"), errors.New("exit status 1")
	}
	r := h.prepare(context.Background())
	if r.Status != "failed" || !strings.Contains(r.Message, "grub-probe") || !strings.Contains(r.Message, "removed again") {
		t.Fatalf("%+v", r)
	}
	if _, err := os.Stat(h.dropIn); !os.IsNotExist(err) {
		t.Fatal("the drop-in was left behind")
	}
}

// ---------------------------------------------------------------- the daemon's side

type ackRecorder struct {
	mu   sync.Mutex
	acks []map[string]any
}

func (a *ackRecorder) list() []map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]map[string]any(nil), a.acks...)
}

// wait for an ack with a final status (done or failed)
func (a *ackRecorder) final(t *testing.T) map[string]any {
	t.Helper()
	for i := 0; i < 200; i++ {
		for _, x := range a.list() {
			if x["status"] == "done" || x["status"] == "failed" {
				return x
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no final ack: %v", a.list())
	return nil
}

func bpfLSMDaemon(t *testing.T, state string) (*Daemon, *ackRecorder, *[][]string) {
	t.Helper()
	rec := &ackRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		rec.mu.Lock()
		rec.acks = append(rec.acks, body)
		rec.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	cl, err := client.New(config.Settings{ProvenzaURL: srv.URL, Key: "pvz_sensor_test"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	calls := &[][]string{}
	var mu sync.Mutex
	d := &Daemon{client: cl, kernel: &kern.Kernel{LSMState: state, Notes: []string{kern.NoteLSMInactive}},
		bpfLSMDropIn: filepath.Join(dir, "99-provenza-bpf-lsm.cfg"),
		bpfLSMResult: filepath.Join(dir, "bpf-lsm.json")}
	d.runSystemctl = func(_ context.Context, args ...string) ([]byte, error) {
		mu.Lock()
		*calls = append(*calls, args)
		mu.Unlock()
		if args[0] == "show" {
			return []byte("loaded\n"), nil
		}
		// the unit's run: prepares, leaves its result
		_ = os.WriteFile(d.bpfLSMDropIn, []byte("x"), 0o644)
		out, _ := json.Marshal(BPFLSMResult{Status: "prepared", LSM: "yama,apparmor,bpf", RebootRequired: true,
			Message: "prepared: reboot the host to activate BPF LSM"})
		return nil, os.WriteFile(d.bpfLSMResult, out, 0o644)
	}
	return d, rec, calls
}

func TestPrepareBPFLSMCommand(t *testing.T) {
	ctx := context.Background()
	c := client.Command{ID: 9, Kind: "prepare-bpf-lsm"}

	d, rec, calls := bpfLSMDaemon(t, kern.LSMInactive)
	if got := d.bpfLSMState(); got != kern.LSMInactive {
		t.Fatal(got)
	}
	if err := d.execute(ctx, c); err != nil {
		t.Fatal(err)
	}
	ack := rec.final(t)
	res, _ := ack["result"].(map[string]any)
	if ack["status"] != "done" || res["status"] != "prepared" || res["reboot_required"] != true {
		t.Fatalf("%v", ack)
	}
	if len(*calls) != 2 || strings.Join((*calls)[1], " ") != "start "+BPFLSMUnit {
		t.Fatalf("systemctl: %v", *calls)
	}
	// the heartbeat now says prepared, and so does the note
	if got := d.bpfLSMState(); got != "prepared" {
		t.Fatal(got)
	}
	if n := d.kernelNotes(); len(n) != 1 || n[0] != noteLSMPrepared {
		t.Fatalf("%v", n)
	}
}

func TestPrepareBPFLSMCommandRefused(t *testing.T) {
	ctx := context.Background()
	c := client.Command{ID: 9, Kind: "prepare-bpf-lsm"}

	// a kernel without BPF LSM: the boot line would not help
	d, rec, calls := bpfLSMDaemon(t, kern.LSMUnavailable)
	if err := d.execute(ctx, c); err == nil {
		t.Fatal("ran")
	}
	if ack := rec.final(t); ack["status"] != "failed" || len(*calls) != 0 {
		t.Fatalf("%v %v", ack, *calls)
	}

	// already active: done, nothing started
	d, rec, calls = bpfLSMDaemon(t, kern.LSMActive)
	if err := d.execute(ctx, c); err != nil {
		t.Fatal(err)
	}
	if ack := rec.final(t); ack["status"] != "done" || len(*calls) != 0 {
		t.Fatalf("%v %v", ack, *calls)
	}

	// an older install without the unit: failed, with what to do
	d, rec, _ = bpfLSMDaemon(t, kern.LSMInactive)
	d.runSystemctl = func(context.Context, ...string) ([]byte, error) { return []byte("not-found\n"), nil }
	if err := d.execute(ctx, c); err == nil {
		t.Fatal("ran")
	}
	if ack := rec.final(t); ack["status"] != "failed" || !strings.Contains(ack["error"].(string), "install script") {
		t.Fatalf("%v", ack)
	}

	// the unit failed: its message reaches the administrator
	d, rec, _ = bpfLSMDaemon(t, kern.LSMInactive)
	d.runSystemctl = func(_ context.Context, args ...string) ([]byte, error) {
		if args[0] == "show" {
			return []byte("loaded\n"), nil
		}
		out, _ := json.Marshal(BPFLSMResult{Status: "failed", Message: "update-grub not found"})
		_ = os.WriteFile(d.bpfLSMResult, out, 0o644)
		return []byte("Job for provenzasensor-bpf-lsm.service failed."), errors.New("exit status 1")
	}
	if err := d.execute(ctx, c); err != nil {
		t.Fatal(err)
	}
	if ack := rec.final(t); ack["status"] != "failed" || ack["error"] != "update-grub not found" {
		t.Fatalf("%v", ack)
	}
}

// Tests against the running kernel. They need root (CAP_BPF, CAP_NET_ADMIN,
// CAP_SYS_ADMIN) and cgroup v2, and run only with PROVENZA_SENSOR_KERNEL_TESTS=1.
package kerneltest

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/kironovlaziz-del/provenza/sensor/internal/bpfobj"
)

func needKernel(t *testing.T) {
	t.Helper()
	if os.Getenv("PROVENZA_SENSOR_KERNEL_TESTS") != "1" {
		t.Skip("set PROVENZA_SENSOR_KERNEL_TESTS=1 (as root) to run kernel tests")
	}
}

// Every program passes the verifier of this kernel.
func TestVerifierAcceptsPrograms(t *testing.T) {
	needKernel(t)
	spec, err := bpfobj.Spec()
	if err != nil {
		t.Fatal(err)
	}
	groups := map[string][]string{"core": bpfobj.CoreProgs, "lsm": bpfobj.LSMProgs, "mkdir": bpfobj.MkdirProgs}
	for group, names := range groups {
		s := spec.Copy()
		for name := range s.Programs {
			if !contains(names, name) {
				delete(s.Programs, name)
			}
		}
		coll, err := ebpf.NewCollection(s)
		if err != nil && group != "core" {
			t.Logf("%s (optional) not available on this kernel: %v", group, err)
			continue
		}
		if err != nil {
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) {
				t.Errorf("%s: verifier: %+v", group, ve)
			} else {
				t.Errorf("%s: %v", group, err)
			}
			continue
		}
		t.Logf("%s: %d programs loaded", group, len(coll.Programs))
		coll.Close()
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

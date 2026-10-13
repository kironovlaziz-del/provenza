package bpfobj

import (
	"errors"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/btf"
)

// The Go mirrors must have the C layouts.
func TestLayouts(t *testing.T) {
	spec, err := Spec()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]uintptr{
		"cg_entry":    unsafe.Sizeof(CgEntry{}),
		"wl_key":      unsafe.Sizeof(WlKey{}),
		"wl_cfg":      unsafe.Sizeof(WlCfg{}),
		"lpm4":        unsafe.Sizeof(LPM4{}),
		"lpm6":        unsafe.Sizeof(LPM6{}),
		"globals":     unsafe.Sizeof(Globals{}),
		"event":       unsafe.Sizeof(Event{}),
		"mkdir_event": unsafe.Sizeof(MkdirEvent{}),
	}
	for name, size := range cases {
		var s *btf.Struct
		if err := spec.Types.TypeByName(name, &s); err != nil {
			if errors.Is(err, btf.ErrNotFound) {
				t.Errorf("%s: not in the object's BTF", name)
				continue
			}
			t.Fatal(err)
		}
		if uintptr(s.Size) != size {
			t.Errorf("%s: C %d bytes, Go %d", name, s.Size, size)
		}
	}
	for _, p := range append(append(append([]string{}, CoreProgs...), LSMProgs...), MkdirProgs...) {
		if spec.Programs[p] == nil {
			t.Errorf("program %s missing", p)
		}
	}
}

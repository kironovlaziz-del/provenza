// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

import "testing"

const me = "S-1-5-21-1111111111-2222222222-3333333333-1001"

func TestSDDLProblem(t *testing.T) {
	ok := []string{
		"O:" + me + "G:DUD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + me + ")",
		"O:" + me + "D:P(A;;FA;;;" + me + ")",
		"O:BAD:(A;;FA;;;OW)(A;;0x1200a9;;;CO)",
		"D:(D;;FA;;;WD)(A;;FA;;;" + me + ")", // a deny entry for Everyone is not a leak
		"O:LAD:P(A;;FA;;;LA)",                // the user is the built-in Administrator account
		"D:(A;;FA;;;" + me + ")S:(AU;SA;FA;;;WD)",
	}
	for _, s := range ok {
		if err := sddlProblem(s, me); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	bad := map[string]string{
		"Everyone":      "D:PAI(A;;FA;;;" + me + ")(A;;FR;;;WD)",
		"Users":         "D:(A;;FA;;;SY)(A;;0x1200a9;;;BU)",
		"Authenticated": "D:(A;;FA;;;AU)",
		"another user":  "D:(A;;FA;;;S-1-5-21-1111111111-2222222222-3333333333-1002)",
		"no DACL":       "O:BAG:BA",
		"Guest":         "D:(A;;FA;;;LG)",
		"unknown kind":  "D:(Q;;FA;;;SY)",
		"short entry":   "D:(A;;FA;;SY)",
		"unterminated":  "D:(A;;FA;;;SY",
	}
	for name, s := range bad {
		if err := sddlProblem(s, me); err == nil {
			t.Errorf("%s: accepted %s", name, s)
		}
	}
}

func TestSDDLUserSIDCaseInsensitive(t *testing.T) {
	if err := sddlProblem("D:(A;;FA;;;s-1-5-21-1-2-3-1001)", "S-1-5-21-1-2-3-1001"); err != nil {
		t.Fatal(err)
	}
}

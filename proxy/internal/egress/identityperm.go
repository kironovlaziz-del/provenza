// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package egress

import (
	"fmt"
	"strings"
)

type permError struct{ path, msg string }

func (e *permError) Error() string { return e.path + " " + e.msg }

// trusted trustees of an identity file on Windows (SDDL abbreviations): the
// system, the local administrators, and the creator-owner / owner-rights
// placeholders that name the file's owner.
var trusted = map[string]bool{"SY": true, "BA": true, "CO": true, "OW": true}

// sddlProblem: why a Windows access list (SDDL string) lets someone other than
// the file's user in (nil: it does not). Only the DACL's allow entries
// count; a deny entry takes nothing away from what the file protects. The
// current user's SID is the third trusted trustee. An entry that cannot be
// parsed is a problem: the answer is "no" unless every entry is understood.
func sddlProblem(sddl, userSID string) error {
	i := strings.Index(sddl, "D:")
	if i < 0 {
		return fmt.Errorf("it has no access list (everyone may read it)")
	}
	dacl := sddl[i+2:]
	if j := strings.Index(dacl, "S:"); j >= 0 { // the audit list follows
		dacl = dacl[:j]
	}
	rest := dacl
	for {
		open := strings.IndexByte(rest, '(')
		if open < 0 {
			break
		}
		end := strings.IndexByte(rest[open:], ')')
		if end < 0 {
			return fmt.Errorf("its access list is malformed")
		}
		ace := rest[open+1 : open+end]
		rest = rest[open+end+1:]
		f := strings.Split(ace, ";")
		if len(f) < 6 {
			return fmt.Errorf("its access list holds an entry that cannot be read (%q)", ace)
		}
		kind, trustee := f[0], f[5]
		switch kind {
		case "D", "OD", "XD": // deny entries take nothing away from what the file protects
			continue
		case "A", "OA", "XA", "ZA": // allow entries: checked below
		default:
			return fmt.Errorf("its access list holds an entry of unknown kind %q", kind)
		}
		if trusted[trustee] || strings.EqualFold(trustee, userSID) {
			continue
		}
		return fmt.Errorf("its access list lets %s read it", trusteeName(trustee))
	}
	return nil
}

func trusteeName(trustee string) string {
	switch trustee {
	case "WD":
		return "Everyone"
	case "BU":
		return "all local users (Users)"
	case "AU":
		return "all signed-in users (Authenticated Users)"
	case "IU":
		return "every interactive user"
	case "NU":
		return "every network user"
	}
	return "another account (" + trustee + ")"
}

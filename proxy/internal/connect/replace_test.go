// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package connect

import (
	"reflect"
	"testing"
)

func TestNumberIn(t *testing.T) {
	for s, want := range map[string]int64{
		"agent-110.pid": 110, "agent-.pid": 0, "agent-x.pid": 0, "agent-0.pid": 0, "other-3.pid": 0,
	} {
		if got := numberIn(s, "agent-", ".pid"); got != want {
			t.Errorf("%s: %d, want %d", s, got, want)
		}
	}
	if numberIn("ProvenzaAgent127", "ProvenzaAgent", "") != 127 || numberIn("ProvenzaTest", "ProvenzaAgent", "") != 0 {
		t.Fatal("Run value names")
	}
}

func TestSplitArgsReadsBackWhatWeWrite(t *testing.T) {
	o := Options{AgentID: 7, Port: 8480, Proxy: "http://127.0.0.1:8443",
		Binary:   `C:\Users\Ann Lee\AppData\Local\provenza\provenza-proxy.exe`,
		Identity: `C:\Users\Ann Lee\.config\provenza\provenza-agent.json`}
	got := splitArgs(o.AutostartCommand())
	want := []string{o.Binary, "agent-start", "-agent-id", "7", "-identity", o.Identity, "-port", "8480", "-proxy", o.Proxy}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%q", got)
	}
}

// What `reg query HKCU\...\Run` prints (here on a Russian Windows: the type
// names are the same in every language).
const regQuery = "\r\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\r\n" +
	"    OneDrive    REG_SZ    \"C:\\Users\\Indigo\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background\r\n" +
	"    ProvenzaAgent110    REG_SZ    C:\\Users\\Indigo\\AppData\\Local\\provenza\\provenza-proxy.exe agent-start -agent-id 110 -identity C:\\Users\\Indigo\\.config\\provenza\\provenza-agent.json -port 8480 -proxy https://stickstock.lol/api/v1\r\n" +
	"    ProvenzaAgent90    REG_SZ    C:\\p\\provenza-proxy.exe agent-start -agent-id 90 -identity C:\\other\\agent.json -port 8490 -proxy https://x\r\n" +
	"    ProvenzaAgent127    REG_EXPAND_SZ    C:\\p\\provenza-proxy.exe agent-start -agent-id 127 -identity C:\\Users\\Indigo\\.config\\provenza\\provenza-agent.json -port 8480 -proxy https://x\r\n\r\n"

func TestEarlierSignInEntries(t *testing.T) {
	vals := parseRunValues(regQuery)
	if len(vals) != 4 || vals[0].Name != "OneDrive" || vals[3].Name != "ProvenzaAgent127" {
		t.Fatalf("%+v", vals)
	}
	o := Options{AgentID: 127, Port: 8480, Identity: `C:\Users\Indigo\.config\provenza\provenza-agent.json`}
	var earlier []string
	for _, v := range vals {
		id := numberIn(v.Name, "ProvenzaAgent", "")
		if id != 0 && id != o.AgentID && servesSame(v.Data, o, "", "-port", "-identity") {
			earlier = append(earlier, v.Name)
		}
	}
	// 110: same port and identity file -> replaced; 90: its own port and identity -> kept; 127: this one
	if !reflect.DeepEqual(earlier, []string{"ProvenzaAgent110"}) {
		t.Fatalf("%v", earlier)
	}
	// the identity file alone is enough (another port, the same agent file)
	o.Port = 9999
	if !servesSame(vals[1].Data, o, "", "-port", "-identity") {
		t.Fatal("identity")
	}
	// case does not matter in a Windows path
	o.Identity = `c:\users\indigo\.config\provenza\provenza-agent.json`
	if !servesSame(vals[1].Data, o, "", "-port", "-identity") {
		t.Fatal("case")
	}
}

// `netstat -ano -p TCP` on a Russian Windows: the state is translated, the
// foreign address 0.0.0.0:0 still marks the listener.
const netstat = "\r\nАктивные подключения\r\n\r\n  Имя    Локальный адрес        Внешний адрес          Состояние       PID\r\n" +
	"  TCP    0.0.0.0:135            0.0.0.0:0              СЛУШАЕТ         1012\r\n" +
	"  TCP    127.0.0.1:8480         127.0.0.1:52011        УСТАНОВЛЕНО     6744\r\n" +
	"  TCP    127.0.0.1:8480         0.0.0.0:0              СЛУШАЕТ         6744\r\n" +
	"  TCP    127.0.0.1:84801        0.0.0.0:0              СЛУШАЕТ         7000\r\n"

func TestListenerPid(t *testing.T) {
	if got := parseListener(netstat, "127.0.0.1:8480"); got != 6744 {
		t.Fatalf("%d", got)
	}
	if got := parseListener(netstat, "127.0.0.1:8490"); got != 0 {
		t.Fatalf("%d", got)
	}
}

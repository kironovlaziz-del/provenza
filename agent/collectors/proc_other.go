//go:build !linux && !windows && !darwin

package collectors

import "errors"

// Other systems: no process listing (the port and model-file collectors
// still run).

func listProcesses() ([]procInfo, error) {
	return nil, errors.New("process listing is not supported on this system")
}

func processUID(int) string { return "" }

func accountName(uid string) string { return uid }

func newBehaviorProbe(map[string]string) behaviorProbe { return connProbe{} }

package collectors

import (
	"os"
	"strings"
)

// currentUser is the account the agent runs as (root, SYSTEM for a
// service; the person when run by hand).
func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return os.Getenv("USERNAME")
}

// ownerFromPath is the person a file belongs to by where it is:
// /home/<user>/..., /Users/<user>/..., C:\Users\<user>\... - the agent
// runs as a service, so its own account says nothing about the file.
func ownerFromPath(p string) string {
	parts := strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' })
	for i := 0; i+1 < len(parts); i++ {
		dir := strings.ToLower(parts[i])
		if (dir == "home" || dir == "users") && (i == 0 || (i == 1 && strings.HasSuffix(parts[0], ":"))) {
			if name := parts[i+1]; name != "Shared" && name != "Public" {
				return name
			}
			return ""
		}
	}
	if strings.HasPrefix(p, "/root/") {
		return "root"
	}
	return ""
}

// AgentUser is currentUser for the heartbeat.
func AgentUser() string { return currentUser() }

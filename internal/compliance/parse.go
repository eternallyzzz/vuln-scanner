package compliance

import "strings"

// parseSSHDConfig returns the last value of a directive in an sshd_config
// text (sshd uses last-match-wins). Comments and inline comments are
// stripped; missing directives report found=false. v1 intentionally parses
// only the main file and not Include'd snippets.
func parseSSHDConfig(text, key string) (value string, found bool) {
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], key) {
			value = strings.ToLower(fields[1])
			found = true
		}
	}
	return value, found
}

// hasEmptyShadowPassword reports whether any /etc/shadow entry has an empty
// password hash. Locked accounts (hash starting with ! or *) are not empty.
func hasEmptyShadowPassword(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		if fields[1] == "" {
			return true
		}
	}
	return false
}

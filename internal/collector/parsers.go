package collector

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

var ssProcessRe = regexp.MustCompile(`"([^"]+)"[^)]*?pid=(\d+)`)

// ParseSSPorts parses `ss -tulnp` output into structured listening sockets.
// It is deliberately tolerant: malformed lines are skipped.
func ParseSSPorts(output string) []PortInfo {
	var ports []PortInfo
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		netid := strings.ToLower(fields[0])
		if netid == "netid" || fields[1] == "State" {
			continue
		}
		protocol := ""
		switch {
		case strings.HasPrefix(netid, "tcp"):
			protocol = "tcp"
		case strings.HasPrefix(netid, "udp"):
			protocol = "udp"
		default:
			continue
		}
		address, port := splitLocalAddress(fields[4])
		if port <= 0 {
			continue
		}
		process := parseSSProcess(strings.Join(fields[5:], " "))
		ports = append(ports, PortInfo{
			Protocol: protocol,
			Address:  address,
			Port:     port,
			Process:  process,
		})
	}
	return ports
}

func splitLocalAddress(local string) (string, int) {
	addr := strings.TrimSpace(local)
	port := 0
	if strings.HasPrefix(addr, "[") {
		end := strings.Index(addr, "]")
		if end < 0 {
			return addr, 0
		}
		portStr := strings.TrimPrefix(addr[end+1:], ":")
		port, _ = strconv.Atoi(portStr)
		return addr[1:end], port
	}
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return addr, 0
	}
	port, _ = strconv.Atoi(addr[idx+1:])
	return addr[:idx], port
}

func parseSSProcess(column string) string {
	matches := ssProcessRe.FindAllStringSubmatch(column, -1)
	var parts []string
	for _, m := range matches {
		parts = append(parts, m[1]+"("+m[2]+")")
	}
	return strings.Join(parts, ",")
}

// ParseTasklistCSV parses `tasklist /v /fo csv /nh` output into processes,
// sorted by resident memory descending.
func ParseTasklistCSV(data []byte) ([]ProcessInfo, error) {
	r := csv.NewReader(strings.NewReader(string(data)))
	r.LazyQuotes = true
	r.FieldsPerRecord = -1
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	var procs []ProcessInfo
	for _, rec := range records {
		if len(rec) < 7 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(rec[1]))
		if err != nil || pid <= 0 {
			continue
		}
		procs = append(procs, ProcessInfo{
			PID:      pid,
			Name:     strings.TrimSpace(rec[0]),
			User:     strings.TrimSpace(rec[6]),
			MemoryMB: parseMemoryString(rec[4]),
		})
	}
	sort.SliceStable(procs, func(i, j int) bool {
		return procs[i].MemoryMB > procs[j].MemoryMB
	})
	return procs, nil
}

func parseMemoryString(v string) int64 {
	v = strings.TrimSpace(strings.ToUpper(v))
	mult := int64(1)
	switch {
	case strings.HasSuffix(v, "GB"):
		mult = 1024 * 1024
		v = strings.TrimSuffix(v, "GB")
	case strings.HasSuffix(v, "MB"):
		mult = 1024
		v = strings.TrimSuffix(v, "MB")
	case strings.HasSuffix(v, "KB"):
		mult = 1
		v = strings.TrimSuffix(v, "KB")
	case strings.HasSuffix(v, "K"):
		v = strings.TrimSuffix(v, "K")
	default:
		return 0
	}
	v = strings.TrimSpace(v)
	kb, err := strconv.ParseFloat(strings.ReplaceAll(v, ",", ""), 64)
	if err != nil {
		return 0
	}
	return int64(kb) * mult / 1024
}

// ParseLSBLK parses `lsblk -bno NAME,SIZE,MOUNTPOINT` output into disks,
// skipping loop and ram devices.
func ParseLSBLK(output string) []StorageSpec {
	var disks []StorageSpec
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") {
			continue
		}
		size, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || size <= 0 {
			continue
		}
		mount := ""
		if len(fields) > 2 {
			mount = fields[2]
		}
		serial, model := "", ""
		if len(fields) > 3 {
			serial = fields[3]
		}
		if len(fields) > 4 {
			model = fields[4]
		}
		disks = append(disks, StorageSpec{
			Name: name, SizeBytes: size, Mount: mount,
			Serial: serial, Model: model,
		})
	}
	return disks
}

// DecodeCommandOutput converts UTF-16LE output (e.g. schtasks on Windows)
// to UTF-8 text and falls back to the raw bytes otherwise.
func DecodeCommandOutput(data []byte) string {
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		data = data[2:]
	}
	if len(data) >= 2 && bytes.Contains(data, []byte{0x00}) {
		u16 := make([]uint16, 0, len(data)/2)
		for i := 0; i+1 < len(data); i += 2 {
			u16 = append(u16, uint16(data[i])|uint16(data[i+1])<<8)
		}
		return string(utf16.Decode(u16))
	}
	return string(data)
}

// ParseIPRoute parses `ip route show` output.
func ParseIPRoute(output string) []RouteInfo {
	var routes []RouteInfo
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		r := RouteInfo{Destination: fields[0]}
		for i := 1; i+1 < len(fields); i++ {
			switch fields[i] {
			case "via":
				r.Gateway = fields[i+1]
			case "dev":
				r.Interface = fields[i+1]
			case "metric":
				r.Metric = fields[i+1]
			}
		}
		routes = append(routes, r)
	}
	return routes
}

// ParseIPNeigh parses `ip neigh show` output.
func ParseIPNeigh(output string) []NeighborInfo {
	var neighbors []NeighborInfo
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		n := NeighborInfo{IP: fields[0]}
		for i := 1; i+1 < len(fields); i++ {
			switch fields[i] {
			case "dev":
				n.Interface = fields[i+1]
			case "lladdr":
				n.MAC = fields[i+1]
			}
		}
		last := fields[len(fields)-1]
		switch last {
		case "REACHABLE", "STALE", "DELAY", "FAILED", "INCOMPLETE", "PERMANENT", "NOARP":
			n.State = last
		}
		neighbors = append(neighbors, n)
	}
	return neighbors
}

// ParseIPTablesSave parses `iptables-save` rules (no names, indexed rules).
func ParseIPTablesSave(output string) []FirewallRule {
	var rules []FirewallRule
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-A ") {
			continue
		}
		rule := FirewallRule{
			Name:    "rule-" + strconv.Itoa(len(rules)+1),
			Enabled: "Yes",
		}
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			switch fields[i] {
			case "-s":
				rule.RemoteIP = fields[i+1]
			case "-p":
				rule.Protocol = fields[i+1]
			case "--dport":
				rule.LocalPort = fields[i+1]
			case "-j":
				rule.Action = fields[i+1]
			}
		}
		rules = append(rules, rule)
	}
	return rules
}

// ParseNFTListRuleset parses the essential lines of `nft list ruleset`.
func ParseNFTListRuleset(output string) []FirewallRule {
	var rules []FirewallRule
	var chain string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "chain ") {
			chain = strings.Fields(line)[1]
			continue
		}
		if chain == "" || strings.HasPrefix(line, "table ") || strings.HasPrefix(line, "}") ||
			strings.HasPrefix(line, "type ") || line == "" {
			continue
		}
		rule := FirewallRule{
			Name:    chain + "/rule-" + strconv.Itoa(len(rules)+1),
			Enabled: "Yes",
			Action:  lastNFTAction(line),
		}
		for i := 0; i+1 < len(strings.Fields(line)); i++ {
			f := strings.Fields(line)
			switch f[i] {
			case "dport":
				rule.LocalPort = strings.Trim(f[i+1], "\"")
			case "saddr":
				rule.RemoteIP = strings.Trim(f[i+1], "\"")
			case "tcp", "udp":
				if strings.Contains(f[i+1], "dport") {
					rule.Protocol = f[i]
				}
			}
		}
		rules = append(rules, rule)
	}
	return rules
}

func lastNFTAction(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	last := fields[len(fields)-1]
	if last == "accept" || last == "drop" || last == "reject" || last == "log" {
		return strings.ToUpper(last)
	}
	return ""
}

// ParseSystemctlUnits parses `systemctl list-units --all --no-legend`.
func ParseSystemctlUnits(output string) []ServiceInfo {
	var services []ServiceInfo
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || !strings.HasSuffix(fields[0], ".service") {
			continue
		}
		services = append(services, ServiceInfo{
			Name:  fields[0],
			State: fields[2] + "/" + fields[3],
		})
	}
	return services
}

// ParseSystemctlUnitFiles parses `systemctl list-unit-files --no-legend`
// into unit -> state (enabled/disabled/static/...).
func ParseSystemctlUnitFiles(output string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasSuffix(fields[0], ".service") {
			continue
		}
		out[fields[0]] = fields[1]
	}
	return out
}

// ParseSystemctlTimers parses `systemctl list-timers --all --no-legend`.
func ParseSystemctlTimers(output string) []ScheduledTask {
	var tasks []ScheduledTask
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		tasks = append(tasks, ScheduledTask{
			Name:    fields[len(fields)-2],
			Status:  "active",
			NextRun: strings.Join(fields[:4], " "),
			Command: fields[len(fields)-1],
		})
	}
	return tasks
}

// ParseCrontab parses crontab files into scheduled tasks.
func ParseCrontab(output, name string) []ScheduledTask {
	var tasks []ScheduledTask
	for i, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		cmd := strings.TrimSpace(strings.TrimPrefix(line, strings.Join(fields[:5], " ")))
		tasks = append(tasks, ScheduledTask{
			Name:    name + "#" + strconv.Itoa(i+1),
			Status:  "active",
			Command: cmd,
		})
	}
	return tasks
}

// ParseSchTasksCSV parses `schtasks /query /fo csv /v` (UTF-16 aware).
func ParseSchTasksCSV(data []byte) ([]ScheduledTask, error) {
	text := DecodeCommandOutput(data)
	r := csv.NewReader(strings.NewReader(text))
	r.LazyQuotes = true
	r.FieldsPerRecord = -1
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}
	header := records[0]
	idx := func(name string) int {
		for i, h := range header {
			hv := strings.ToLower(strings.TrimSpace(h))
			if strings.EqualFold(hv, name) || strings.Contains(hv, strings.ToLower(name)) {
				return i
			}
		}
		return -1
	}
	iTask := idx("TaskName")
	if iTask < 0 {
		iTask = idx("任务名")
	}
	iNext := idx("Next Run Time")
	if iNext < 0 {
		iNext = idx("下次运行时间")
	}
	iStatus := idx("Status")
	if iStatus < 0 {
		iStatus = idx("状态")
	}
	iCmd := idx("Task To Run")
	if iCmd < 0 {
		iCmd = idx("要运行的任务")
	}
	var tasks []ScheduledTask
	for _, rec := range records[1:] {
		get := func(i int) string {
			if i < 0 || i >= len(rec) {
				return ""
			}
			return strings.TrimSpace(rec[i])
		}
		name := get(iTask)
		if name == "" {
			continue
		}
		name = strings.TrimPrefix(name, `\`)
		tasks = append(tasks, ScheduledTask{
			Name:    name,
			Status:  get(iStatus),
			NextRun: get(iNext),
			Command: get(iCmd),
		})
	}
	return tasks, nil
}

// ParseNetShFirewall parses `netsh advfirewall firewall show rule name=all`.
func ParseNetShFirewall(output string) []FirewallRule {
	decoded := DecodeCommandOutput([]byte(output))
	var rules []FirewallRule
	var current *FirewallRule
	for _, line := range strings.Split(decoded, "\n") {
		line = strings.TrimSpace(line)
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "Rule Name":
			if current != nil {
				rules = append(rules, *current)
			}
			current = &FirewallRule{Name: value, Enabled: "", Direction: "", Action: "", Protocol: "", LocalPort: "", RemoteIP: ""}
		case "Enabled":
			if current != nil {
				current.Enabled = value
			}
		case "Direction":
			if current != nil {
				current.Direction = value
			}
		case "Action":
			if current != nil {
				current.Action = value
			}
		case "Protocol":
			if current != nil {
				current.Protocol = value
			}
		case "Local Port":
			if current != nil {
				current.LocalPort = value
			}
		case "Remote IP":
			if current != nil {
				current.RemoteIP = value
			}
		}
	}
	if current != nil {
		rules = append(rules, *current)
	}
	return rules
}

// ParseOpenSSLCert parses `openssl x509 -noout -subject -issuer -serial -dates`.
func ParseOpenSSLCert(output, store string) (CertificateInfo, bool) {
	var c CertificateInfo
	found := false
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		found = true
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "subject":
			c.Subject = value
		case "issuer":
			c.Issuer = value
		case "serial":
			c.Serial = value
		case "notBefore":
			c.NotBefore = value
		case "notAfter":
			c.NotAfter = value
		}
	}
	c.Store = store
	return c, found
}

// ParsePasswd parses /etc/passwd into account names with metadata.
func ParsePasswd(output string) []AccountInfo {
	var accounts []AccountInfo
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		name := fields[0]
		shell := fields[6]
		accounts = append(accounts, AccountInfo{
			Name:     name,
			Group:    fields[3],
			Disabled: strings.Contains(shell, "nologin") || shell == "/bin/false",
		})
	}
	return accounts
}

// ParseGroupOutput parses `getent group` lines into member names.
func ParseGroupOutput(output string) map[string]bool {
	members := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		for _, m := range strings.Split(fields[3], ",") {
			m = strings.TrimSpace(m)
			if m != "" {
				members[m] = true
			}
		}
	}
	return members
}

// ParseDF parses `df -Pk` output into mount -> usage percent.
func ParseDF(output string) map[string]float64 {
	usage := map[string]float64{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || !strings.HasSuffix(fields[4], "%") {
			continue
		}
		pct, err := strconv.ParseFloat(strings.TrimSuffix(fields[4], "%"), 64)
		if err != nil {
			continue
		}
		usage[fields[5]] = pct
	}
	return usage
}

// ParseWSLList parses `wsl -l -q` output (NUL/newline separated names).
func ParseWSLList(output string) []RuntimeInfo {
	var runtimes []RuntimeInfo
	for _, name := range strings.FieldsFunc(output, func(r rune) bool {
		return r == '\x00' || r == '\n' || r == '\r'
	}) {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		runtimes = append(runtimes, RuntimeInfo{Name: name, Type: "wsl"})
	}
	return runtimes
}

// ParseDockerPS parses `docker ps -a --format` output into runtimes.
func ParseDockerPS(output string) []RuntimeInfo {
	var runtimes []RuntimeInfo
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			continue
		}
		runtimes = append(runtimes, RuntimeInfo{
			Name: fields[0], Type: "container", State: fields[2],
		})
	}
	return runtimes
}

// ParsePhysicalMemoryJSON parses Win32_PhysicalMemory ConvertTo-Json output.
func ParsePhysicalMemoryJSON(data []byte) ([]MemoryModule, error) {
	type raw struct {
		DeviceLocator        string `json:"DeviceLocator"`
		Capacity             int64  `json:"Capacity"`
		Speed                int64  `json:"Speed"`
		ConfiguredClockSpeed int64  `json:"ConfiguredClockSpeed"`
		PartNumber           string `json:"PartNumber"`
		SerialNumber         string `json:"SerialNumber"`
		SMBIOSMemoryType     int64  `json:"SMBIOSMemoryType"`
	}
	var items []raw
	if len(data) == 0 {
		return nil, nil
	}
	if data[0] == '[' {
		if err := json.Unmarshal(data, &items); err != nil {
			return nil, err
		}
	} else {
		var item raw
		if err := json.Unmarshal(data, &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	var modules []MemoryModule
	for _, r := range items {
		speed := ""
		if r.Speed > 0 {
			speed = strconv.FormatInt(r.Speed, 10)
		} else if r.ConfiguredClockSpeed > 0 {
			speed = strconv.FormatInt(r.ConfiguredClockSpeed, 10)
		}
		modules = append(modules, MemoryModule{
			Slot:       r.DeviceLocator,
			CapacityMB: r.Capacity / (1024 * 1024),
			Type:       memoryTypeName(r.SMBIOSMemoryType),
			Speed:      speed,
			Serial:     r.SerialNumber,
		})
	}
	return modules, nil
}

func memoryTypeName(t int64) string {
	switch t {
	case 20:
		return "DDR"
	case 21:
		return "DDR2"
	case 24:
		return "DDR3"
	case 26:
		return "DDR4"
	case 27:
		return "DDR5"
	default:
		return ""
	}
}

// ParseLogicalDiskJSON parses Win32_LogicalDisk output into storage volumes.
func ParseLogicalDiskJSON(data []byte) ([]StorageSpec, error) {
	type raw struct {
		DeviceID   string `json:"DeviceID"`
		Size       int64  `json:"Size"`
		FreeSpace  int64  `json:"FreeSpace"`
		FileSystem string `json:"FileSystem"`
	}
	var items []raw
	if len(data) == 0 {
		return nil, nil
	}
	if data[0] == '[' {
		if err := json.Unmarshal(data, &items); err != nil {
			return nil, err
		}
	} else {
		var item raw
		if err := json.Unmarshal(data, &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	var volumes []StorageSpec
	for _, r := range items {
		if r.Size <= 0 {
			continue
		}
		usage := 0.0
		if r.Size > 0 {
			usage = float64(r.Size-r.FreeSpace) / float64(r.Size) * 100
		}
		volumes = append(volumes, StorageSpec{
			Name:         r.DeviceID,
			SizeBytes:    r.Size,
			Mount:        r.DeviceID,
			Model:        r.FileSystem,
			UsagePercent: usage,
		})
	}
	return volumes, nil
}

// ParseDMIdecodeMemory parses `dmidecode -t memory` output.
func ParseDMIdecodeMemory(output string) []MemoryModule {
	var modules []MemoryModule
	var current *MemoryModule
	flush := func() {
		if current != nil && current.Slot != "" && current.CapacityMB > 0 {
			modules = append(modules, *current)
		}
		current = nil
	}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "Memory Device" {
			flush()
			current = &MemoryModule{}
			continue
		}
		if current == nil || !strings.Contains(line, ":") {
			continue
		}
		key, value, _ := strings.Cut(line, ":")
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "Locator":
			current.Slot = value
		case "Size":
			if strings.HasSuffix(value, " GB") {
				n, _ := strconv.ParseFloat(strings.TrimSuffix(value, " GB"), 64)
				current.CapacityMB = int64(n * 1024)
			} else if strings.HasSuffix(value, " MB") {
				n, _ := strconv.ParseFloat(strings.TrimSuffix(value, " MB"), 64)
				current.CapacityMB = int64(n)
			}
		case "Type":
			current.Type = value
		case "Speed":
			current.Speed = value
		case "Serial Number":
			current.Serial = value
		}
	}
	flush()
	return modules
}

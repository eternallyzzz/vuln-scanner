package collector

import "testing"

func TestParseSSPorts(t *testing.T) {
	out := `Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
tcp    LISTEN  0       128     0.0.0.0:22            0.0.0.0:*         users:(("sshd",pid=1295,fd=3))
tcp6   LISTEN  0       128     [::]:80               [::]:*            users:(("nginx",pid=771,fd=6),("nginx",pid=772,fd=6))
udp    UNCONN  0       0       127.0.0.53:53         0.0.0.0:*
bad line without enough fields
`
	ports := ParseSSPorts(out)
	if len(ports) != 3 {
		t.Fatalf("got %d ports, want 3: %+v", len(ports), ports)
	}
	if ports[0].Protocol != "tcp" || ports[0].Address != "0.0.0.0" || ports[0].Port != 22 || ports[0].Process != "sshd(1295)" {
		t.Fatalf("tcp port wrong: %+v", ports[0])
	}
	if ports[1].Protocol != "tcp" || ports[1].Address != "::" || ports[1].Port != 80 {
		t.Fatalf("ipv6 port wrong: %+v", ports[1])
	}
	if ports[1].Process != "nginx(771),nginx(772)" {
		t.Fatalf("multi process wrong: %q", ports[1].Process)
	}
	if ports[2].Protocol != "udp" || ports[2].Port != 53 || ports[2].Process != "" {
		t.Fatalf("udp port wrong: %+v", ports[2])
	}
}

func TestParseTasklistCSV(t *testing.T) {
	data := []byte(`"chrome.exe","1234","Console","1","245,678 K","Running","DESKTOP\\alice","0:01:23","New Tab"
"System","4","Services","0","8 K","Running","NT AUTHORITY\SYSTEM","0:00:00",""
"python.exe","5678","Console","1","1,024 MB","Running","DESKTOP\\alice","0:02:00","idle"
`)
	procs, err := ParseTasklistCSV(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(procs) != 3 {
		t.Fatalf("got %d procs, want 3", len(procs))
	}
	if procs[0].Name != "python.exe" || procs[0].PID != 5678 || procs[0].MemoryMB != 1024 {
		t.Fatalf("top process wrong: %+v", procs[0])
	}
	if procs[1].Name != "chrome.exe" || procs[1].MemoryMB != 239 {
		t.Fatalf("chrome wrong: %+v", procs[1])
	}
	if procs[2].User != "NT AUTHORITY\\SYSTEM" {
		t.Fatalf("system user wrong: %+v", procs[2])
	}
}

func TestParseLSBLK(t *testing.T) {
	out := `sda 536870912000 / S1A2B3 WD-Blue
sda1 536870912000 /boot
loop0 104857600
ram0 16777216
sdb 1000204886016
`
	disks := ParseLSBLK(out)
	if len(disks) != 3 {
		t.Fatalf("got %d disks, want 3: %+v", len(disks), disks)
	}
	if disks[0].Name != "sda" || disks[0].SizeBytes != 536870912000 || disks[0].Mount != "/" {
		t.Fatalf("sda wrong: %+v", disks[0])
	}
	if disks[0].Serial != "S1A2B3" || disks[0].Model != "WD-Blue" {
		t.Fatalf("sda serial/model wrong: %+v", disks[0])
	}
	if disks[2].Name != "sdb" || disks[2].Mount != "" {
		t.Fatalf("sdb wrong: %+v", disks[2])
	}
}

func TestParseIPRoute(t *testing.T) {
	out := `default via 192.168.1.1 dev eth0 metric 100
10.0.0.0/8 via 10.0.0.1 dev eth1
172.16.0.0/12 dev eth0 proto kernel scope link src 172.16.0.2
`
	routes := ParseIPRoute(out)
	if len(routes) != 3 {
		t.Fatalf("got %d routes, want 3", len(routes))
	}
	if routes[0].Destination != "default" || routes[0].Gateway != "192.168.1.1" ||
		routes[0].Interface != "eth0" || routes[0].Metric != "100" {
		t.Fatalf("default route wrong: %+v", routes[0])
	}
	if routes[2].Gateway != "" || routes[2].Interface != "eth0" {
		t.Fatalf("link route wrong: %+v", routes[2])
	}
}

func TestParseIPNeigh(t *testing.T) {
	out := `192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
10.255.255.254 dev eth0 FAILED
`
	neigh := ParseIPNeigh(out)
	if len(neigh) != 2 {
		t.Fatalf("got %d neighbors, want 2", len(neigh))
	}
	if neigh[0].IP != "192.168.1.1" || neigh[0].MAC != "aa:bb:cc:dd:ee:ff" || neigh[0].State != "REACHABLE" {
		t.Fatalf("neighbor wrong: %+v", neigh[0])
	}
	if neigh[1].State != "FAILED" {
		t.Fatalf("failed neighbor wrong: %+v", neigh[1])
	}
}

func TestParseIPTablesSave(t *testing.T) {
	out := `*filter
:INPUT DROP [0:0]
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -s 10.0.0.0/8 -j DROP
COMMIT
`
	rules := ParseIPTablesSave(out)
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}
	if rules[0].Protocol != "tcp" || rules[0].LocalPort != "22" || rules[0].Action != "ACCEPT" {
		t.Fatalf("rule0 wrong: %+v", rules[0])
	}
	if rules[1].RemoteIP != "10.0.0.0/8" || rules[1].Action != "DROP" {
		t.Fatalf("rule1 wrong: %+v", rules[1])
	}
}

func TestParseSystemctl(t *testing.T) {
	units := ParseSystemctlUnits(`ssh.service loaded active running OpenSSH Daemon
cron.service loaded inactive dead
nginx.service not-found inactive dead
`)
	if len(units) != 3 || units[0].Name != "ssh.service" || units[0].State != "active/running" {
		t.Fatalf("units wrong: %+v", units)
	}
	files := ParseSystemctlUnitFiles(`ssh.service enabled
cron.service enabled
nginx.service disabled
`)
	if files["ssh.service"] != "enabled" || files["nginx.service"] != "disabled" {
		t.Fatalf("unit files wrong: %+v", files)
	}
	timers := ParseSystemctlTimers(`Mon 2026-08-04 03:00:00 CST 12h left Sun 2026-08-03 03:00:00 CST 12h ago apt-daily.timer apt-daily.service
`)
	if len(timers) != 1 || timers[0].Name != "apt-daily.timer" || timers[0].Command != "apt-daily.service" {
		t.Fatalf("timers wrong: %+v", timers)
	}
}

func TestParseCrontab(t *testing.T) {
	out := `# comment
*/5 * * * * /usr/bin/check.sh
0 2 * * * root /usr/local/bin/backup
`
	tasks := ParseCrontab(out, "/etc/crontab")
	if len(tasks) != 2 {
		t.Fatalf("got %d tasks, want 2", len(tasks))
	}
	if tasks[0].Command != "/usr/bin/check.sh" || tasks[1].Command != "root /usr/local/bin/backup" {
		t.Fatalf("crontab commands wrong: %+v", tasks)
	}
}

func TestParseSchTasksCSV(t *testing.T) {
	data := []byte("HostName,TaskName,Next Run Time,Status,Task To Run\r\n" +
		"host1,\\MyTask,2026/8/5 03:00:00,Running,\"C:\\bin\\job.exe\"\r\n" +
		"host1,\\OtherTask,Disabled,Ready,\"C:\\bin\\other.exe\"\r\n")
	tasks, err := ParseSchTasksCSV(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 2 || tasks[0].Name != "MyTask" || tasks[0].Command != `C:\bin\job.exe` {
		t.Fatalf("tasks wrong: %+v", tasks)
	}
}

func TestParseNetShFirewall(t *testing.T) {
	out := `Rule Name:                            My Rule
------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private
Grouping:                             -
Local IP:                             Any
Remote IP:                            Any
Protocol:                             TCP
Local Port:                           443
Remote Port:                          Any
Edge traversal:                       No
Action:                               Allow

Rule Name:                            Block SSH
------------------------------------------------------------------
Enabled:                              No
Direction:                            Out
Protocol:                             TCP
Action:                               Block
`
	rules := ParseNetShFirewall(out)
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2: %+v", len(rules), rules)
	}
	if rules[0].Name != "My Rule" || rules[0].Enabled != "Yes" || rules[0].LocalPort != "443" ||
		rules[0].Action != "Allow" || rules[0].Direction != "In" {
		t.Fatalf("rule0 wrong: %+v", rules[0])
	}
	if rules[1].Name != "Block SSH" || rules[1].Action != "Block" {
		t.Fatalf("rule1 wrong: %+v", rules[1])
	}
}

func TestParseOpenSSLCert(t *testing.T) {
	out := `subject=CN = example.com, O = Acme
issuer=CN = R11, O = Let's Encrypt
serial=1234ABCD
notBefore=Aug  1 00:00:00 2026 GMT
notAfter=Oct 30 00:00:00 2026 GMT
`
	cert, ok := ParseOpenSSLCert(out, "/etc/ssl/certs")
	if !ok || cert.Subject != "CN = example.com, O = Acme" || cert.Serial != "1234ABCD" ||
		cert.NotAfter == "" || cert.Store != "/etc/ssl/certs" {
		t.Fatalf("cert wrong: %+v ok=%v", cert, ok)
	}
}

func TestParseAccounts(t *testing.T) {
	passwd := ParsePasswd(`root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/bash
bob:x:1001:1001::/home/bob:/usr/sbin/nologin
`)
	if len(passwd) != 3 || passwd[2].Disabled != true || passwd[1].Name != "alice" {
		t.Fatalf("passwd wrong: %+v", passwd)
	}
	admins := ParseGroupOutput("sudo:x:27:alice,bob\nwheel:x:10:root\n")
	if !admins["alice"] || !admins["root"] || admins["nobody"] {
		t.Fatalf("group members wrong: %+v", admins)
	}
}

func TestParseDFAndRuntimes(t *testing.T) {
	usage := ParseDF(`Filesystem     1024-blocks      Used Available Capacity Mounted on
/dev/sda1        97628160  51234567  40000000      57% /
/dev/sdb1       195352371 100000000  90000000      53% /data
`)
	if usage["/"] != 57 || usage["/data"] != 53 {
		t.Fatalf("df wrong: %+v", usage)
	}
	wsl := ParseWSLList("Debian\x00Alpine\x00")
	if len(wsl) != 2 || wsl[0].Name != "Debian" || wsl[0].Type != "wsl" {
		t.Fatalf("wsl wrong: %+v", wsl)
	}
	containers := ParseDockerPS("nginx\tnginx:latest\tUp 2 hours\nredis\tredis:7\tExited (0)\n")
	if len(containers) != 2 || containers[0].Type != "container" || containers[1].State != "Exited (0)" {
		t.Fatalf("docker wrong: %+v", containers)
	}
}

func TestParseMemoryAndLogicalDisk(t *testing.T) {
	mods, err := ParsePhysicalMemoryJSON([]byte(`[{"DeviceLocator":"DIMM0","Capacity":17179869184,"Speed":4800,"ConfiguredClockSpeed":4800,"PartNumber":"KF548S38","SerialNumber":"12345","SMBIOSMemoryType":26}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 1 || mods[0].CapacityMB != 16384 || mods[0].Type != "DDR4" || mods[0].Speed != "4800" {
		t.Fatalf("memory wrong: %+v", mods)
	}
	vols, err := ParseLogicalDiskJSON([]byte(`[{"DeviceID":"C:","Size":500107862016,"FreeSpace":200000000000,"FileSystem":"NTFS"}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(vols) != 1 || vols[0].Name != "C:" || vols[0].Model != "NTFS" ||
		vols[0].UsagePercent < 59 || vols[0].UsagePercent > 61 {
		t.Fatalf("volume wrong: %+v", vols)
	}
}

func TestParseDMIdecodeMemory(t *testing.T) {
	out := `Memory Device
	Locator: DIMM0
	Size: 16 GB
	Type: DDR5
	Speed: 4800 MT/s
	Serial Number: 12345

Memory Device
	Locator: DIMM1
	Size: No Module Installed
	Type: Unknown
`
	mods := ParseDMIdecodeMemory(out)
	if len(mods) != 1 || mods[0].Slot != "DIMM0" || mods[0].CapacityMB != 16384 ||
		mods[0].Type != "DDR5" || mods[0].Serial != "12345" {
		t.Fatalf("dmidecode memory wrong: %+v", mods)
	}
}

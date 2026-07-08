---

title: "Network Security Essentials"

date: 2026-07-08 16:00 +0300

categories: [Foundations, Networking]

tags: [networking, soc, siem, log-analysis, incident-response]

description: "What a network perimeter breach looks like end to end: reconnaissance, VPN brute force, lateral movement, C2 beaconing, and data exfiltration, read straight out of firewall, WAF, and VPN logs."

---

## Description

- A network is an ecosystem: workstations, file and database servers, application servers, Active Directory, routers, switches, and the firewall that sits at the edge deciding what gets in and what gets out. The perimeter is where that ecosystem meets the open internet, and it's the first place a SOC analyst (Security Operations Center analyst, the person who triages security alerts) looks for trouble.
- Source: TryHackMe, room "Network Security Essentials." Findings below come from reading firewall logs, WAF (Web Application Firewall) / IDS (Intrusion Detection System) alerts, and VPN authentication logs for a simulated breach of a financial services company, Initech Corp.

## The problem

- Most network components never touch the internet directly. Firewalls, VPN gateways, and public-facing web servers do, which makes them the first thing an attacker probes and the first place defenders need eyes on.
- Two log families cover that view. Host-centric logs (Windows Event Logs, syslog, EDR (Endpoint Detection and Response) agents) show what happened on one machine. Network-centric logs (firewall, IDS/IPS, VPN, proxy) show what happened between machines. Neither tells the whole story alone.
- The task: a month of firewall, WAF, and VPN logs from Initech Corp, one attacker buried somewhere in them, and a question with real stakes. Did they just knock on the door, or did they get inside?

## How it works

- **Step 1: know what's exposed and why each piece matters.**

| Component | Role | Why attackers want it |
|---|---|---|
| Firewall | Filters traffic at the network edge | Controls the only door in; logs every connection attempt |
| VPN gateway | Authenticates remote employees | Brute-forceable, and a valid login lands you inside the LAN |
| Web/application servers | Run public-facing services | Internet-facing by design, scanned constantly for exploitable software |
| Active Directory | Manages accounts and access rights | One compromised domain admin account controls the whole enterprise |
| File/database servers | Hold the data that matters | The actual target once an attacker is inside |

- **Step 2: separate host-centric visibility from network-centric visibility.** Host logs tell you what happened inside a room. Network logs tell you who entered and left the building. Building a full timeline needs both, but perimeter monitoring lives almost entirely in the network-centric world: firewall allow/block decisions, IDS signatures, VPN authentication results.

- **Step 3: recognize the three signatures that show up at the perimeter on any given day.**

| Signature | What the logs show | Verdict pattern |
|---|---|---|
| Port scan | One external IP, many destination ports, mostly BLOCK | Attacker probing for an open service |
| Web attack (SQLi, XSS, directory traversal) | WAF alerts with `attack_type` set, mixed ALLOW/BLOCK | Filter on `action=BLOCK` first; the WAF names the attack for you |
| Brute force | One source IP, thousands of FAILED_AUTH events against one gateway | Group by source IP; scattered SUCCESS entries from other IPs are normal employee logins |

- **Step 4: walk an actual breach chain end to end.** This is what Initech's logs held once the pieces got lined up.

  Reconnaissance: filtering `firewall.log` for BLOCK and cutting the source IP with `cut -d' ' -f5 | cut -d: -f1 | sort -nr | uniq -c` surfaced one IP, 203.0.113.45, responsible for 279 blocked connections against 10.0.0.20 across ports 21, 22, 23, 445, and 3389. A classic port scan, low severity on its own.

  Credential access: the VPN logs told a different story. `grep FAIL | cut -d' ' -f3 | sort -nr | uniq -c` showed 118 failed logins from a single IP, all against the username `svc_backup`, a service account. One of those attempts succeeded, and the attacker walked away with an internal address, 10.8.0.23.

  Lateral movement: pivoting on 10.8.0.23 in the firewall log showed a sweep against three internal hosts, 10.0.0.20, 10.0.0.51, and 10.0.0.60, across SSH (22), SMB (445, Server Message Block, a Windows file-sharing protocol), and RDP (3389). The IDS confirmed this wasn't just scanning: alerts fired for "Possible MS-SMB Lateral Movement" on port 445, meaning the attacker moved between machines using an actual exploit, not a guess.

  C2 beaconing: filtering `ids_alerts.log` for C2 turned up dozens of "TROJAN Possible C2 (Command and Control) Beaconing" alerts, all from 10.0.0.60 to 198.51.100.77 on port 4444, spaced at regular intervals. A fixed source checking in with a fixed destination on a schedule is the signature of a compromised host reporting to its handler.

  Data exfiltration: the last host in the chain, 10.0.0.51, sent a steady stream of large HTTP POST requests to external addresses over ports 80 and 8080. IDS tagged them "Possible HTTP POST Large Upload" under the classification Potential Data Exfiltration. Data left the building.

## Why it matters

- No single log line in this investigation proves a breach. The port scan alone is routine internet noise. The failed VPN logins alone could be a user who forgot a password. What confirms a fully compromised network is the chain: recon feeds into a successful brute force, the brute force hands over an internal foothold, the foothold gets used for lateral movement, the lateral movement drops a C2 implant, and the implant starts moving data out.
- An analyst who checks only one log source at a time misses that chain. This room tests pivoting: taking one suspicious IP or host from a firewall log and immediately checking whether it shows up in the WAF logs, the VPN logs, and the IDS alerts too.
- That's the gap between closing a ticket after one alert and reconstructing what actually happened to a network over a month.

## Key takeaways

- A network perimeter isn't one device. It's the firewall, VPN gateway, DMZ (Demilitarized Zone, a buffer segment for public-facing servers), and every public-facing service working together, and all of it produces logs worth reading.
- Host-centric logs show what happened on a machine. Network-centric logs show what happened between machines. Perimeter monitoring depends on the second category almost entirely.
- Port scans, web attacks, and brute-force attempts each leave a distinct pattern: many ports from one source, WAF alerts with a named attack type, or thousands of failed auths against one account.
- A real breach rarely shows up as one alert. It shows up as a chain: reconnaissance, credential access, lateral movement, C2 beaconing, and exfiltration, each stage sitting in a different log file, waiting for someone to connect them.
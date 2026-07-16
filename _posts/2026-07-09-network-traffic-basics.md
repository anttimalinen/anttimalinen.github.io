---

title: "Network Traffic Basics"

date: 2026-07-09 16:00 +0300

categories: [Foundations, Networking]

tags: [networking, tcp, dns, packet-capture, netflow, soc]

description: "What network traffic analysis is, why logs alone miss the content of a connection, and how logs, full packet capture, and flow statistics like NetFlow combine to give a SOC analyst full visibility."

---

## Description

- Network Traffic Analysis (NTA) captures, inspects, and analyzes the data moving through a network to build full visibility into what talks to what, and why. NTA is not another name for Wireshark. It combines log correlation, deep packet inspection, and network flow statistics under one goal: know a network's normal traffic pattern and recognize what breaks it.
- Source: TryHackMe, room "Network Traffic Basics." This post covers what NTA observes at each layer of the TCP/IP model, the sources and flows that make up a corporate network, and the three methods (logs, full packet capture, network statistics) analysts use to collect that traffic.

## The problem

- A firewall log confirms WIN-016 (192.168.1.16) sent a stream of DNS queries to random subdomains under one top-level domain. It does not confirm what those queries carried. Pulling the query type shows several are TXT records, and inspecting the reply surfaces a base64-encoded Command and Control (C2, the channel an attacker uses to send instructions to a compromised system) payload riding inside what looks like a routine DNS answer. This technique, DNS tunneling, hides C2 traffic or exfiltrated data inside what looks like ordinary DNS lookups.
- The gap sits between what a log records and what crossed the wire. A GET request for a ZIP file logs a filename and a byte count. It does not log what's inside that ZIP. Closing that gap requires inspecting the traffic itself, not just the summary a device chose to write down.
- The task: know what each layer of a connection reveals, know which devices on a network generate the traffic worth watching, and know the collection methods that turn raw traffic into something searchable.

## How it works

- **Step 1: know what each layer of the TCP/IP stack exposes and what it hides.**

| Layer | What logs typically capture | What logs miss | Example |
|---|---|---|---|
| Application | HTTP headers, request URLs, response codes | Payload content (file contents, POST bodies) | A GET request for `suspicious_package.zip` logs the filename and a 10,485,760-byte response, never the bytes inside it |
| Transport | Source and destination ports, TCP flags | Sequence numbers, not captured by default | A sudden jump in sequence number mid-session flags a session hijacking attempt |
| Internet | Source and destination IP, TTL (Time To Live) | Fragment offset and total length | Overlapping fragment offsets let an attacker reassemble a packet in a way that slips past an IDS |
| Link | Source and destination MAC address | Repeated gratuitous ARP replies from the same MAC | ARP poisoning shows up only when the same MAC claims two different IP addresses |

- **Step 2: separate the sources that generate traffic from the sources that carry it.** Endpoint devices (servers, hosts, IoT devices, mobile phones) generate the bulk of network traffic. Intermediary devices (firewalls, switches, proxies, IDS/IPS, routers) pass that traffic through and add their own routing protocols (EIGRP, OSPF, BGP), management protocols (SNMP, PING), and logging protocols (SYSLOG), but at a fraction of the volume.

- **Step 3: know the difference between North-South and East-West traffic.**

| Flow type | Path | Typical protocols | Why it matters |
|---|---|---|---|
| North-South | Crosses the firewall between LAN and WAN | HTTPS, DNS, SSH, VPN, SMTP, RDP | Monitored by default because every packet passes one chokepoint |
| East-West | Stays inside the LAN | Kerberos and Active Directory authentication, SMB, backup and replication | Monitored less, but this is where an attacker moves laterally after landing a foothold |

  A Kerberos-authenticated SMB session shows the East-West pattern. A host requesting `\\FILESERVER\MARKETING` first authenticates to a Domain Controller's Key Distribution Center for a Ticket Granting Ticket, then requests a service ticket, then opens the share. None of that traffic touches the firewall.

- **Step 4: pick the right collection method for the job.**

| Method | How it works | Performance impact | Note |
|---|---|---|---|
| Logs | Each vendor logs the fields it decides matter: source IP, destination IP, a request line | None | No universal standard. Syslog and SNMP standardize how logs travel, not what they contain |
| Network TAP | A physical device placed inline copies the signal at the link layer, no MAC or IP address needed | Near zero | Full packet capture on a 1 Gbps line runs about 10.8 TB a day, so placement and duration both need planning |
| Port mirroring (SPAN) | A switch duplicates traffic from one port to a monitoring port in software | Can degrade performance under heavy load | Same idea works on virtual switches and cloud environments, like AWS VPC Traffic Mirroring |
| NetFlow / IPFIX | Collects metadata about a traffic flow (source, destination, volume, duration) instead of full packets | Minimal | Built into most NGFWs, IDS, and IPS already. Effective for spotting C2 traffic, exfiltration, and lateral movement without storing every packet |

- **Step 5: place the tap and read the traffic.** The room's exercise puts a small network topology on a static site and asks you to place a tap in the position that captures the traffic you need, then pull a flag out of HTTP traffic and a second flag out of DNS traffic.

- **Step 6: know the tools built for this.** Wireshark and tcpdump handle full packet inspection. Snort, Suricata, and Zeek run as IDS/IPS engines that alert on patterns instead of requiring a human to read every packet.

## Why it matters

- An analyst who reads only the firewall log misses the DNS tunneling case above. A SOC alert says "unusual number of DNS queries." Confirming whether that's exfiltration or a chatty application requires pulling the query content, and that's a full packet capture or a mirrored port away, not a firewall log away.
- Network statistics protocols like NetFlow let an analyst spot the shape of C2 beaconing (fixed source, fixed destination, regular interval) without capturing and storing every packet on a busy link, which matters the moment the link runs faster than 1 Gbps and full capture stops being practical.
- Verifying an alert, reconstructing an attack timeline, and ruling out a false positive depend on the same skill: knowing which collection method answers which question, and going to get that data instead of guessing from a summary log line.

## Key takeaways

- NTA combines log correlation, full packet capture, and network flow statistics. None of the three alone gives full visibility.
- Each layer of the TCP/IP stack hides something a log line does not capture: payload content at the application layer, sequence numbers at the transport layer, fragment offsets at the internet layer, repeated ARP claims at the link layer.
- Endpoint devices generate most network traffic. Intermediary devices mostly pass it through.
- North-South traffic crosses the firewall and gets monitored by default. East-West traffic stays inside the LAN and is where lateral movement happens, which makes it worth watching despite the lighter monitoring.
- Logs answer "did this happen." Full packet capture and NetFlow/IPFIX answer "what happened," each at a different cost in storage and performance.
- This room builds the vocabulary for the next one: hands-on packet analysis in Wireshark.
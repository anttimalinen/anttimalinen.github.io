---

title: "Wireshark: Traffic Analysis"

date: 2026-07-12 16:00 +0300

categories: [Foundations, Networking]

tags: [wireshark, network-forensics, arp-spoofing, dns-tunneling, https, soc]

description: "How Wireshark exposes Nmap scans, ARP poisoning MITM attacks, tunneled C2 traffic, and cleartext credentials by correlating TCP flags, ARP conflicts, DNS query lengths, and TLS handshakes across a full packet capture."

---

## Description

- Wireshark: Traffic Analysis closes the Wireshark trio, after "Wireshark: The Basics" and "Wireshark: Packet Operations." The first two rooms taught navigation and query syntax. This one applies both to a single job: reading correlated packet-level evidence and calling out anomalies, malicious activity, and attacker infrastructure inside a capture.
- Source: TryHackMe, room "Wireshark: Traffic Analysis." This post covers Nmap scan detection, ARP poisoning and MITM (Man-in-the-Middle) identification, host identification through DHCP, NetBIOS, and Kerberos, ICMP and DNS tunneling, cleartext protocol analysis for FTP and HTTP, HTTPS decryption with a TLS key log file, and two bonus tasks: hunting cleartext credentials and generating firewall ACL (Access Control List) rules straight from Wireshark. Every domain and IP address in this room is for identification only, never for direct interaction.

## The problem

- Real captures don't arrive labeled. An Nmap scan, an ARP-spoofed MITM attack, and a DNS tunnel all sit inside traffic that looks unremarkable at the IP layer. Confirming any of them takes recognizing a specific pattern, not waiting for a single alert to fire.
- Trusted protocols make the best cover. ICMP exists to report network errors. DNS exists to resolve names. Both cross most firewalls without inspection, which is exactly why attackers use them to carry C2 (Command and Control) traffic and exfiltrated data.
- The task: learn the packet-level signature for each technique in this room, in the order an investigation usually needs them: reconnaissance, interception, host identification, tunneling, and cleartext credential exposure, then turn findings into something a team can act on.

## How it works

- **Step 1: read TCP flags before naming a scan type.** Every scan pattern in this room comes down to which flags are set and which aren't.

| Flag combination | Meaning | Filter (field) | Filter (value) |
|---|---|---|---|
| SYN only | Connection request | `tcp.flags.syn == 1` | `tcp.flags == 2` |
| ACK only | Acknowledgment | `tcp.flags.ack == 1` | `tcp.flags == 16` |
| SYN, ACK | Second step of the handshake | `(tcp.flags.syn==1) and (tcp.flags.ack==1)` | `tcp.flags == 18` |
| RST | Connection reset or refused | `tcp.flags.reset == 1` | `tcp.flags == 4` |
| RST, ACK | Reset with acknowledgment | `(tcp.flags.reset==1) and (tcp.flags.ack==1)` | `tcp.flags == 20` |
| FIN | Graceful close | `tcp.flags.fin == 1` | `tcp.flags == 1` |

- **Step 2: tell the three Nmap scan types apart.**

| Scan type | Command | Handshake behavior | Privilege | Window size | Filter |
|---|---|---|---|---|---|
| TCP Connect | `nmap -sT` | Completes the full three-way handshake | Works without root, the only option for a non-privileged user | Larger than 1024 bytes | `tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024` |
| SYN scan | `nmap -sS` | Never finishes the handshake, sends RST after SYN/ACK | Needs root or an elevated account | 1024 bytes or less | `tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024` |
| UDP scan | `nmap -sU` | No handshake exists. Open ports stay silent; closed ports answer with an ICMP error | No privilege requirement noted | Not applicable | `icmp.type==3 and icmp.code==3` |

  A UDP scan's closed-port response is an ICMP Type 3, Code 3 packet (destination unreachable, port unreachable). Expanding that ICMP packet in the details pane reveals the encapsulated original request, which is how an analyst ties the error back to the exact port that was probed.

  Running these filters against the room's `nmap/Exercise.pcapng` surfaced 1,000 TCP Connect scans in total, with TCP port 80 scanned specifically via TCP Connect. UDP closed-port messages totaled 1,083, and the one open UDP port in the 55-70 range was port 68.

- **Step 3: know ARP well enough to spot poisoning.** Address Resolution Protocol (ARP) maps an IP address to a MAC address on the local network. It has no authentication, doesn't route beyond the local segment, and trusts every reply it receives. ARP poisoning (also called ARP spoofing or a MITM attack) abuses that trust by sending forged ARP traffic, usually claiming to be the gateway, so a victim's packets route through the attacker first.

| Purpose | Filter |
|---|---|
| Global search | `arp` |
| ARP requests | `arp.opcode == 1` |
| ARP responses | `arp.opcode == 2` |
| Broadcast requests | `arp.dst.hw_mac==00:00:00:00:00:00` |
| Duplicate or conflicting IP-to-MAC pairs | `arp.duplicate-address-detected or arp.duplicate-address-frame` |
| Requests from one specific MAC | `((arp) && (arp.opcode == 1)) && (arp.src.hw_mac == target-mac-address)` |

  Wireshark's expert info flags a conflict, but only on the second occurrence of a duplicate IP-to-MAC pairing, so recognizing the first half of the pattern is on the analyst. The investigation in this room builds in three stages. First, a single MAC address (ending in `b4`) shows up owning one IP address legitimately, then claiming a second, different IP, the network's actual gateway address. That's the spoofing signal. Second, the same MAC crafts ARP requests against a whole range of addresses, which reads as flooding or scanning rather than one isolated conflict. Third, adding the MAC address as a column to the HTTP packet list (Analyse > Apply as Column) shows every HTTP packet on the network terminating at that same attacker MAC instead of the real gateway, confirming an active, ongoing MITM rather than a one-off anomaly.

| Role | MAC address | IP address | Evidence |
|---|---|---|---|
| Attacker | `00:0c:29:e2:18:b4` | Owns `192.168.1.25`, claims `192.168.1.1` | Crafted ARP requests across an IP range and claimed the gateway's address |
| Gateway | `50:78:b3:f3:cd:f4` | `192.168.1.1` | The legitimate MAC-to-IP pairing for the real gateway |
| Victim | `00:0c:29:98:c7:a8` | `192.168.1.12` | HTTP traffic from this host lands at the attacker's MAC instead of the gateway's |

  Running the room's `arp/Exercise` file against this pattern turned up 284 ARP requests crafted by the attacker and 90 HTTP packets received by the attacker's MAC. Digging into the intercepted traffic surfaced 6 sniffed username-and-password entries, including the password for "Client986" (`clientnothere!`) and a comment field submitted by "Client354" reading "Nice work!"

- **Step 4: identify hosts and users through DHCP, NetBIOS, and Kerberos.** Naming conventions make an enterprise network easy to inventory and just as easy for an attacker to blend into, which is why identifying hosts through protocol traffic, not just naming patterns, matters.

| Protocol | Global filter | Packet type filters | What it reveals |
|---|---|---|---|
| DHCP (Dynamic Host Configuration Protocol) | `dhcp or bootp` | Request: `dhcp.option.dhcp == 3`. ACK: `dhcp.option.dhcp == 5`. NAK: `dhcp.option.dhcp == 6` | Request carries hostname (option 12), requested IP (option 50), lease time (option 51), client MAC (option 61). ACK carries domain name (option 15) and assigned lease time. NAK carries a rejection message (option 56), best read manually since it varies by case |
| NetBIOS (NBNS) | `nbns` | `nbns.name contains "keyword"` | Query name, TTL (Time To Live), and IP address tied to a NetBIOS name registration |
| Kerberos | `kerberos` | `kerberos.CNameString contains "keyword"` | Username in requests. Hostnames also appear in this field, ending in `$`, so `kerberos.CNameString and !(kerberos.CNameString contains "$")` isolates usernames from hostnames |

  Kerberos packets also expose `pvno` (protocol version, filter `kerberos.pvno == 5`), `realm` (the domain the ticket was issued for, filter `kerberos.realm contains ".org"`), `sname` (the service and domain tied to the ticket, filter `kerberos.SNameString == "krbtgt"` for ticket-granting-ticket requests), and `addresses` (client IP and NetBIOS name, present only in request packets).

  Working through the room's `dhcp-netbios.pcap` and `kerberos.pcap` files answered five identification questions: the MAC address of host "Galaxy A30" was `9a:81:41:cb:96:6c`, workstation "LIVALJM" sent 16 NetBIOS registration requests, host "Galaxy-A12" requested IP `172.16.13.85`, user "u5" held IP `10[.]1[.]12[.]2`, and the one available hostname inside the Kerberos packets was `xp1$`.

- **Step 5: catch ICMP and DNS tunneling.** Tunneling hides one protocol's data inside another to move it securely, or covertly, across network segments. Attackers favor ICMP and DNS because both are trusted, everyday protocols that most perimeters wave through.

| Protocol | Indicator | Filter |
|---|---|---|
| ICMP | Payload larger than the standard 64-byte packet | `data.len > 64 and icmp` |
| DNS | Known tunneling tool signature | `dns contains "dnscat"` |
| DNS | Abnormally long query name, excluding local mDNS noise | `dns.qry.name.len > 15 and !mdns` |

  ICMP tunneling usually starts after malware execution or a successful exploit, carrying TCP, HTTP, or SSH data inside the ICMP payload for C2 or exfiltration. Most enterprise networks restrict custom ICMP packets or require elevated privileges to craft them, but a careful attacker can still shape a tunneled packet to match the normal 64-byte size, so packet size alone isn't a guarantee. DNS tunneling follows the same setup: a query gets crafted with an encoded command as a subdomain, something like `encoded-commands.maliciousdomain.com`, and the response carries the actual instruction back, blending into ordinary DNS noise the whole way.

  Investigating `dns-icmp/icmp-tunnel.pcap` identified SSH as the protocol riding inside the ICMP tunnel. Investigating `dns-icmp/dns.pcap` identified `dataexfil[.]com` as the domain receiving the anomalous DNS queries.

- **Step 6: read cleartext FTP traffic.** File Transfer Protocol (FTP) prioritizes simplicity over security, which opens the door to MITM attacks, credential theft, phishing, malware planting, and data exfiltration whenever it runs unencrypted.

| Response series | Meaning | Examples | Filter |
|---|---|---|---|
| x1x | Information | 211 system status, 212 directory status, 213 file status | `ftp.response.code == 211` |
| x2x | Connection | 220 service ready, 227 passive mode, 228 long passive, 229 extended passive | `ftp.response.code == 227` |
| x3x | Authentication | 230 login success, 231 logout, 331 valid username, 430 invalid credentials, 530 login denied | `ftp.response.code == 230` |

| Command | Purpose | Filter |
|---|---|---|
| USER | Submits username | `ftp.request.command == "USER"` |
| PASS | Submits password | `ftp.request.command == "PASS"` |
| CWD | Changes working directory | Filter as needed on the command field |
| LIST | Lists directory contents | Filter as needed on the command field |

  Three advanced filters turn raw FTP traffic into attack signals: `ftp.response.code == 530` lists every failed login, `(ftp.response.code == 530) and (ftp.response.arg contains "username")` narrows that to attempts against one specific account, a brute-force signal, and `(ftp.request.command == "PASS") and (ftp.request.arg == "password")` lists every target that received the same password, a password-spray signal.

  Working through `ftp/ftp.pcap` found 737 incorrect login attempts, a 39,424-byte file accessed by the "ftp" account, an uploaded file named `resume.doc`, and a permission-change attempt on that file using `CHMOD 777`.

- **Step 7: read cleartext HTTP traffic, including User-Agent and Log4j patterns.** HTTP crosses almost every perimeter unblocked, which makes it the protocol of choice for phishing pages, web attacks, exfiltration, and C2 traffic alike.

| Response code | Meaning |
|---|---|
| 200 | Request successful |
| 301 / 302 | Resource moved, permanently or temporarily |
| 400 | Bad request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not found |
| 405 | Method not allowed |
| 408 | Request timeout |
| 500 | Internal server error |
| 503 | Service unavailable |

| Field | Filter | Use |
|---|---|---|
| User-Agent | `http.user_agent contains "keyword"` | Identifies the claimed browser/OS, or a scanning tool posing as one |
| Request URI | `http.request.uri contains "admin"` | Flags targeted paths |
| Host | `http.host contains "keyword"` | Identifies the targeted domain |
| Server | `http.server contains "apache"` | Fingerprints the responding web server |

  User-Agent strings are a lead, never a verdict. Watch for a single host presenting different User-Agents in a short window, non-standard or custom strings, subtle spelling drift ("Mozilla" versus "Mozlilla"), known scanning tool signatures (sqlmap, Nmap, Wfuzz, Nikto), or payload data stuffed directly into the field: `(http.user_agent contains "sqlmap") or (http.user_agent contains "Nmap") or (http.user_agent contains "Wfuzz") or (http.user_agent contains "Nikto")`.

  Log4j exploitation has a known cleartext fingerprint: a POST request carrying the strings `jndi:ldap` or `Exploit.class`, sometimes with `$` or `==` (base64 padding) turning up inside the User-Agent field itself.

| Purpose | Filter |
|---|---|
| Isolate POST requests | `http.request.method == "POST"` |
| Search packet-level IP fields for the exploit string | `(ip contains "jndi") or (ip contains "Exploit")` |
| Search the whole frame for the exploit string | `(frame contains "jndi") or (frame contains "Exploit")` |
| Flag encoded payloads riding in the User-Agent | `(http.user_agent contains "$") or (http.user_agent contains "==")` |

  Investigating `http/user-agent.pcap` found 6 anomalous User-Agent types, with the spelling-difference anomaly sitting in packet 52. Investigating `http/http.pcapng` located the Log4j attack's starting packet at frame 444; decoding the base64 command inside that exchange pointed to `62[.]210[.]130[.]250` as the contacted IP.

- **Step 8: decrypt and read HTTPS traffic.** HTTPS uses TLS (Transport Layer Security) to encrypt communications, which is exactly why it's also used by attackers and malicious sites: the same protection that secures legitimate traffic hides malicious traffic just as well.

| Purpose | Filter |
|---|---|
| All HTTP(S) requests | `http.request` |
| Global TLS search | `tls` |
| TLS Client Hello | `tls.handshake.type == 1` |
| TLS Server Hello | `tls.handshake.type == 2` |
| SSDP noise (Simple Service Discovery Protocol) | `ssdp` |

  Client Hello and Server Hello, isolated and cleared of SSDP noise, identify exactly which IPs took part in a TLS handshake: `(http.request or tls.handshake.type == 1) and !(ssdp)` for the client side, `(http.request or tls.handshake.type == 2) and !(ssdp)` for the server side.

  Decryption itself needs a key log file, a text file holding the unique per-session key pairs a browser (Chrome or Firefox both support this) writes out when the `SSLKEYLOGFILE` environment variable is set during the browsing session. The keys have to be captured while the traffic is being recorded; there's no way to generate them retroactively for a session that already happened. Once loaded through the right-click menu or Edit > Preferences > Protocols > TLS, the same packet exposes several new views: Frame, Decrypted TLS, Decompressed Header, Reassembled TCP, and Reassembled SSL.

  Working through `https/Exercise.pcap` located the Client Hello to `accounts.google.com` at frame 16. Loading `KeysLogFile.txt` and decrypting the session exposed 115 HTTP2 packets. Frame 322's decrypted authority header pointed to `safebrowsing[.]googleapis[.]com`. Reading through the decrypted traffic surfaced the flag `FLAG{THM-PACKETMASTER}`.

- **Step 9: bonus, hunt cleartext credentials with a built-in tool.** Spotting one suspicious login attempt by eye is manageable. Spotting a pattern of multiple credential submissions across a large capture is not, which is what Wireshark's Tools > Credentials menu (available from version 3.1 onward) exists to fix. It automatically extracts cleartext usernames and passwords from FTP, HTTP, IMAP, POP, and SMTP traffic, showing the packet number, protocol, username, and a pointer back to the packet holding that username. It only covers those five protocols, so it supplements manual inspection rather than replacing it.

- **Step 10: bonus, turn findings into a deployable firewall rule.** Detection without action stalls an investigation. Wireshark's Tools > Firewall ACL Rules menu takes a single selected packet and generates a ready-to-deploy rule, built for an external firewall interface, in one of six formats: Netfilter (iptables), Cisco IOS (standard or extended), IPFilter (ipfilter), IPFirewall (ipfw), Packet filter (pf), or Windows Firewall (netsh, old or new syntax). Selecting a packet tied to a confirmed malicious IP, port, or MAC address turns an afternoon of analysis into a rule someone can paste straight into a firewall config.

## Why it matters

- Every technique in this room hides behind something either invisible by design (ARP, local-segment only) or implicitly trusted (ICMP, DNS, HTTP). An analyst checking only for obvious IP-level oddities misses all of it. The tell always sits one layer deeper: a TCP window size, a duplicate ARP claim, a DNS query length, a base64 fragment padding out a User-Agent string.
- Correlation across protocols turns a suspicion into a confirmed incident. The ARP case in this room makes that explicit: the ARP anomalies alone suggested spoofing, but only cross-referencing that MAC address against HTTP destination traffic confirmed an active MITM intercepting one specific victim's requests.
- Wireshark's Credentials and Firewall ACL Rules tools close the gap between finding something and doing something about it. A cleartext password or a confirmed malicious IP is only half the job. A SOC analyst needs the finding in a form a team can act on: a credential to rotate, or a rule ready to push.
- This room is a starting point, not an endpoint. Wireshark reads what's already in a capture; it doesn't watch a network continuously or alert on its own. The room's own closing notes point toward IDS/IPS tools built for that job: Snort, Zeek, and NetworkMiner.

## Key takeaways

- TCP flag combinations distinguish Nmap's three scan types: TCP Connect completes the handshake and needs no privilege, SYN scans stay half-open and need root, UDP scans get silence from open ports and an ICMP Type 3, Code 3 from closed ones.
- ARP poisoning shows up as one MAC address claiming two different IPs, or flooding requests across a subnet. Confirming an active MITM takes correlating that MAC against a second protocol, like HTTP destination traffic.
- DHCP, NetBIOS, and Kerberos each identify hosts and users a different way: DHCP through request options, NetBIOS through name queries, Kerberos through the CNameString field filtered to exclude hostnames ending in `$`.
- ICMP and DNS tunneling both hide data inside protocols too trusted to block outright. Oversized ICMP payloads and abnormally long DNS query names are the starting filters for catching either.
- FTP and HTTP cleartext analysis both come down to response codes, request commands, and pattern-matching known attack signatures, like Log4j's `jndi:ldap` string, straight out of the packet content.
- HTTPS stays opaque without a captured TLS key log file. With one loaded, Wireshark decrypts the session and exposes the same request and response detail cleartext HTTP gives up for free.
- Wireshark's Tools menu turns a finding into an action: Credentials surfaces cleartext logins for a handful of protocols automatically, and Firewall ACL Rules generates a deployable rule from a single selected packet.
- This closes the Wireshark trio. Snort, Zeek, and NetworkMiner are the next step, applying detection at network scale instead of one capture at a time.

---

title: "Data Exfiltration Detection"

date: 2026-07-14 16:00 +0300

categories: [Foundations, Networking]

tags: [data-exfiltration, dns-tunneling, splunk, wireshark, soc]

description: "How data leaves a compromised network through DNS tunneling, FTP, HTTP, and ICMP, and how correlating Wireshark packet captures with Splunk log queries turns those covert channels into a confirmed incident."

---

## Description

- Data exfiltration is the unauthorized transfer of sensitive data from an organization to a destination an adversary controls. It can be a deliberate insider act or the result of malware and compromised credentials, and it sits at the end of most breaches: the moment data leaves, the attacker has what they came for.
- Source: TryHackMe, room "Data Exfiltration Detection." This post covers why adversaries exfiltrate data, the phases and techniques behind it, and hands-on detection across four channels: DNS tunneling, FTP, HTTP, and ICMP, using Wireshark for packet-level evidence and Splunk for log correlation.

## The problem

- Adversaries exfiltrate for concrete reasons: financial gain from selling stolen records, espionage against intellectual property, ransomware groups threatening to leak stolen data on top of encrypting it, sabotage through leaked internal data, and reconnaissance that feeds future attacks. The motive shapes the target, not the detection approach.
- Every channel in this room, DNS, FTP, HTTP, ICMP, is a protocol organizations already trust and allow through the firewall by default. That trust is what makes each one usable for exfiltration, and it means no single blocked connection or single alert proves anything on its own.
- The task: given four separate packet captures and a Splunk instance holding pre-ingested logs, identify which channel carried the exfiltrated data, which host was compromised, where the data went, and what proof (a flag) confirms it, for each of the four channels in turn.

## How it works

- **Step 1: know the shape of an exfiltration attack before opening a single log.** Real threat actors map cleanly onto these techniques.

| Threat actor | Technique | Description |
|---|---|---|
| APT29 (Cozy Bear) | HTTPS over legitimate domains | Encrypted HTTPS channels moved data out of government networks |
| FIN7 | HTTP POST to C2 servers | Stolen data embedded in POST request bodies to evade detection |
| Lunar Spider (Zloader) | Encrypted C2 channels | Sustained a two-month intrusion using staged, encrypted exfiltration |
| DarkSide Ransomware | Dual extortion | Data stolen before encryption, then leak threats layered on top |
| APT10 (Cloud Hopper) | Cloud-to-cloud transfer | Data pulled from managed service providers through cloud APIs |

  An exfiltration attack usually runs through four phases: discovery and collection (locating sensitive files), staging and compression (aggregating, encrypting, or encoding data into ZIP, RAR, or base64), exfiltration transport (network, removable media, cloud, or a covert channel), and C2 coordination (orchestrating the transfer and confirming receipt on the attacker's end).

| Technique category | Examples | Where to look |
|---|---|---|
| Network-based | HTTP/HTTPS uploads, FTP/SFTP/SCP, DNS tunneling, ICMP, custom TCP/UDP | Proxy logs, firewall/NGFW flows, NetFlow, DNS logs |
| Host-based | PowerShell, rclone, awscli, curl/wget, archive creation, removable USB, ADS | Sysmon/EDR process and network events, Windows Security object access, auditd/shell history |
| Cloud | S3 PutObject, Azure Blob uploads, GCS inserts, external Drive/SharePoint sharing | CloudTrail, Azure Activity, GCP Audit, cloud storage access logs |
| Covert & encoding | DNS tunneling, base64/chunked encoding, steganography, low-and-slow splitting | DNS logs, proxy logs with many small POSTs |
| Insider & collaboration | Slack/Teams/Dropbox/Drive uploads or external sharing, compromised accounts | Audit logs, share events, mail logs |

  SOC L1 triage centers on five things regardless of channel: the source host and user, the destination, the volume transferred, the process identity or command line involved, and corroborating evidence spread across proxy, DNS, flow, host, and cloud logs. No single one of those five confirms an incident alone. Every technique this room investigates, DNS tunneling, FTP, HTTP, ICMP, falls under that same network-based category: the data crosses the wire rather than staying host-local, which is why Wireshark and Splunk, not endpoint tooling, carry this investigation.

- **Step 2: detect exfiltration through DNS tunneling.** DNS is a covert channel of choice: every host performs DNS lookups, that traffic passes outbound without inspection by default, and data can ride inside subdomain labels or TXT record responses.

| What to look for | Why it matters |
|---|---|
| High query count to one external domain | A spike against a single domain outside the normal baseline |
| Long subdomain labels (over 60-100 characters) | Legitimate domains don't need labels that long |
| High-entropy or base32/base64-looking query names | Mixed case, digits, `-`, `=` in a hostname is not how real domains read |
| Rare record types (TXT, NULL) or many large TXT responses | Encoded data rides more comfortably in TXT than in an A record |
| Frequent NXDOMAIN or beaconing at regular intervals | Queries with no real answer, sent on a fixed schedule, look automated |

  In Wireshark, working against `dns_exfil.pcap`, the filters build in layers: `dns` isolates all DNS traffic, `dns.flags.response == 0` narrows to queries with no response, `dns && frame.len > 70` surfaces the unusually long queries, and `dns && dns.qry.name contains <domain>` confirms every query hitting one specific suspicious domain.

  In Splunk, the same investigation runs as a sequence of searches: `index=data_exfil sourcetype=DNS_logs` pulls the raw log set, `index="data_exfil" sourcetype="DNS_logs" | stats count by src_ip` shows which internal hosts are generating DNS traffic, `| stats count by query | sort -count` ranks the queries themselves, and `| where len(query) > 30` isolates the abnormally long ones.


  This investigation identified `tunnelcorp.net` as the domain receiving the tunneled traffic, 315 suspicious DNS logs tied to it, and `192.168.1.103` as the internal host sending the largest share of those requests.

- **Step 3: detect exfiltration through FTP.** FTP stays in use for exfiltration because it's old, simple, and often still sitting on a network through a legitimate or misconfigured server, reachable with compromised credentials or a throwaway account.

| What to look for | Why it matters |
|---|---|
| `USER` and `PASS` commands | FTP authenticates in cleartext, so credentials are visible on the wire |
| `STOR` (upload) and `RETR` (download) | Repeated or oversized transfers point to bulk data movement, not routine use |
| Large data connections to unusual external IPs, especially off-hours | Timing outside normal business activity is a signal on its own |
| Data channel openings on ephemeral PASV ports paired with large payloads | Passive mode plus size is the pattern to watch, not either alone |

  Working against `ftp-lab.pcap`, the filter chain isolates the investigation step by step: `ftp || ftp-data` pulls every FTP control and data packet, `ftp.request.command == "USER" || ftp.request.command == "PASS"` exposes login attempts and any weak or suspicious credentials, `ftp contains "STOR"` flags upload activity worth following as a TCP stream, and `ftp contains "csv"` narrows straight to file transfers involving spreadsheet data. A final pass with `ftp && frame.len > 90`, followed by Follow TCP Stream, exposes the content of the largest transfers directly.


  This investigation found 5 connections from the guest account, a file named `customer_data.xlsx` exfiltrated from the root account, `192.168.1.105` as the internal IP sending the largest payload to an external address, and the flag `THM{ftp_exfil_hidden_flag}` inside the stream carrying the CSV transfer.

- **Step 4: detect exfiltration through HTTP.** HTTP hides exfiltration inside the single busiest, most routine traffic type on any network: bulk data in POST bodies, small chunks smuggled into GET query strings for low-and-slow exfiltration, data hidden in custom headers, payloads split across chunked or multipart requests, or the whole channel wrapped in TLS so the payload stays invisible without inspection.

| What to look for | Why it matters |
|---|---|
| Unusually large POST requests to external or unexpected hosts | Bulk uploads outside normal application behavior stand out by size alone |
| Requests to low-reputation or rarely-seen domains | A destination absent from the normal baseline is worth a second look |
| Frequent small requests followed by one large upload | Beaconing that ends in a bulk transfer is a staging-then-exfiltration pattern |
| Chunked or multipart transfers composing a larger file | Splitting a file across requests is a way to dodge simple size thresholds |

  In Splunk, the investigation narrows in stages: `index="data_exfil" sourcetype="http_logs"` pulls the full log set (with the time range set to All Time), `method=POST` isolates uploads, `| stats count avg(bytes_sent) max(bytes_sent) min(bytes_sent) by domain | sort - count` ranks destinations by upload volume, and `method=POST bytes_sent > 600 | table _time src_ip uri domain dst_ip bytes_sent | sort - bytes_sent` surfaces the single largest suspicious transfer as a clean table.

  Correlating that finding against `http_lab.pcap` in Wireshark follows the same narrowing pattern: `http` shows all HTTP traffic, `http.request.method == "POST"` isolates uploads, and `http.request.method == "POST" and frame.len > 500`, tightened further to `frame.len > 750`, cuts the noise down to the one request that matches what Splunk already flagged. Following that HTTP stream exposes the actual file content being sent out.


  This investigation identified `192.168.1.103` as the compromised host used to exfiltrate the data, and the flag `THM{http_raw_3xf1ltr4t10n_succ3ss}` inside the exfiltrated content itself.

- **Step 5: detect exfiltration through ICMP.** ICMP exists for diagnostics, not data transfer, which is why it works as a covert channel: it's commonly permitted through firewalls and inspected less strictly than TCP or UDP. Attackers encode file chunks into echo request or reply payloads, sometimes using uncommon ICMP types or codes to dodge signature-based detection, fragmenting large payloads across multiple packets, and encoding the data (base64 is common) so it reads as high-entropy noise rather than a recognizable pattern.

| What to look for | Why it matters |
|---|---|
| Persistent ICMP sessions to an external host with no legitimate monitoring reason | Ongoing ICMP traffic to one address outside normal ping or monitoring use is a flag on its own |
| Payloads well above typical ping size | A standard ping runs around 74 bytes total; anything meaningfully larger warrants a look |
| High-entropy or base64/hex-patterned payload content | Encoded data doesn't look like normal ICMP diagnostic content |
| Bursts of ICMP with no other application traffic from the same host | ICMP as the only activity from a host is itself unusual |

  Working against `icmp_lab.pcap`, three filters carry the investigation: `icmp` isolates all ICMP traffic, `icmp.type == 8` narrows to echo requests, and `icmp.type == 8 and frame.len > 100` flags the packets carrying payloads well past the ~74-byte size of a normal ping.


  This investigation surfaced the flag `THM{1cmp_3ch0_3xf1ltr4t10n_succ3ss}` inside the oversized ICMP payloads.

## Why it matters

- No channel in this room gets caught by a single alert. DNS tunneling needed a query-length filter layered on top of a no-response filter. HTTP needed a Splunk byte-volume ranking correlated against a Wireshark frame-length filter before one suspicious request stood out from routine web traffic. Detection here is a narrowing process across multiple data points, not a single rule firing.
- Mapping each channel to a real threat actor (APT29's HTTPS exfiltration, FIN7's HTTP POST technique, DarkSide's dual extortion) turns an abstract lab exercise into pattern recognition that applies to an actual SOC queue: these are documented techniques, not hypothetical ones.
- DNS and ICMP both work as covert channels because they're trusted by default. A network that only blocks or inspects "risky" protocols leaves its most routine, most permitted traffic unmonitored. DNS and ICMP operate in that blind spot.
- Correlating Splunk and Wireshark mirrors how this plays out on the job: logs give breadth across an entire environment fast, while packet capture gives the depth needed to confirm content and pull hard evidence, like a flag or a filename, out of a single suspicious stream.

## Key takeaways

- Data exfiltration sits at the end of the kill chain, actions on objectives, so catching it in progress is the last chance to contain a breach before data is fully gone.
- DNS tunneling shows up as long, high-entropy subdomain labels and unanswered queries concentrated on one domain: `tunnelcorp.net`, 315 logs, `192.168.1.103` in this investigation.
- FTP exfiltration shows up in cleartext `USER`/`PASS` credentials and oversized `STOR` transfers: a guest account, 5 connections, `customer_data.xlsx`, and `192.168.1.105` sending the largest payload here.
- HTTP exfiltration hides inside routine POST traffic and needs volume-based filtering (bytes sent, frame length) to separate it from normal usage: `192.168.1.103` again, this time over HTTP.
- ICMP exfiltration is a payload-size problem: anything meaningfully larger than a standard ~74-byte ping on an ICMP echo request deserves a second look.
- Every channel here is a protocol organizations trust by default. That's the reason it works, and it's why SOC triage depends on correlating source, destination, volume, and process evidence across multiple log sources instead of trusting any single one.
- This room covers four channels. Cloud storage APIs, insider collaboration tools, and encrypted C2 traffic carry the same underlying risk and reward the same correlation-first approach.
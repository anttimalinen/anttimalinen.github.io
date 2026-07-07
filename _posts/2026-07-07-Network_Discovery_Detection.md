---
title: "Network Discovery Detection"

date: 2026-07-07 18:00 +0300

categories: [Foundations, Networking]

tags: [networking, soc, siem, log-analysis]

description: "What network discovery scanning looks like from the SOC seat: external versus internal scans, horizontal versus vertical port scans, and how to spot both in Zeek and SIEM logs."

---

## Description

- Network discovery scanning is how an attacker builds a map of a target before touching anything critical. This post breaks down what that scanning looks like in real logs, and how a SOC analyst (Security Operations Center analyst, the person who triages security alerts) tells a hostile scan apart from routine noise.
- Source: TryHackMe's SOC Level 1 path, room "Network Discovery Detection." Findings below come from reading Zeek (a tool that logs network connection metadata, not full packet contents) and firewall logs in Kibana (the search interface for Elastic/SIEM data).

## The problem

- Scanning by itself isn't automatically hostile. Vulnerability scanners, asset inventory tools, and search engine crawlers all touch a network the same way an attacker's reconnaissance does.
- The real job is telling a hostile scan apart from that noise, then reading its severity correctly. Severity comes down to two things: where the scan originates, and which MITRE ATT&CK stage (a public framework that names each phase of an attack, such as Reconnaissance or Discovery) it maps to.

| Scan origin | Source → destination pattern | ATT&CK stage | Severity | Response |
|---|---|---|---|---|
| External | Public IP → internal IP | Reconnaissance, no foothold yet | Low | Block the source IP at the perimeter firewall |
| Internal | Internal IP → internal IP | Discovery, attacker already has a foothold | High | Confirm it isn't an authorised scan, then escalate to incident response |

## How it works

- **Step 1: separate internal scanning from external scanning.** TryHackMe drops three exported log files in `/home/ubuntu/Downloads/logs` (`log-session-0.csv` through `log-session-2.csv`). Running `head -n2` on each file, then cutting the source and destination IP columns with `cut -d',' -f3,5`, splits them fast. Two files show a public IP hitting a private one. One file, `log-session-2.csv`, shows two private IPs talking to each other across thousands of entries, the internal scan: source 192.168.230.127, 2,276 log entries. The external scan sits in a separate file, sourced from 203.0.113.25 (a public IP), hitting an internal host on port 5922.

- **Step 2: tell horizontal scanning apart from vertical scanning.** Once an attacker knows what hosts exist, the next step is finding out what's open on them.

| Scan type | Pattern in the logs | What it tells the attacker | Real-world example |
|---|---|---|---|
| Horizontal | One source IP, one destination port, many destination IPs | Which hosts expose a specific port | WannaCry sweeping for open port 445 (SMB) |
| Vertical | One source IP, one destination IP, many destination ports | What's running on one specific host | Footprinting a single high-value server |

  Filtering the logs down to source IP, destination IP, and destination port surfaces both patterns here. The horizontal scan swept the 203.0.113.0/24 range (CIDR notation, meaning every address from 203.0.113.0 to 203.0.113.255), checking the same port across the whole block. The vertical scan targeted a single host, 192.168.230.145, checking three ports tied to common services: 80 (HTTP), 445 (SMB), and 3389 (RDP).

- **Step 3: identify the scanning technique itself.** Three mechanisms explain almost everything you'll see in discovery traffic.

| Technique | How it works | Log signature | Stealth |
|---|---|---|---|
| Ping sweep | Sends an ICMP (Internet Control Message Protocol, used for diagnostics like ping) echo request to every address in a range | Many ICMP requests from one source across a subnet | Loud, easy to block |
| TCP SYN scan | Sends a SYN (the first packet in a TCP three-way handshake) and drops the connection if there's no reply | `conn_state: S0` in Zeek, meaning a SYN went out and nothing came back | Quiet, blends into normal traffic |
| UDP scan | Sends an empty UDP packet, waits for a port-unreachable reply or a timeout | Isolated UDP packets, no consistent sweep pattern | Slow and unreliable, rarely a first move |

  In this room, filtering Kibana for ICMP traffic pointed to 192.168.230.127 as the source of a ping sweep touching a whole subnet. Checking `zeek.conn.conn_state` for the traffic between 203.0.113.25 and 192.168.230.145 showed `S0`, with one originator packet and zero response packets, confirming a TCP SYN scan. Filtering for `network.protocol: udp` across the full time range turned up no sweep pattern, so the answer to "any UDP scanning?" is no.


## Why it matters

- This is one of the most common alert types a Tier 1 SOC analyst triages on any given shift.
- Getting the call wrong in either direction has a cost. Miss the difference between external recon and internal discovery, and a low-severity perimeter scan gets escalated while a real post-compromise signal sits in the queue behind it.
- Reading `conn_state`, packet counts, and IP or port patterns straight from the SIEM, without waiting on a senior analyst to confirm the call, is the kind of log literacy that separates someone who has read about SIEM tools from someone who has actually used one to find something real.

## Key takeaways

- External scanning (public source, internal destination) maps to Reconnaissance and is low severity. Internal-to-internal scanning maps to Discovery and needs immediate escalation.
- Horizontal scans hit one port across many hosts. Vertical scans hit many ports on one host. Both show up from source IP, destination IP, and destination port alone.
- Ping sweeps are loud and ICMP-based. TCP SYN scans are quiet and show up as `S0` with no reply. UDP scans are slow and rare as a first move.
- None of this needs deep packet inspection. Source and destination IP, destination port, and a single connection-state field are usually enough to classify a scan and decide how urgently it needs a response.
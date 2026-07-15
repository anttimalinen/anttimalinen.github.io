---

title: "NetworkMiner"

date: 2026-07-15 13:00 +0300

categories: [Foundations, Networking]

tags: [networkminer, network-forensics, pcap-analysis, credential-extraction, soc]

description: "How NetworkMiner's host, session, DNS, credential, file, and anomaly tabs turn a raw pcap into a fast forensic overview, and how that overview differs from what Wireshark is built for."

---

## Description

- NetworkMiner is an open-source Network Forensic Analysis Tool (NFAT), a category of tool built to reconstruct hosts, sessions, files, and credentials from captured network traffic rather than to inspect individual packets one at a time. Developed and maintained by Netresec, it runs on Windows, Linux, macOS, and FreeBSD, and works two ways: as a passive sniffer that fingerprints hosts, sessions, and open ports without putting any traffic on the network, or as a PCAP parser that reassembles files and certificates from a capture already sitting on disk.
- Source: TryHackMe, room "NetworkMiner." This post covers what NetworkMiner is built for, how it differs from Wireshark, a tour of its Hosts, Sessions, DNS, Credentials, Files, Images, Parameters, Keywords, Messages, and Anomalies tabs, the practical differences between NetworkMiner versions 1.6 and 2.7, and hands-on findings across six capture files: `mx-3.pcap`, `mx-4.pcap`, `mx-7.pcap`, `mx-9`, `case1.pcap`, and `case2.pcap`.

## The problem

- A large pcap doesn't announce what's interesting inside it. Before deciding where to dig with Wireshark's packet-level filters, an analyst needs a fast answer to a simpler set of questions: which hosts are talking, what operating systems are they running, what files and credentials crossed the wire, and does anything look like a known attack pattern.
- Getting that answer by scrolling through packets one at a time doesn't scale, and it's the wrong tool for the job. Wireshark is built for depth: protocol dissection, payload inspection, statistical filtering. NetworkMiner is built for breadth: an object-centric overview that groups a capture by host, file, credential, and message instead of by packet.
- The task: learn NetworkMiner's tabs well enough to pull that overview out of an unfamiliar capture in minutes, then run that skill against six real capture files covering host fingerprinting, MAC correlation, credential extraction, file and image carving, anomaly detection, and DNS-level identification.

## How it works

- **Step 1: know what NetworkMiner is built for, and when to reach for it instead of Wireshark.**

| Capability | Description |
|---|---|
| Traffic sniffing | Intercepts, sniffs, and logs packets passing through the network |
| Parsing PCAP files | Parses a capture file and shows packet content in detail |
| Protocol analysis | Identifies the protocols present in a parsed capture |
| OS fingerprinting | Identifies host operating systems from capture data, relying on the Satori and p0f fingerprinting databases |
| File extraction | Extracts images, HTML files, and emails from a parsed capture |
| Credential grabbing | Extracts credentials from a parsed capture |
| Cleartext keyword parsing | Extracts cleartext keywords and strings from a parsed capture |

  NetworkMiner runs in two modes. Sniffer mode captures live traffic directly, but this feature exists on Windows only and isn't as reliable as a dedicated sniffer, so it's not the recommended way to use the tool. Packet parsing mode, the mode this room focuses on, ingests an existing capture and surfaces a quick overview, the "low hanging fruit," before a deeper investigation starts elsewhere.

| Pros | Cons |
|---|---|
| OS fingerprinting | Not useful for active sniffing |
| Easy file extraction | Not built for large pcap investigation |
| Credential grabbing | Limited filtering |
| Cleartext keyword parsing | Not built for manual, packet-by-packet traffic investigation |
| Fast overall overview | |

- **Step 2: know exactly where NetworkMiner's strengths stop and Wireshark's begin.** Both tools share a GUI, cross-platform support, sniffing capability, and PCAP handling, but they diverge sharply on depth versus breadth.

| Feature | NetworkMiner | Wireshark |
|---|---|---|
| Purpose | Quick overview, traffic mapping, data extraction | In-depth analysis |
| OS fingerprinting | Yes | No |
| Parameter/keyword discovery | Yes | Manual |
| Credential discovery | Yes | Yes |
| File extraction | Yes | Yes |
| Filtering options | Limited | Extensive |
| Packet decoding | Limited | Extensive |
| Protocol analysis | No | Yes |
| Payload analysis | No | Yes |
| Statistical analysis | No | Yes |
| Host categorization | Yes | No |

  The best practice this room teaches follows directly from that table: record traffic for offline analysis, get a quick overview with NetworkMiner first, then go deep with Wireshark once something worth investigating has been identified.

- **Step 3: tour the interface before opening a capture.** The File menu loads a pcap by browsing, dragging and dropping, or receiving one over IP. The Tools menu clears the dashboard and removes loaded data. The Help menu shows version and update information. The Case Panel, on the right side of the window, lists every loaded capture and lets an analyst reload, remove, or right-click a file to view its metadata (parsing time, data link layer type, and other capture-level details) through Show Metadata.

  [Screenshot placeholder: Case Panel with a loaded pcap and the Show Metadata dialog open]

- **Step 4: read the Hosts tab for identity and fingerprinting.** This tab lists every identified host in the capture along with IP address, MAC address, OS type, open ports, sent and received packet counts, and incoming/outgoing sessions. OS fingerprinting here depends on the Satori and p0f projects, and the MAC address database traces back to the mac-ages project. Hosts can be sorted and color-coded, and the right-click menu copies any selected value directly.

- **Step 5: read the Sessions and DNS tabs for traffic shape.** Sessions lists every detected session with frame number, client and server address, source and destination port, protocol, and start time, searchable with `ExactPhrase`, `AllWords`, `AnyWord`, or `RegExe` input types. DNS lists every DNS query with frame number, timestamp, client and server, ports, IP TTL (Time To Live), DNS response time, transaction ID and type, and the query and answer content itself, with the same search bar available.

- **Step 6: pull cleartext credentials directly.** The Credentials tab extracts usernames, passwords, and hashes from protocols including Kerberos, NTLM, RDP cookies, HTTP cookies, HTTP requests, IMAP, FTP, SMTP, and MS SQL. Extracted hashes decrypt with external tools like Hashcat or John the Ripper. The right-click menu copies a username or password value in one click, which matters when a hash runs to several hundred characters.

- **Step 7: know the remaining tabs before starting an investigation.**

| Tab | What it shows |
|---|---|
| Files | Extracted files: frame number, filename, extension, size, source/destination address and port, protocol, timestamp, and reconstructed path |
| Images | Extracted images, with source and destination address and file path shown on hover |
| Parameters | Extracted parameters: name, value, frame number, source/destination host and port, timestamp |
| Keywords | Extracted keyword matches with frame number, timestamp, keyword, context, and source/destination host and port. Filtering here requires reloading the case files after adding a keyword |
| Messages | Extracted emails, chats, and messages: frame number, source/destination host, protocol, sender, receiver, timestamp, and size, with attachments viewable through the built-in viewer |
| Anomalies | Detected anomalies. NetworkMiner isn't an IDS (Intrusion Detection System), but its developers added specific detection for the EternalBlue exploit and spoofing attempts |

- **Step 8: know what changed between version 1.6 and 2.7, because the room's VM ships both.** Feature parity between versions isn't total, and a couple of exercise questions in this room only answer correctly in one specific version.

| Feature | Version 1.6 | Version 2.7 |
|---|---|---|
| MAC address conflict detection | Not available | Available |
| Detailed sent/received packet breakdown | Available | Not available |
| Frame-level processing (frame count and detail) | Available | Not available |
| Extended parameter capture | Captures fewer parameters | Captures more parameters |
| Single-tab cleartext data view | Available (can't be matched back to individual packets) | Not available |

- **Step 9: run all of it against six real capture files.** [Screenshot placeholder: Hosts tab expanded for `mx-3.pcap` showing MAC address correlation]

  **`mx-3.pcap`, host fingerprinting and MAC correlation:**

| Question | Finding |
|---|---|
| Total number of frames | 460 |
| IP addresses sharing a MAC address with host 145.253.2.203 | 2 |
| Packets sent from host 65.208.228.223 | 72 |
| Webserver banner under host 65.208.228.223 | Apache |

  **`mx-4.pcap`, credential extraction:**

| Question | Finding |
|---|---|
| Extracted username for the 02694W-WIN10 host | `#B\Administrator` |
| Extracted NTLM hash for that user | `$NETNTLMv2$#B$136B077D942D9A63$FBFF3C253926907AAAAD670A9037F2A5$01010000000000000094D71AE38CD60170A8D571127AE49E00000000020004003300420001001E003000310035003600360053002D00570049004E00310036002D004900520004001E0074006800720065006500620065006500730063006F002E0063006F006D0003003E003000310035003600360073002D00770069006E00310036002D00690072002E0074006800720065006500620065006500730063006F002E0063006F006D0005001E0074006800720065006500620065006500730063006F002E0063006F006D00070008000094D71AE38CD601060004000200000008003000300000000000000000000000003000009050B30CECBEBD73F501D6A2B88286851A6E84DDFAE1211D512A6A5A72594D340A001000000000000000000000000000000000000900220063006900660073002F003100370032002E00310036002E00360036002E0033003600000000000000000000000000` |

  This is an NTLMv2 authentication exchange captured off the wire, not a stored password. Cracking it (with Hashcat or John the Ripper) recovers the plaintext offline; the capture alone only proves the credential exchange happened.

  [Screenshot placeholder: Credentials tab showing the extracted NTLMv2 hash for `02694W-WIN10`]

  **`mx-7.pcap` and `mx-9`, file carving, anomaly detection, and messages:**

| Question | Finding |
|---|---|
| Linux distro named in the file at frame 63602 (fallback: 63075) | CentOS |
| Name and surname in the file at frame 76469 (fallback: 75942) | Ned Flanders |
| Source address of image `ads.bmp.2E5F0FD9[1].bmp` | 80.239.178.187 |
| Frame number of the possible TLS anomaly | 36255 |
| Platform that sent the email starting "You have more..." | Facebook |
| Email address of Branson Matheson | branson@sandsite.org |

  [Screenshot placeholder: Anomalies tab showing the flagged TLS anomaly at frame 36255]

  **`case1.pcap`, cross-version host and session investigation:**

| Question | Finding |
|---|---|
| Full OS name of host 131.151.37.122 | Windows - Windows NT 4 |
| Bytes sent by client (`*.32.91`) through port 1065 | 192 |
| Bytes sent back by server (`*.37.122`) through port 143 | 20769 |
| Sequence number of frame 9 | `2AD77400` |
| Number of detected content types | 2 |

  The port-1065 and content-type questions answer cleanly in version 2.7.2. The frame-9 sequence number question only works in version 1.6, since frame-level detail was removed starting in version 2.0, matching Step 8's version comparison directly.

  **`case2.pcap`, file and image carving:**

| Question | Finding |
|---|---|
| USB product's brand name | ASIX |
| Phone model | Lumia 535 |
| Source IP of the fish image | 50.22.95.9 |
| Password of homer.pwned.se@gmx.com | spring2015 |
| DNS query of frame 62001 | pop.gmx.com |

  [Screenshot placeholder: Files tab filtered for the USB product image in `case2.pcap`]

## Why it matters

- NetworkMiner's object-centric view (hosts, files, credentials, messages) answers the first question in almost any investigation faster than packet-by-packet inspection can: who's on this network, what did they send, and does anything already look wrong. That speed is the entire reason to reach for it before Wireshark, not instead of it.
- The version 1.6 versus 2.7 split in this room isn't trivia. A real investigation can hit the same wall: a feature an analyst expects (frame-level detail, MAC conflict detection) might only exist in one specific tool version, and knowing that in advance saves time mid-investigation instead of costing it.
- Credential extraction here produces a hash, not a password. Treating a captured NTLMv2 exchange as "the credential" instead of "proof an authentication attempt happened, pending cracking" is the kind of gap that turns an accurate finding into an inaccurate report.
- NetworkMiner explicitly isn't an IDS, and its Anomalies tab only catches a couple of specific, hardcoded patterns like EternalBlue. Relying on it to catch everything wrong in a capture would be a mistake; its actual job is triage, pointing an analyst toward what Wireshark needs to confirm.

## Key takeaways

- NetworkMiner is a Network Forensic Analysis Tool, built for a fast, object-centric overview of a capture (hosts, sessions, files, credentials, messages), not for deep packet-level inspection.
- It runs in two modes: an unreliable Windows-only sniffer, and a packet-parsing mode that's the actual recommended use case for this tool.
- Compared to Wireshark, NetworkMiner trades filtering depth, protocol analysis, and payload inspection for OS fingerprinting, host categorization, and fast keyword/parameter discovery. Neither tool replaces the other; the standard workflow is NetworkMiner first, Wireshark second.
- The Hosts, Sessions, and DNS tabs answer "who's here and what are they doing." Credentials, Files, Images, Parameters, Keywords, and Messages answer "what did they send." Anomalies flags a narrow set of known patterns, not a general threat feed.
- Version 1.6 and 2.7 aren't strictly better-or-worse: 2.7 adds MAC conflict detection and richer parameter capture, while 1.6 retains frame-level detail and packet-level breakdown that 2.7 dropped.
- Across `mx-3.pcap`, `mx-4.pcap`, `mx-7.pcap`, `mx-9`, `case1.pcap`, and `case2.pcap`, this investigation pulled host fingerprints, an NTLMv2 credential exchange, carved files and images, a flagged TLS anomaly, and full message content, all without opening a single packet manually.
- This room sets up the natural next step from here: Wireshark for depth, Snort for signature-based detection, and Brim for log-centric correlation.
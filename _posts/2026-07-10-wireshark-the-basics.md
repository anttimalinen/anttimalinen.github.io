---

title: "Wireshark: The Basics"

date: 2026-07-10 16:00 +0300

categories: [Foundations, Networking]

tags: [wireshark, packet-capture, networking, pcap, osi-model, soc]

description: "How Wireshark's GUI, packet dissection, navigation tools, and basic display filters turn a 58,000-packet capture into the handful of packets that answer an actual investigation."

---

## Description

- Wireshark is an open-source, cross-platform packet analyzer that reads live network traffic and PCAP (Packet Capture) files. It is not an Intrusion Detection System (IDS): it decodes and displays packets, but it does not flag anomalies or modify anything it captures. Spotting a problem depends on the analyst reading the capture, not the tool.
- Source: TryHackMe, room "Wireshark: The Basics." This post covers the GUI layout, how Wireshark dissects a packet through the OSI (Open Systems Interconnection) model, the navigation tools built for large captures, and the basic filters that cut a capture down to what matters. The lab provides two capture files: `http1.pcapng` for following the walkthrough, and `Exercise.pcapng` for answering the room's questions.

## The problem

- Without navigation and filtering skill, a capture file is 58,620 packets of noise. The tool surfaces every field of every packet; it does not tell an analyst which of those fields matters for the incident at hand.
- Wireshark only reads and decodes packets. It never flags an anomaly the way an IDS does, so finding a session hijack, an exfiltrated file, or a hidden comment inside a packet takes navigation skill, not an open tool.
- The task: dissect one packet layer by layer, learn the navigation tools built for large captures, and apply the filters that turn 58,620 packets into the handful worth reading.

## How it works

- **Step 1: know the five GUI sections before opening a capture.**

| Section | What it does |
|---|---|
| Toolbar | Menus and shortcuts for sniffing, filtering, sorting, summarizing, exporting, merging |
| Display Filter Bar | Where filter queries go |
| Recent Files | Previously opened captures, reopens with a double-click |
| Capture Filter and Interfaces | Capture filters and available sniffing points (network interfaces like `lo`, `eth0`, `ens33`) |
| Status Bar | Tool status, active profile, packet counts |

- **Step 2: once a capture loads, read it across three panes.**

| Pane | Shows |
|---|---|
| Packet List | One-line summary per packet: source, destination, protocol, info |
| Packet Details | Full protocol breakdown of the selected packet |
| Packet Bytes | Hex and ASCII view of the selected packet, highlighted to match whatever is selected in Packet Details |

  Wireshark colors packets by protocol and by condition. The default ruleset marks most traffic green, so anomalies and unfamiliar protocols stand out against that baseline. Coloring rules come in two types: temporary rules that last only the current session, and permanent rules saved to a profile. Live capture starts and stops from the toolbar's shark icon: blue starts, red stops, green restarts. Two capture files merge into one through File > Merge. File-level metadata, including the SHA256 hash, capture time, and any saved comments, sits under Statistics > Capture File Properties.

- **Step 3: dissect a packet through the OSI model.**

| Layer shown in Wireshark | OSI layer | What it reveals |
|---|---|---|
| Frame | Physical | The packet number and capture-level metadata |
| Source [MAC] | Data Link | Source and destination MAC addresses |
| Source [IP] | Network | Source and destination IPv4 addresses |
| Protocol | Transport | TCP or UDP, source and destination ports |
| Protocol Errors | Transport (continued) | TCP segments that needed reassembly |
| Application Protocol | Application | Protocol-specific details (HTTP, FTP, SMB) |
| Application Data | Application (continued) | The application-specific payload itself |

- **Step 4: use the navigation tools built for a capture with tens of thousands of packets.**

| Tool | What it does |
|---|---|
| Go to Packet | Jumps straight to a packet number |
| Find Packet | Searches by display filter, hex, string, or regex, across the packet list, details, or bytes pane. Case insensitive by default |
| Mark Packet | Flags a packet black for the current session; marks do not survive closing the file |
| Packet Comment | Attaches a note to a packet that stays saved inside the capture file |
| Export Packets | Saves a chosen subset of packets to a new file |
| Export Objects | Pulls files transferred inside a stream, limited to DICOM, HTTP, IMF, SMB, and TFTP |
| Time Display Format | Switches from seconds-since-capture-start to a readable format like UTC |

  Expert Info sorts anomalies into severities:

| Severity | Colour | Meaning |
|---|---|---|
| Chat | Blue | Normal workflow information |
| Note | Cyan | Notable events, like application error codes |
| Warn | Yellow | Unusual error codes or problem statements |
| Error | Red | Malformed packets |

- **Step 5: filter the capture down to what matters.** Wireshark filters traffic two ways. A capture filter decides what gets recorded during a live sniff. A display filter decides what's shown from packets already captured.

| Option | What it does |
|---|---|
| Apply as Filter | Filters on one clicked field |
| Conversation Filter | Filters every packet tied to one IP-and-port conversation instead of one field |
| Colourise Conversation | Highlights a conversation without hiding the rest |
| Prepare as Filter | Builds the query into the filter bar without running it, so more conditions can be added first |
| Apply as Column | Adds a clicked field as a visible column in the packet list |
| Follow Stream | Reconstructs a TCP, UDP, or HTTP stream into its application-level view, including any cleartext usernames or passwords it carried |

  Basic query syntax covers three cases:

| Filter type | Syntax | Example |
|---|---|---|
| Protocol name | `<protocol>` | `http` |
| Protocol port | `tcp.port == <port>` or `udp.port == <port>` | `tcp.port == 80` |
| IP address | `ip.addr == <IP>` | `ip.addr == 192.168.1.2` |

- **Step 6: run it against `Exercise.pcapng`.** 
  - The capture file comment held the flag `TryHackMe_Wireshark_Demo`.
  - Total packet count: 58,620. SHA256 hash of the file: `f446de335565fb0b0ee5e5a3266703c778b2f3dfad7efeaeccb2da5641a6d6eb`.
  - A string search for `r4w` in packet details surfaced artist `r4w8173`.
  - Packet 12's comment, run through `md5sum`, resolved to `911cd574a42865a956ccde2d04495ebf`.
  - Export Objects pulled a `.txt` file out of the capture naming the alien `PACKETMASTER`.
  - Expert Info logged 1,636 warnings.
  - Filtering on `http` cut the capture to 1,089 displayed packets.
  - Following the HTTP stream on packet 33790 turned up a server response listing 3 artists. The second was `Blad3`.

## Why it matters

- An analyst who can't dissect a packet layer by layer can't tell a legitimate TCP retransmission from an attacker probing for a service. The OSI breakdown Wireshark gives for free only pays off once someone knows which layer holds the answer to their question.
- Navigation tools matter at scale. A 58,620-packet file makes scrolling useless; Find Packet, Mark Packet, and Expert Info exist because reading every line by hand does not scale past a few dozen packets.
- Filtering is the daily-driver skill. Capture filters, display filters, Follow Stream, and Conversation Filter turn an unmanageable capture into the ten packets that answer a specific incident question, which is the actual job of a SOC analyst staring at a pcap during an investigation.

## Key takeaways

- Wireshark reads and decodes; it does not detect. Every finding depends on the analyst's own filtering and dissection skill, not the tool.
- A packet breaks into layers matching the OSI model: Frame, MAC, IP, Protocol (with any reassembly errors), Application Protocol, and Application Data.
- Go to Packet, Find Packet, Mark Packet, Packet Comments, and Expert Info exist to make a capture with tens of thousands of packets searchable instead of scrollable.
- Apply as Filter, Conversation Filter, Prepare as Filter, and Follow Stream each answer a different question: one field, one conversation, a queued query, or a full reconstructed session.
- Basic display filter syntax covers three cases: protocol name, `tcp.port`/`udp.port`, and `ip.addr`.
- This room sets up "Wireshark: Packet Operations" next, going deeper into capture-versus-display filter syntax and packet-level operations.
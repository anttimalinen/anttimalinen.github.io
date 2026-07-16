---

title: "Wireshark: Packet Operations"

date: 2026-07-11 16:00 +0300

categories: [Foundations, Networking]

tags: [wireshark, packet-filtering, display-filters, network-statistics, pcap, soc]

description: "How Wireshark's Statistics menu, capture and display filter syntax, protocol-level filters, and advanced operators turn an 81,420-packet capture into a targeted investigation. The second room in the Wireshark trio."

---

## Description

- Wireshark: Packet Operations sits second in TryHackMe's Wireshark trio, between "Wireshark: The Basics" and "Wireshark: Traffic Analysis." The first room covered navigating and dissecting a single packet. This one covers the tools that work across an entire capture: the Statistics menu for a bird's-eye view of what a pcap contains, and query-based filtering for narrowing tens of thousands of packets down to the handful that answer a specific question.
- Source: TryHackMe, room "Wireshark: Packet Operations." This post covers the Statistics summary and protocol-detail views, the difference between capture and display filters, comparison and logical operators, protocol-specific filters for IP, TCP/UDP, HTTP, and DNS, the advanced filtering functions (`contains`, `matches`, `in`, `upper`, `lower`, `string`), and the bookmarks, filter buttons, and profiles that make a filter reusable across investigations. The room's domains and IP addresses are for reference only and are never meant to be interacted with directly.

## The problem

- Dissecting one packet at a time, the skill covered in "Wireshark: The Basics," does not scale to an 81,420-packet capture. An analyst needs a way to see the shape of a whole capture before deciding which packet is worth opening in the first place.
- Filtering by right-clicking a field, the basic approach from the first room, breaks down once a question gets specific. Which packets carry a TTL under 10. Which packets use one of three nonstandard ports. Which HTTP responses came from an Apache server no matter how the header capitalizes the name. Answering any of those means writing a query, not clicking a field.
- The task: use the Statistics menu to build a hypothesis about what a capture holds, then use capture filters, display filters, comparison and logical operators, protocol-specific filters, and advanced functions to test that hypothesis against the packets themselves.

## How it works

- **Step 1: get the big picture before opening a single packet.**

| Statistics option | What it shows | Menu path |
|---|---|---|
| Resolved Addresses | IP addresses paired with the hostnames captured in DNS answers | Statistics > Resolved Addresses |
| Protocol Hierarchy | A tree view of every protocol in the capture, by packet count and percentage | Statistics > Protocol Hierarchy |
| Conversations | Traffic between two endpoints, shown in Ethernet, IPv4, IPv6, TCP, and UDP formats | Statistics > Conversations |
| Endpoints | Unique values for a single field (Ethernet, IPv4, IPv6, TCP, UDP), rather than paired conversations | Statistics > Endpoints |

  Resolved Addresses only shows a hostname if the capture contains an actual DNS answer for it. Wireshark cannot supply a hostname for an IP that was never looked up. Protocol Hierarchy carries the right-click-to-filter behavior from the first room, so an oversized slice of one protocol turns into a filter without typing a query. Endpoints adds two extras worth knowing: a "Name resolution" toggle that converts the first three bytes of a MAC address into a manufacturer name using IEEE data, and IP/port name resolution, off by default, enabled under Edit > Preferences > Name Resolution, after which it shows up in the packet list pane and in the Conversations and Endpoints views. GeoIP mapping goes further still, plotting source and destination addresses on a map, but it needs a MaxMind database configured under that same Preferences menu and an active internet connection to render. The lab machine has neither.

- **Step 2: narrow the Statistics view to one protocol at a time.**

| View | Menu path | What it surfaces |
|---|---|---|
| IPvX Statistics | Statistics > IPv4/IPv6 Statistics | Packets filtered to a single IP version |
| DNS | Statistics > DNS | rcode (response code), opcode, class, query type, per-service query stats, response time |
| HTTP | Statistics > HTTP | Request and response codes, original request lines |

  IPvX Statistics matters once a capture mixes IPv4 and IPv6 traffic and a question only concerns one version. DNS statistics expose response time per query, which is how a stalled or unusually slow DNS lookup surfaces before anyone opens a single packet. HTTP statistics do the same job for web traffic, breaking every request and response code down into a tree by count and percentage.

- **Step 3: know which filter type to reach for.**

| Filter type | Applies to | Changeable mid-capture | Typical use |
|---|---|---|---|
| Capture filter | Traffic being recorded | No, set before capture starts | Saving only a specific slice of live traffic, mostly used by experienced analysts |
| Display filter | Traffic already captured | Yes | Investigating an existing capture; supports far more protocols than capture filters |

  A capture filter and a display filter for the same idea use different syntax. A capture filter for port 80 traffic reads `tcp port 80`. The equivalent display filter reads `tcp.port == 80`. The two are not interchangeable: a display filter expression will not work as a capture filter, and the reverse holds too.

  Capture filter syntax builds from three pieces: a scope (`host`, `net`, `port`, `portrange`), a direction (`src`, `dst`, `src or dst`, `src and dst`), and a protocol (`ether`, `wlan`, `ip`, `ip6`, `arp`, `rarp`, `tcp`, `udp`). Display filter syntax works on a different scale: it targets one of roughly 3,000 supported protocols using dot notation to drill into a specific field, and the Display Filter Expression builder (Analyse > Display Filter Expression) lists every field, its accepted value type, and any predefined values, since memorizing all 3,000 protocols isn't a realistic goal for anyone.

- **Step 4: apply comparison operators.**

| English | Symbol | Meaning | Example |
|---|---|---|---|
| eq | == | Equal | `ip.src == 10.10.10.100` |
| ne | != | Not equal | `ip.src != 10.10.10.100` |
| gt | > | Greater than | `ip.ttl > 250` |
| lt | < | Less than | `ip.ttl < 10` |
| ge | >= | Greater than or equal to | `ip.ttl >= 0xFA` |
| le | <= | Less than or equal to | `ip.ttl <= 0xA` |

  Wireshark accepts decimal and hexadecimal values in the same filter, so `ip.ttl >= 0xFA` and `ip.ttl >= 250` return the same result.

- **Step 5: combine conditions with logical operators.**

| English | Symbol | Meaning | Example |
|---|---|---|---|
| and | && | Logical AND | `(ip.src == 10.10.10.100) AND (ip.src == 10.10.10.111)` |
| or | \|\| | Logical OR | `(ip.src == 10.10.10.100) OR (ip.src == 10.10.10.111)` |
| not | ! | Logical NOT | `!(ip.src == 10.10.10.222)` |

  `ip.src != 10.10.10.222` and `!(ip.src == 10.10.10.222)` look equivalent. The first form is deprecated and can return inconsistent results. `!(value)` is the form to trust.

- **Step 6: read the filter bar's own feedback.** The filter toolbar colors every query as it's typed. Green means valid, red means invalid, yellow means the filter works but is unreliable and worth rewriting. Filters are written lowercase, and autocomplete breaks each protocol down field by field with a dot, the same dot notation used throughout every filter in this room.

- **Step 7: filter at the Network layer with IP fields.**

| Filter | Result |
|---|---|
| `ip` | All IP packets |
| `ip.addr == 10.10.10.111` | All packets containing IP 10.10.10.111, in either direction |
| `ip.addr == 10.10.10.0/24` | All packets from the 10.10.10.0/24 subnet |
| `ip.src == 10.10.10.111` | Packets originating from 10.10.10.111 |
| `ip.dst == 10.10.10.111` | Packets sent to 10.10.10.111 |

  `ip.addr` ignores direction. `ip.src` and `ip.dst` don't; they only match traffic flowing that specific way, which matters the moment a question asks who sent something rather than who was involved.

- **Step 8: filter at the Transport and Application layers.**

| Filter | Result |
|---|---|
| `tcp.port == 80` | TCP packets on port 80 |
| `udp.port == 53` | UDP packets on port 53 |
| `tcp.srcport == 1234` | TCP packets originating from port 1234 |
| `udp.srcport == 1234` | UDP packets originating from port 1234 |
| `tcp.dstport == 80` | TCP packets sent to port 80 |
| `udp.dstport == 5353` | UDP packets sent to port 5353 |

| Filter | Result |
|---|---|
| `http` | All HTTP packets |
| `dns` | All DNS packets |
| `http.response.code == 200` | HTTP packets with response code 200 |
| `dns.flags.response == 0` | DNS requests |
| `http.request.method == "GET"` | HTTP GET requests |
| `dns.flags.response == 1` | DNS responses |
| `http.request.method == "POST"` | HTTP POST requests |
| `dns.qry.type == 1` | DNS "A" record queries |

- **Step 9: reach for advanced operators once a basic filter isn't precise enough.**

| Function | Type | What it does | Example |
|---|---|---|---|
| `contains` | Comparison operator | Case-sensitive search for a value inside a field | `http.server contains "Apache"` |
| `matches` | Comparison operator | Case-insensitive regular expression match | `http.host matches "\.(php\|html)"` |
| `in` | Set membership | Matches a field against a defined set of values | `tcp.port in {80 443 8080}` |
| `upper` | Function | Converts a string field to uppercase before comparing | `upper(http.server) contains "APACHE"` |
| `lower` | Function | Converts a string field to lowercase before comparing | `lower(http.server) contains "apache"` |
| `string` | Function | Converts a non-string field, like a frame number, into a string for pattern matching | `string(frame.number) matches "[13579]$"` |

  `contains` behaves like the Find Packet search from the first room, scoped to one field instead of the whole packet. `matches` trades that precision for pattern flexibility, at the cost of case sensitivity and the occasional false match on a complex pattern. `in` replaces a chain of OR statements: `tcp.port in {80 443 8080}` does the same job as three separate `tcp.port ==` filters joined with `or`, in one line.

- **Step 10: save the filters worth reusing.** Bookmarks and filter buttons both live on the filter toolbar. A bookmark saves a filter for recall from a dropdown. A filter button goes further, adding a labeled, clickable shortcut for a filter used often enough to deserve one click instead of a retype. Profiles solve a wider problem: switching between investigation cases usually means switching coloring rules and filter buttons too, and a profile bundles both into one saved configuration under Edit > Configuration Profiles, so working three cases in a day doesn't mean rebuilding the same setup three times.

- **Step 11: run all of it against `Exercise.pcapng`.**

  Statistics summary findings:
  - The hostname starting with "bbc" resolved to 199.232.24.81.
  - The capture held 435 IPv4 conversations.
  - The endpoint with the "Micro-St" (Micro-Star) manufacturer MAC prefix transferred 7,474 KB.
  - Four IP addresses in the capture geolocated to Kansas City.
  - The IP address tied to the "Blicnet" AS organization was 188.246.82.7.

  Statistics protocol detail findings: the IPv4 view surfaced the single most-contacted destination address in the capture, the DNS view exposed the slowest query response time recorded, and the HTTP view broke down exactly how many requests went to `rad[.]msn[.]com`. The room asks for these as exact values read straight off the Statistics panes rather than computed by hand, so the number worth recording here is the process: open Statistics > IPv4 Statistics, Statistics > DNS, and Statistics > HTTP in turn and read the answer directly from each tree.

  Protocol filter findings:
  - `ip` matched 81,420 packets.
  - `ip.ttl < 10` matched 66 packets.
  - `tcp.port == 4444` matched 632 packets.
  - `http.request.method == "GET" && tcp.port == 80` matched 527 packets.
  - `dns.qry.type == 1` matched 51 type A queries.

  Advanced filtering findings:
  - Filtering Microsoft IIS servers and excluding port 80 left 21 packets.
  - Filtering Microsoft IIS servers running version 7.5 returned 71 packets.
  - `tcp.port in {3333 4444 9999}` matched 2,235 packets total.
  - Packets with an even TTL numbered 77,289.
  - Switching to the "Checksum Control" profile and reading Bad TCP Checksum packets returned 34,185.
  - Running the room's pre-built filter button displayed 261 packets.

## Why it matters

- Statistics turns an unopened pcap into a hypothesis. Protocol Hierarchy shows what's overrepresented, Conversations and Endpoints show who's talking to whom, and DNS and HTTP statistics show where the slow or heavy requests sit, all before a single packet gets opened. That hypothesis is what turns a blind scroll through 81,420 packets into a targeted filter.
- Capture filters and display filters solve different problems, and mixing up their syntax wastes time during a live investigation. Knowing that a capture filter locks in before recording starts, while a display filter can be rewritten as many times as a question changes, decides which one an analyst reaches for on a live sniff versus an existing pcap.
- The advanced operators exist because real traffic is messy. A server header capitalized as "apache" instead of "Apache" defeats a case-sensitive `contains` filter unless it's wrapped in `lower()`. A set of three nonstandard ports used by one piece of malware is faster to check with `in {}` than with two chained `or` statements. None of these functions are exotic; they're the difference between a filter that works on the lab's clean sample data and one that survives contact with an actual capture.
- Bookmarks, filter buttons, and profiles turn a one-off query into a repeatable process. An analyst covering multiple cases in a shift benefits the same way a SOC playbook does: build the filter once, save it, and stop rebuilding it from memory every time a similar case lands on the desk.

## Key takeaways

- The Statistics menu (Resolved Addresses, Protocol Hierarchy, Conversations, Endpoints, IPvX Statistics, DNS, HTTP) gives a summary of a capture before any packet gets opened, which is how a hypothesis gets built instead of guessed.
- Capture filters lock in before recording starts and use a scope-direction-protocol syntax (`tcp port 80`). Display filters work on an existing capture, stay editable, and use dot notation against roughly 3,000 supported protocols (`tcp.port == 80`). The two syntaxes are not interchangeable.
- Comparison operators (`==`, `!=`, `>`, `<`, `>=`, `<=`) and logical operators (`&&`, `||`, `!`) combine to build precise queries. `!=` is deprecated for reliability reasons; `!(value)` is the form to use instead.
- IP filters (`ip.addr`, `ip.src`, `ip.dst`), TCP/UDP filters (`tcp.port`, `udp.port`, `srcport`, `dstport`), and HTTP/DNS filters (`http.request.method`, `http.response.code`, `dns.qry.type`, `dns.flags.response`) cover the Network, Transport, and Application layers respectively.
- `contains`, `matches`, `in`, `upper`, `lower`, and `string` handle the cases a basic equality filter can't: case sensitivity, pattern matching, set membership, and type conversion.
- Bookmarks, filter buttons, and profiles turn a filter built once into a filter reused across every future investigation that needs it.
- This room sets up "Wireshark: Traffic Analysis" next, applying every filter and statistics view covered here to an actual suspicious-activity investigation.
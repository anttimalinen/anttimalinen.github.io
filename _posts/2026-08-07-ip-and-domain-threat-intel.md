---

title: IP and Domain Threat Intel

date: 2026-08-07 21:00 +0300

categories: [Foundations, Threat Intelligence]

tags: [dns-enrichment, ip-enrichment, whois-rdap, asn-analysis, geoip, vpn-proxy-detection]

description: "A TryHackMe SOC Level 1 writeup on enriching IPs and domains through DNS records, WHOIS/RDAP, ASN and geolocation analysis, Shodan and Censys service exposure, and VPN/Tor detection, closed out with an APT infrastructure challenge."

---

## Description

"IP and Domain Threat Intel" is the third room in the SOC Level 1 threat intelligence track, sitting after "Intro to Cyber Threat Intel" and "File and Hash Threat Intel." The first two rooms teach an analyst to read a file and decide whether it is dangerous. This one hands the analyst a bare indicator instead, an IP address or a domain name with no file attached, and asks the same question: is this worth escalating?

The room frames every alert around three steps: verify, enrich, decide. Verification confirms the indicator is real. Enrichment builds context around it, and that context is what turns a raw alert into something an L1 analyst can act on. This room spends almost all of its time on enrichment, because a raw IP or domain tells you close to nothing on its own. `2.58.56.50` means nothing until you know it sits behind a Tor-friendly bulletproof host in the Netherlands and has been named in VirusTotal comments as Remcos infrastructure. `purematrixa[.]com` means nothing until you know it was registered one day before it showed up in your SIEM.

The room supplies a downloadable archive of exported threat intel for the practical exercises, and it explains why upfront: live indicators rot fast. A domain that resolves to a malicious IP today might point somewhere else next week, and an ASN flagged as bulletproof hosting today might get reassigned or sanctioned by the time you read this. Static, timestamped exports let the room ask fixed questions with fixed answers, while still pointing analysts toward the live tools, `nslookup.io`, `whois.domaintools.com`, VirusTotal, `bgp.tools`, Shodan, Censys, `crt.sh`, IP2Proxy, and Spur, that a working SOC runs day to day.

Five tasks build the skill in order: domain enrichment through DNS and WHOIS, IP enrichment through reputation and ASN lookups, service exposure through Shodan and Censys, VPN and Tor detection through IP2Proxy and Spur, and a closing challenge that strings all four together against a real APT-linked domain. Every practice question in this writeup came back correct, and every indicator below is defanged the way the room presents it, with brackets around the dot.

## The problem

An analyst opens a SIEM alert and finds one IP address and nothing else. No file, no hash, no process tree. Just a string of numbers that could belong to almost anything.

That IP could be a shared AWS load balancer serving a thousand unrelated customers, or it could be a dedicated command-and-control server rented for forty dollars a month from a host that advertises itself on the same forums where the malware got built. Somewhere between those two extremes sits a compromised home router, repurposed as a relay without its owner ever noticing. Nothing in the alert distinguishes between these cases, and treating them the same way is expensive either direction. Block the AWS range and legitimate traffic breaks. Ignore the compromised router and the intrusion continues.

Mandiant's M-Trends 2026 report puts a number on how much that ambiguity costs. Global median dwell time, the stretch between initial compromise and detection, rose to fourteen days in 2025, up from eleven the year before. Exploitation of internet-facing systems stayed the leading initial infection vector for a sixth straight year, at 32 percent of intrusions Mandiant could trace. More striking is what Mandiant found about the handoff between an initial access broker and whoever buys the access next: that gap shrank from over eight hours in 2022 to roughly 22 seconds in 2025. Once a foothold exists, the infrastructure behind it gets used almost immediately. An analyst who cannot enrich an IP fast enough to tell reputable from rented is working against a window measured in seconds, not days.

Verizon's 2026 Data Breach Investigations Report adds a second layer to the same problem. The report singles out residential proxies, malicious traffic routed through legitimate consumer IP addresses, as one of the most persistent tools in the attacker toolkit, because that traffic looks identical to a real user on a home connection to most defenses. A login from a residential IP in the right country and city can pass every geographic check a SIEM runs and still be an attacker sitting behind a VPN. The room's own VPN detection task builds around this scenario, and it exists because geography alone stopped being a reliable signal years ago.

Domains carry a parallel problem. A brand-new domain registered hours before it appears in a phishing email is a strong signal on its own, but an analyst who does not check WHOIS or RDAP data never sees that signal. A domain using Cyrillic characters to impersonate a Latin brand name renders identically in a browser address bar, and an analyst who does not convert it to Punycode never catches the substitution. The room's job is to close both gaps: teach the tools that turn a bare indicator into a decision, fast enough to matter.

## How it works

**Step 1: Read the workflow before touching a tool**

Every task in this room maps back to verify, enrich, decide. Verification is usually already done by the time an alert lands in the queue, a SIEM rule fired or an EDR flagged a connection. Enrichment is the work this room teaches: pulling DNS records, WHOIS data, reputation scores, ASN ownership, geolocation, exposed services, and VPN status until the indicator has enough context to support a decision. The room also names its prerequisites directly, "Intro to Cyber Threat Intel" and "File and Hash Threat Intel," and that ordering matters. This room assumes an analyst already knows how to triage a suspicious file. It builds infrastructure analysis on top of that foundation rather than repeating it.

**Step 2: Resolve DNS records to see what a domain points to**

DNS is the layer that turns a name like `tryhackme.com` into an address a machine can route to, and two record types carry most of the useful signal for a SOC analyst.

| Record type | What it reveals | Red flag |
|---|---|---|
| A / AAAA | The IPv4 or IPv6 address the domain resolves to | Resolves to a known bad ASN, a residential range, or a bulletproof host |
| TXT | Mail security settings (SPF, DKIM) and third-party tool integrations | Empty records, or a faked DKIM signature staged for a phishing campaign |

A legitimate domain like `tryhackme.com` resolving to an Amazon IP address is unremarkable; huge swaths of the legitimate internet sit behind AWS or a CDN in front of it. The same resolution on a domain nobody has heard of before is worth a second look, because it means the domain's real hosting is hidden behind shared cloud infrastructure until you dig further.

**Step 3: Check WHOIS or RDAP for the domain's age**

Age is one of the cheapest, highest-signal checks available. Attack infrastructure rarely survives more than a few months before takedown or rotation, so a domain registered days ago carries far more weight than one registered a decade ago.

Worth knowing here: the room describes WHOIS as "gradually being replaced by RDAP," but that transition has already run its course for most of the internet. ICANN officially retired the WHOIS requirement for generic top-level domains on January 28, 2025, and by that September, hundreds of gTLD registries had shut off their WHOIS service entirely. RDAP is the default lookup protocol for most gTLDs now, returning structured JSON instead of WHOIS's free-form text, though country-code domains remain a patchwork: some, like `.de`, `.uk`, and `.nl`, run fully on RDAP, while others still lean on legacy WHOIS. An analyst who only knows the WHOIS command syntax and not RDAP is working with a shrinking toolset.

The room's practice scenario puts this to work against a live alert:

| Question | Finding |
|---|---|
| SIEM alert date | June 1, 2026 |
| Domain | `purematrixa[.]com` |
| CDN in use | Cloudflare |
| Domain age at alert time | One day old |

A domain registered one day before it triggers a critical SIEM alert is about as clear a signal as infrastructure analysis produces. No further enrichment was strictly necessary to justify escalating that alert, though the CDN detail still matters: Cloudflare fronting the domain means the true origin server stays hidden until an analyst pivots off other indicators, such as TLS certificate data or leaked backend IPs.

**Step 4: Recognize the DNS-based tricks attackers lean on**

Three techniques show up often enough that every analyst should recognize them on sight.

| Technique | How it works | How to catch it |
|---|---|---|
| CDN abuse | Traffic routed through Cloudflare, Akamai, or Fastly to hide the real origin server | The A record alone won't help; the same CDN IP fronts thousands of sites. Pivot to TLS certs or passive DNS history |
| Typosquatting | Domains like `tryhakme[.]com` or `micros0ft[.]net` rely on a user's typo or a glance that misses the swap | Treat brand lookalikes as high risk by default, but check first whether the real company registered it defensively |
| IDN homograph attacks | Non-ASCII characters (Cyrillic, Greek) substitute for visually identical Latin letters, e.g. a Cyrillic "а" in `tryhаckme[.]com` | Convert to Punycode with a tool like punycoder.com; anything starting with `xn--` contains non-ASCII characters and needs scrutiny |

Homograph attacks in particular have industrialized since they were first demonstrated in 2005. Security researchers and vendors tracking phishing infrastructure in 2026 describe AI-assisted domain generation pushing lookalike registration volume well past what manual brand monitoring can keep up with, and the technique has spread past browser address bars into software package names on registries like npm and PyPI, where a single mistyped dependency can pull in a compromised package instead of the real one. The defensive logic stays the same regardless of where the lookalike shows up: name similarity to something trusted is a reason to look closer, not a reason to trust it.

**Step 5: Pull IP reputation and figure out who owns the network**

Two free lookups cover most of the reputation groundwork a SOC needs: AbuseIPDB for a history of port scans and brute-force reports, and VirusTotal for an overall reputation score plus any community comments analysts have left on the indicator. A single detection on an IP outside known CDN ranges is worth flagging; CDN ranges get noisy hits from shared infrastructure and need more context before acting.

Reputation only tells you what an IP has done. Ownership tells you what kind of infrastructure you're dealing with, and that comes from its Autonomous System, a block of IP prefixes controlled by one organization and identified by an ASN.

| ASN category | What it usually means | Example from the room |
|---|---|---|
| Residential | Home internet connections; alerts here often mean VPN use or a compromised consumer device | AS124888, Vodafone |
| Server hosting | The highest-risk category; commonly rented for malware distribution and C2 | AS215439, PLAY2GO |
| Cloud / CDN | Legitimate services and adversary infrastructure share the same address space | AS16509, Amazon AWS |

The room's IP enrichment practice worked against `2[.]58[.]56[.]50`, flagged as a potential C2 address:

| Question | Finding |
|---|---|
| Country | Netherlands |
| C2 family (per VirusTotal community comments) | Remcos |
| Autonomous System | 1337 Services GmbH |
| BGP.Tools tags | Server Hosting, Tor Services |

That ASN, AS210558, is a real, currently active piece of internet infrastructure worth understanding beyond the room's exercise. BGP.Tools lists it under the operator name RDP.sh with the same two tags the room's answer expects, server hosting and Tor services, and the Tor Project's own community resource lists 1337 Services GmbH among hosts to watch closely because so many Tor relays already run on its ranges. Recent measurements put the network carrying tens of thousands of megabits per second of traffic across both middle and exit relays. None of that makes every IP on the ASN malicious. It does mean an analyst who sees this ASN attached to an alert should treat the geolocation and ownership data with real skepticism, since the network mixes ordinary hosting customers with a large volume of anonymized routing.

Remcos itself stayed active and evolving through the first half of 2026. Security researchers tracked a campaign called SHADOW#REACTOR in January using a multi-stage VBS and PowerShell loader to deploy Remcos through MSBuild, a second wave in February shifting the malware from a store-and-exfiltrate model toward real-time surveillance, and a June campaign that delivered both Remcos and AsyncRAT together through spreadsheet-themed phishing across a dozen countries. A malware family named in a two-year-old walkthrough is not automatically stale.

**Step 6: Use geolocation to catch anomalies, not to confirm identity**

Geolocation enrichment answers a narrower question than people expect. It doesn't identify who is behind a connection. It checks whether the location makes sense given what you already know about the account or the network. A US-based employee's session suddenly originating from the Netherlands is worth a look even before any other enrichment runs. A European company's outbound traffic reaching a country it has no business relationship with tells a similar story from the network side. City-level accuracy from tools like ipinfo.io or iplocation.net stays unreliable, so treat country-level geolocation as a useful filter and nothing more precise than that.

**Step 7: Fingerprint exposed services and read the TLS certificate**

Knowing what ports and services an IP exposes helps in two directions. On a victim's public IP, an open service like SSH or RDP often marks the entry point an attacker used. On an attacker's IP, outdated or unusual services often mean the host itself was compromised and repurposed as infrastructure rather than built for the job. Shodan and Censys both index this kind of exposure, with Censys covering some non-standard ports Shodan misses and offering deeper certificate search behind a paid tier.

TLS certificates layer on a further signal once HTTPS is involved.

| Certificate field | What to look for |
|---|---|
| Issuer | A self-signed certificate is a strong sign the site deserves investigation |
| Validity | Newly issued or unusually long-lived certificates both suggest purpose-built malware infrastructure rather than a normal commercial site |
| Subject | Self-signed certs often name the software behind the HTTPS service, such as a firewall appliance |

The room's service exposure practice targeted `64[.]89[.]160[.]44`, already confirmed malicious, to establish its role in the incident:

| Question | Finding |
|---|---|
| Remote access service exposed | RDP |
| Open ports identified | 9 |
| C2 leaked through an exposed service's certificate | AsyncRAT |
| Certificate validity period | 3,935 days |

A certificate valid for nearly eleven years on infrastructure hosting an active RAT is its own tell. Legitimate services rotate certificates far more often than that, both for security hygiene and because most commercial certificate authorities cap validity well under a year. A multi-year, self-issued certificate sitting on a box exposing RDP and leaking AsyncRAT traffic reads as infrastructure built once and left running rather than infrastructure maintained by anyone with an incentive to keep it looking legitimate.

AsyncRAT has kept close company with Remcos through 2026 campaigns, frequently delivered in the same phishing chains and sharing overlapping infrastructure, which is consistent with what this exercise found: two different RAT families traceable through the same enrichment workflow, on infrastructure with the same basic red flags.

**Step 8: Detect VPNs, proxies, and Tor exit nodes before trusting a location**

This is the task that ties geolocation back to something defensible. A login that matches on country, city, and user agent still tells you nothing if the IP behind it belongs to a VPN provider, because VPN services make faking any location close to instant. IP2Proxy and Spur both maintain databases specifically for labeling VPN, proxy, and Tor exit node IPs, and both offer a usable free tier alongside paid options meant for SIEM integration.

The room's practice worked through two versions of the same scenario:

| Scenario | Alert priority |
|---|---|
| London user logs in from a London IP confirmed as Mullvad VPN | Raise the alarm, prioritize (Yea) |
| London user logs in from a London IP that matches no known VPN provider | Do not close as a false positive (Nay) |

The first case makes sense once VPN masking is confirmed: geography stops meaning anything the moment you know the IP is a VPN exit node, so the "clean" match on country and city is worthless and the alert needs real attention. The second case is the one analysts get wrong more often. Not matching a known VPN provider list only means the IP isn't tagged, not that it's clean. Standard reputation and ASN checks still need to run before an analyst closes anything.

This connects directly to what Verizon's 2026 DBIR flags as one of the more durable attacker advantages: residential proxy services that route traffic through real consumer IP addresses rather than easily blocklisted data center ranges, making detection meaningfully harder than spotting a commercial VPN with a known exit node list. Combined with the earlier ASN table, VPN and proxy detection becomes the last layer in a workflow that starts at the domain, moves to the IP, and ends at the identity behind the connection.

The room compresses that full workflow into a short checklist worth keeping close to any alert queue: for a domain, does it resemble a known brand, what is its reputation, how old is the registration, and what IP does it resolve to. For an IP, is it inside a known CDN range, what is its reputation, does its geolocation match the expected context, is it a VPN or proxy node, and what type of ASN does it belong to. Steps get skipped or reordered depending on what the alert already tells you, but the order of operations, domain first, then IP, then identity, holds up across most triage.

**Step 9: Work the challenge against a real APT-linked domain**

The final task drops the practice scenario framing and hands the analyst a live incident: an APT group has compromised the company, and the domain `raytracingengine[.]com` needs full enrichment to identify the infrastructure behind it. The task's own guidance is worth noting as a lesson in itself, it tells analysts to try the live tools first, because attacker infrastructure this specific and this recent is often already taken down within days, and to fall back to the exported incident report only when the live lookups come up empty.

| Question | Finding |
|---|---|
| Resolved IP | 35.188.105.97 |
| Cloud provider | Google Cloud |
| Server country | United States |
| Domain creation date | February 21, 2026 |
| Attack server OS (via exposed service) | Linux |

Every finding here reinforces a pattern from earlier in the room: a cloud-hosted IP on a major provider rather than a boutique bulletproof host, a domain young enough that its registration date sits inside the same year as the incident, and a Linux-based server fingerprinted through its exposed services rather than assumed. None of these facts alone would justify an escalation, but stacked together, through the enrichment sequence this room teaches, they turn a bare domain name into a clear picture of attacker infrastructure.

## Why it matters

The core skill in this room, turning a bare IP or domain into a decision, sits on the fault line where modern intrusions succeed or get caught early. Mandiant's finding that initial-access handoffs now happen in roughly 22 seconds means the infrastructure an analyst is enriching today may already be staged for a second, more damaging actor by the time the enrichment finishes, which puts a real cost on every minute an analyst spends fumbling through an unfamiliar tool instead of reading the result.

The residential proxy problem Verizon's 2026 DBIR keeps raising year over year is what the VPN detection task in this room is built to catch. Attackers routing traffic through real consumer IP addresses defeat geographic and reputation-based defenses that assume malicious traffic looks different from legitimate traffic. It often doesn't anymore, and the only reliable countermeasure is the kind of proxy and VPN database lookup this room teaches directly.

Bulletproof hosting adds a structural wrinkle CISA addressed head-on in November 2025, when it published joint guidance with the NSA, FBI, and international partners specifically on mitigating risk from providers that knowingly lease infrastructure to cybercriminals. The guidance is blunt about the limits of ASN-based blocking: a bulletproof provider can obtain a new, unflagged ASN from a regional internet registry in under a business week and shift its entire customer base onto it. That's why the room teaches ASN analysis as one signal among several, alongside geolocation, reputation, exposed services, and VPN status, rather than as a single decisive check. The 1337 Services GmbH network this room's practice exercise flags is a live example of the pattern CISA describes: a hosting provider whose infrastructure genuinely mixes ordinary customers with a substantial volume of Tor relay traffic, tagged accordingly by independent trackers like BGP.Tools and the Tor Project's own community resources.

The malware families this room surfaces, Remcos and AsyncRAT, are not museum pieces. Both stayed in active, evolving use through 2026, showing up in campaigns that shifted Remcos from simple data theft toward real-time surveillance capability and paired it with AsyncRAT in coordinated phishing operations spanning a dozen countries in a single wave. An analyst who recognizes these families in VirusTotal comments or exposed TLS certificates is not reading history. They're catching current infrastructure mid-campaign.

Even the room's aside about WHOIS being "gradually" replaced by RDAP undersells how far that transition has already gone. ICANN completed the sunset of WHOIS as a requirement for generic top-level domains in January 2025, and analysts who still reach only for legacy WHOIS syntax are working with a protocol most registries have already turned off. The tools an analyst reaches for will keep changing year over year. The judgment underneath them, correlating multiple weak signals instead of trusting any single verdict, is the part worth holding onto.

## Key takeaways

- Enrichment turns a bare indicator into a decision through five layers: DNS resolution, WHOIS/RDAP registration data, IP reputation and ASN ownership, exposed services and TLS certificates, and VPN/proxy/Tor status.
- Domain age is one of the highest-signal, lowest-cost checks available. A domain registered one day before triggering an alert needs little further justification to escalate.
- CDN fronting hides an origin server behind shared address space; typosquatting and IDN homograph attacks hide malicious domains behind visual similarity to trusted brands. Punycode conversion catches homographs that a browser address bar won't show.
- ASN type shapes how much weight to give a reputation hit. Residential ASNs suggest VPN use or a compromised consumer device, server hosting ASNs carry the highest baseline risk, and cloud or CDN ASNs need deeper analysis before either verdict applies.
- Bulletproof hosting providers rotate ASNs faster than blocklists can keep up, which is why CISA's November 2025 guidance and this room both treat ASN analysis as one signal among several rather than a standalone verdict.
- A confirmed VPN, proxy, or Tor exit node invalidates geolocation entirely, even when country and city both match expectations. Not matching a known VPN database only means the IP isn't tagged yet, not that it's clean.
- Remcos and AsyncRAT remain active, evolving malware families in 2026, not legacy indicators, which is why VirusTotal community comments and TLS certificate metadata still catch them in enrichment workflows built around correlation rather than static signatures.
---

title: Intro to Cyber Threat Intel

date: 2026-08-05 13:00 +0300

categories: [Foundations, Threat Intelligence]

tags: [threat-intelligence, cti-lifecycle, mitre-attack, stix-taxii, cyber-kill-chain, tlp]

description: "A TryHackMe SOC Level 1 writeup on the cyber threat intelligence lifecycle, the standards that govern how analysts share it, and a practical exercise that turns a phishing alert into a documented threat profile."

---

## Description

"Intro to Cyber Threat Intel" is the entry point into TryHackMe's threat intelligence content within the SOC Level 1 path. The room defines the vocabulary a Level 1 analyst needs before touching a threat intel platform: the difference between data, information, and intelligence, the six-phase intelligence lifecycle, the standards that govern how intelligence gets labeled and shared, and the frameworks that translate a raw alert into a named adversary technique. It closes with a practical exercise that builds a threat profile from a phishing incident inside a simulated SIEM dashboard. Source: TryHackMe, room "Intro to Cyber Threat Intel," part of the SOC Level 1 learning path.

The room has no terminal work. Every task is read, reason, and answer, which makes it a reference point rather than a lab. That reference point matters because the vocabulary introduced here (IOC, IOA, TTP, TLP, STIX, TAXII) reappears in every later room in the path, and getting the definitions wrong at this stage compounds into misapplied labels later.

## The problem

Two hundred alerts sit in the queue at the start of a shift. Most of them are noise: a scanner hitting a honeypot, a user mistyping a password twice, a cron job phoning home to a server that changed its DNS record last month. One of them is a PowerShell process reaching out to a domain nobody registered on purpose. An analyst who treats every alert the same way either burns the shift chasing false positives or misses the one connection that mattered.

Threat intelligence exists to break that tie. It answers three questions before an analyst commits time to an investigation: what is on the other end of this indicator, what has it done before, and what does the organization do about it right now. Triage without that context becomes a coin flip dressed up as analysis. Triage with it lets the analyst spend the shift on the alerts that deserve attention and close the rest with a documented reason instead of a shrug.

Verizon's 2026 Data Breach Investigations Report quantifies the cost of skipping that step. Vulnerability exploitation overtook credential abuse as the leading initial access vector in 2025, accounting for 31 percent of breaches against 13 percent for credential abuse alone, while the median time to fully patch a vulnerability grew from 32 days to 43. Mandiant's M-Trends 2026 report puts the global median dwell time, the stretch between an attacker's first foothold and the moment a defender notices, at 14 days, up from 11 the year before. Both figures describe organizations that had the telemetry to catch an intrusion earlier and lacked the intelligence context to act on it in time. This room builds that context from the ground up.

## How it works

**Step 1: Turning data into intelligence**

Cyber Threat Intelligence, CTI for short, is evidence-based knowledge about an adversary that helps an organization decide what to do about a threat. The room frames the discipline through three layers, each one building on the last.

| Layer | Definition | Alert-queue example | SOC L1 action |
|---|---|---|---|
| Data | An unprocessed observable | `45.155.205.3:443` | Capture the artifact |
| Information | Data plus factual annotation | IP registered to Hetzner, first seen 2023-07-14 | Record attributes |
| Intelligence | Analyzed information that answers "so what" | IP belongs to the current BumbleBee C2, block immediately | Escalate or suppress |

An L1 analyst pushes artifacts up that ladder through enrichment: quick, methodical lookups across public, commercial, and internal sources that establish origin, behavior, and relevance. Three labels recur throughout that process. An Indicator of Compromise (IOC) is evidence a breach already happened, such as a command-and-control address showing up in the logs. An Indicator of Attack (IOA) is a malicious action still in progress, such as PowerShell spawning a service nobody scheduled. Tactics, Techniques, and Procedures (TTPs) describe an adversary's methodology in detail, usually expressed as MITRE ATT&CK IDs.

Each indicator type demands a different first move. Memorizing a list of tools matters less than recognizing which category an artifact falls into.

| Indicator | Example | First resources | Associated IOA/TTP |
|---|---|---|---|
| IPv4/IPv6 | `45.155.205.3` | WHOIS, VirusTotal Relations, Shodan | Repeated SSH failures; `T1110.003` Password Guessing |
| Domain/FQDN | `malicious-updates[.]net` | WHOIS age, passive DNS, urlscan.io | Surge of DNS queries to a 24-hour-old domain |
| URL | `hxxp://malicious-updates[.]net/login` | URLhaus, urlscan.io, Any.Run with network off | Browser POST to `/gateway.php` carrying a payload |
| File hash | `e99a18c428cb38d5...` | VirusTotal, Hybrid-Analysis, MalShare | `T1055` Process Injection into `regsvr32.exe` |
| Email address | `billing@evil-corp.com` | MXToolbox, Have I Been Pwned | SPF failure paired with a recent domain registration |
| Local artifact | `HKCU\Software\Run\updater.exe` | Sigma rules, EDR prevalence query | `T1547.001` Registry Run Keys |

Bookmarking these lookups, or wiring them into a SIEM launcher panel, saves thirty seconds per alert. Across a month of two-hundred-alert shifts, that adds up to hours.

**Step 2: Sorting intelligence by altitude and origin**

Not every piece of intelligence serves the same audience. The room splits CTI into four classifications by altitude:

- Strategic intel looks at the organization's threat landscape over months or years. An annual ransomware trends report predicting a shift toward data-wiping extortion in healthcare is strategic.
- Tactical intel assesses adversary behavior through TTPs. An advisory describing new abuse of `T1059.005` (Visual Basic) in malspam campaigns is tactical.
- Operational intel covers campaign-specific motive and intent, useful for understanding which of an organization's people, processes, and technologies sit in the crosshairs.
- Technical intel is atomic: IPs, hashes, domains, the artifacts that map directly onto a block list.

An L1 analyst escalates technical IOCs constantly, documents tactical IOAs as they appear, and feeds the patterns upward into operational reporting. The origin of that intelligence matters just as much as its altitude. Internal telemetry (SIEM, EDR, phishing mailbox submissions) carries the highest immediate relevance because it describes the analyst's own environment. Commercial services such as vendor feeds and paid sandboxes offer high fidelity but often carry export and sharing restrictions tied to licensing. Open-source intelligence, OSINT, sources like AbuseIPDB and URLhaus update fast but need cross-confirmation before an analyst acts on them alone. Communities and ISACs, sector-specific Information Sharing and Analysis Centers such as FS-ISAC for financial services, add context no single organization would generate on its own.

Most SOCs consume this intelligence through two mechanisms, and mixing them up causes real operational pain. A feed is a scheduled stream of indicators delivered as CSV, JSON, or STIX; over-ingesting feeds without curation drowns an analyst in false positives faster than it builds trust in the program. A SOC that turns on five commercial feeds in one week without checking overlap or relevance tends to see duplicate alerts on the same low-value IP ranges within days, and the on-call analyst learns to dismiss the noise before learning to trust the signal underneath it. Curating a feed before promoting it, checking hit rate against the organization's own telemetry for a trial period, prevents that trust from eroding before the program gets a fair test. A platform, MISP and OpenCTI are the leading open-source examples, is a structured repository that stores indicators, tracks enrichment history, maps relationships between artifacts, and enforces TLP permissions. Feeds get introduced gradually, checked against the organization's actual threat model, and promoted into the platform only once they prove actionable. The platform then becomes the single source of truth an analyst queries first.

**Step 3: Running the six-phase lifecycle on a live case**

The room walks the lifecycle through a scenario: Alex, an L1 analyst at TryHatMe Corp, gets asked to protect a PostgreSQL production database holding customer data. The database sits behind a next-generation firewall capable of IP and domain blocking, with an EDR agent watching the host for file-hash matches. Six phases carry that mandate from vague instruction to measured outcome.

Direction sets the mission. Alex meets the CTI lead and the database administrator to translate "bring in threat intelligence" into two measurable questions: which external IPs and domains are currently used to exploit PostgreSQL or exfiltrate its data, and which malware families targeting PostgreSQL drivers or credentials are active this week. Those two questions become the success criteria for everything downstream.

Collection gathers raw material against those questions from four sources: a commercial feed from the firewall vendor with 37 IPs flagged as database-exfil C2 in the last 24 hours, an OSINT pull from AbuseIPDB tagged PostgreSQL-brute-force with 15 IPs and four domains, the organization's internal MISP instance holding two SHA-256 hashes of PgSQL credential stealers from past incidents, and a fresh vendor threat report contributing one new hash and three C2 domains. Alex exports each source and stores a dated copy for reproducibility.

Processing normalizes and correlates that raw material. Indicator syntax gets standardized (IPv6 compressed, domains lowercased, subnet masks stripped), duplicates against the platform's existing table get merged, and every entry gets tagged with source, date, and TLP label. Processing is also where contradictions surface: one IP shows up in the NGFW feed as TLP:AMBER and in AbuseIPDB as TLP:CLEAR. The stricter label wins, so the merged record inherits TLP:AMBER, which keeps the list from leaking further than intended if it gets shared later.

Analysis turns processed information into judgment. Blocking every indicator flagged as suspicious invites false positives, so Alex cross-checks each one against local telemetry. A thirty-day Splunk query shows one NGFW IP attempting, and failing, a TCP connection to port 5432 against the production subnet, which validates that indicator's relevance. A reverse search in OpenCTI links a new hash to the PgSteal malware family, and an Any.Run sandbox run confirms credential-dump behavior against the exact ODBC driver the organization uses. Confidence gets graded against a simple rubric:

| Confidence | Source agreement | Local sightings | Action |
|---|---|---|---|
| High | Same IOC in 2+ sources | 1+ local attempt | Immediate block |
| Medium | Single trusted source | No local hits | Alert-only |
| Low | OSINT only | No context | Monitor for 14 days |

Seven IPs and one hash clear the high bar. The rest go into a fourteen-day monitoring queue.

Dissemination gets the finished intelligence to the people who can act on it, tailored to what each consumer needs. The firewall team gets a CSV upload with a change ticket documenting risk and TLP label. The endpoint team gets a YARA rule set loaded into the EDR console. The CTI platform gets the full indicator objects with all tags, preserving history for future correlation. Management gets a two-hundred-word summary in the weekly cyber-risk memo, enough to show return on investment without burying a non-technical reader in indicator syntax.

Feedback closes the loop. Two weeks after the block rules go live, the median dwell time for PgSQL brute-force IPs drops from 48 hours to zero because the blocks are now pre-emptive, and the false-positive rate on the new blocks sits at zero percent with nothing revoked. Those numbers justify expanding the program, so Alex updates the direction document and schedules a second iteration covering DNS tunneling indicators for the same asset group.

**Step 4: Sharing intelligence without leaking it**

Every piece of intelligence carries a sharing boundary, and getting that boundary wrong can breach a partner agreement or tip off an adversary that a campaign has been noticed. The Traffic Light Protocol, TLP, defined by FIRST.org, labels that boundary in four colors.

| TLP label | Sharing boundary | Typical SOC L1 behavior |
|---|---|---|
| TLP:CLEAR | No restriction | Post to the internal wiki or platform |
| TLP:GREEN | Peer community, not public | Upload to MISP or a partner-SOC Slack workspace |
| TLP:AMBER | Organization-wide, clients on need-to-know | Reference in tickets, do not copy the raw indicator |
| TLP:RED | Named recipients only | Store in an encrypted note, no ticketing system without clearance |

FIRST updated the standard to TLP 2.0 in August 2022, retiring TLP:WHITE in favor of TLP:CLEAR and adding TLP:AMBER+STRICT as a modifier an analyst can apply to AMBER when intelligence should never leave the originating organization, with no onward pass to clients. The day-to-day rule stays the same regardless of version: whatever label arrives with an indicator travels with it into every platform and triage note, without exception. A TLP:RED indicator pasted into a public ticketing system by mistake does more than embarrass whoever typed it. It can burn a partner's live investigation and end the sharing relationship that produced the tip in the first place, which is why the label matters as much as the indicator itself.

Once an indicator carries a label, it needs a format that survives being passed between organizations without losing meaning. Structured Threat Information Expression, STIX, is a JSON-based language, currently at version 2.1 and an OASIS standard since 2021, that describes indicators, relationships, and context in a form both humans and machines can parse. A single STIX bundle can link an indicator object to a malware object, a threat-actor object, and a relationship object describing how they connect, which is what lets a platform show an analyst the full chain instead of a bare IP address. Trusted Automated Exchange of Intelligence Information, TAXII, is the transport layer that moves that STIX data between systems over HTTPS in near real time. TAXII supports two models: Collection, where a producer hosts intelligence and consumers pull it on request, and Channel, where a central server pushes intelligence out to subscribers automatically.

Sharing intelligence carries a cost alongside the benefit. Near-real-time feeds shorten the gap between one organization's incident and another's preventive action, and contributing back earns reciprocal trust from the community. Privacy law, customer NDAs, or internal competitive information can still forbid disclosure outright, and publishing an IOC too early can warn an adversary that its infrastructure has been burned before the organization finishes acting on it.

**Step 5: Naming the adversary's behavior**

A PowerShell command in a triage note means little to a teammate or an auditor unless it carries a label everyone recognizes. MITRE ATT&CK supplies that label: each technique, `T1059.001` PowerShell, `T1048.003` DNS tunneling, and so on, works as a shared reference between analysts, vendors, and incident responders. As of mid-2026, the Enterprise matrix alone catalogs 15 tactics, 222 techniques, and 475 sub-techniques drawn from 174 documented threat groups. An L1 analyst uses the matrix in three steps: match the observed behavior to a tactic and technique pair, write the ID into the triage note (for example, "Observed `T1071.001` web-based C2 against FINANCE-TRYHATME-00"), and hand that note to Level 2 or incident response, who recognize which mitigations and threat-actor profiles apply without having to re-derive the context.

ATT&CK catalogs how adversaries attack. MITRE D3FEND catalogs how defenders respond, mapping each entry to a defensive tactic such as credential hardening or data obfuscation. A proxy alert for `T1048.003` DNS tunneling, for instance, points to D3FEND's `D3-DNSTA` DNS Traffic Analysis technique, which lists concrete controls: block excessive TXT record queries and alert on unusual query entropy. Adding that control to the "next actions" field turns a diagnosis into a mitigation.

The Cyber Kill Chain, developed by Lockheed Martin, breaks an intrusion into seven linear phases and remains useful for briefing non-technical stakeholders on how an attack unfolds.

| Phase | Purpose | Examples |
|---|---|---|
| Reconnaissance | Gather information on the target | OSINT, email harvesting, network scans |
| Weaponization | Build malware for the target | Backdoored exploit, malicious Office document |
| Delivery | Get the malware to the victim | Email, weblink, USB |
| Exploitation | Breach a vulnerability to execute code | EternalBlue, Zero-Logon |
| Installation | Establish persistence | Password dumping, backdoors, RATs |
| Command and Control | Remotely operate the compromised system | Empire, Cobalt Strike |
| Actions on Objectives | Achieve the attack's goal | Data encryption, exfiltration, defacement |

The model's linear structure draws fair criticism for glossing over lateral movement and insider activity that rarely follow a straight line from reconnaissance to impact. Paul Pols addressed that gap in 2017 with the Unified Kill Chain, folding the original seven phases together with MITRE ATT&CK into 18 phases grouped under three higher-level stages. In covers everything up to establishing a foothold, matching the Kill Chain's Reconnaissance through Installation phases. Through covers the pivoting and privilege escalation an attacker needs to reach a target asset once inside, a stretch the original Kill Chain barely addresses. Out covers achieving the objective and, where relevant, covering tracks on the way back. Teams increasingly treat the Kill Chain as the narrative that explains an intrusion to leadership and ATT&CK as the engineering index that drives detection content, rather than picking one framework as a full replacement for the other.

**Step 6: Scoring what needs patching first**

A SOC queue carries almost as many vulnerability notifications as malware alerts, and an L1 analyst needs a shared vocabulary to triage them. A CVE, Common Vulnerabilities and Exposures, assigns a catalog number to a discovered vulnerability, for example `CVE-2023-4863`. CVSS, the Common Vulnerability Scoring System, rates severity on a 0 to 10 scale. CVSS 3.1 remains the version in the widest production use, but CVSS 4.0, published by FIRST in November 2023, now runs alongside it: the National Vulnerability Database publishes both scores for newly disclosed CVEs. CVSS 4.0 organizes its score into four metric groups instead of three: Base for the vulnerability's intrinsic properties, Threat for whether exploitation is active, proof-of-concept, or unreported, Environmental for how the vulnerability behaves in a specific deployment, and a new Supplemental group covering factors like safety impact. The NVD itself remains the canonical repository linking CVE numbers to CVSS scores, known exploits, and affected products.

A CVSS score alone still leaves a gap that a threat intel analyst needs to close. A 9.8 on a system nobody can reach from the internet may deserve a lower place in the queue than a 6.5 that a named threat group is exploiting this week. The Exploit Prediction Scoring System, EPSS, maintained alongside CVSS by FIRST, estimates the probability that a given CVE gets exploited in the wild within the next 30 days, and pairing that probability with CISA's Known Exploited Vulnerabilities list turns a static severity score into an intelligence-informed priority order.

**Step 7: Building a threat profile from a live alert**

The room's practical task drops the analyst into a static SIEM dashboard and asks them to trace a phishing incident from the inbox to the endpoint. The log shows a message arriving from `vipivillain@badbank.com`, followed by a download of a file named `flbpfuh.exe` onto the victim host. Pulling those two facts, plus the extraction IP address the malware later reached out to, into a threat profile form completes the exercise:

| Field | Value |
|---|---|
| Threat Actor Extraction IP Address | `91.185.23.222` |
| Threat Actor Email Address | `vipivillain@badbank.com` |
| Malware Tool | `flbpfuh.exe` |
| User Victim Logged Account | Administrator |
| Victim Email Recipient | John Doe |

Submitting the completed profile returns the flag `THM{NOW_I_CAN_CTI}`. The exercise is small, but it forces the same discipline the rest of the room describes: pull the artifact, annotate it, decide what it means, and write it down somewhere a teammate can find it.

## Why it matters

The gap between having telemetry and having intelligence shows up in the numbers every year. Mandiant's M-Trends 2026 report puts the global median dwell time at 14 days, up from 11 the year before, and organizations that detected an intrusion internally did so in roughly nine days, against 25 days when an external party had to notify them first. That nine-day figure reflects teams that had context ready before the alert fired rather than teams reconstructing context from scratch afterward.

CISA's #StopRansomware program runs the dissemination phase at national scale. Each joint advisory, built with the FBI and often state or sector ISACs, packages IOCs, TTPs, and YARA rules for a specific ransomware family aimed at network defenders rather than executives or the general public. The advisories get revised as intelligence ages: CISA's Play ransomware advisory, for example, was updated in mid-2025 to add newly observed TTPs and strip out indicators that had gone stale, the same processing and feedback discipline Alex applies to the PostgreSQL scenario, running at the scale of a federal agency instead of one SOC.

Verizon's 2026 DBIR supplies the reason the Direction phase carries as much weight as it does. Vulnerability exploitation overtook credential abuse as the top initial access vector in 2025, at 31 percent of breaches, while organizations remediated only 26 percent of vulnerabilities on CISA's Known Exploited Vulnerabilities list, down from 38 percent the year before. An analyst who cannot connect a CVE to an active campaign has no way to argue that one unpatched system deserves priority over another, and that connection is what technical and tactical intelligence supplies.

The frameworks in this room outlast any specific tool. A SOC that migrates from one SIEM to another, or swaps one commercial feed for a competitor's, still expects an analyst to write `T1071.001` in a triage note, apply the correct TLP label, and know the difference between an IOC and an IOA on sight. That vocabulary carries between employers and platforms in a way that fluency in one vendor's query syntax never does.

None of this requires an analyst to become a full-time intelligence specialist. It requires knowing which question a given piece of intelligence answers, which label controls how far it can travel, and which teammate needs it next. That discipline separates a queue that gets triaged from a queue that gets survived.

## Key takeaways

- Data becomes intelligence only once it answers a "so what" question. An IP address alone is data; an IP address tied to an active campaign with a recommended action is intelligence.
- IOC, IOA, and TTP describe different points on an intrusion's timeline: evidence something already happened, a malicious action in progress, and the adversary's broader methodology.
- The six-phase lifecycle, Direction, Collection, Processing, Analysis, Dissemination, Feedback, is not academic. TLP collisions during Processing and confidence grading during Analysis are where most triage mistakes happen.
- TLP 2.0 replaced TLP:WHITE with TLP:CLEAR in 2022 and added TLP:AMBER+STRICT for intelligence that should never leave the originating organization. The stricter label always wins when sources disagree.
- MITRE ATT&CK and the Cyber Kill Chain answer different questions and work best together: the Kill Chain narrates the intrusion, while ATT&CK supplies the technique-level detail that drives detection engineering.
- A CVE without a CVSS score and a threat-intel connection is just a catalog number. Prioritization depends on knowing whether a vulnerability is being actively exploited, not just how severe it looks on paper.
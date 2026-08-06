---

title: File and Hash Threat Intel

date: 2026-08-06 20:00 +0300

categories: [Foundations, Threat Intelligence]

tags: [malware-analysis, file-hashing, virustotal, sandbox-analysis, mitre-attack, ioc-extraction]

description: "A TryHackMe SOC Level 1 writeup on enriching suspicious files through path heuristics, hash lookups against VirusTotal and MalwareBazaar, sandbox detonation, and an Akira-themed practical that ties every step together."

---

## Description

"File and Hash Threat Intel" picks up where "Intro to Cyber Threat Intel" leaves off, and it names that room as a prerequisite. The introductory room defines the vocabulary; this one puts it to work on an actual binary. The room frames every alert queue entry around three steps, verify, enrich, and decide, then spends its five tasks on the enrich step: reading a suspicious filename, generating and checking a hash, pulling vendor verdicts from VirusTotal and MalwareBazaar, detonating the sample in a sandbox, and closing with a timed practical built around an Akira-themed ransomware sample. Source: TryHackMe, room "File and Hash Threat Intel," part of the SOC Level 1 learning path.

The room's own scenario sets a real constraint: at a company called Try Daily, an EDR sweep flags several binaries during a Monday release cycle, and the L1 analyst, shadowing an L2 mentor rather than working solo, has sixty minutes to sort the samples into bait, benign, or malicious before handing findings upstream. That time pressure is the point, and the shadowing detail matters too. An L1 analyst is not expected to make the final call alone; the job is to work the cheap, fast checks well enough that the L2 mentor's time gets spent on judgment calls instead of re-running lookups the L1 already had access to. File and hash intelligence only earns its place in a SOC workflow if an analyst can move through it fast enough to make that handoff worth having.

## The problem

A file lands on an analyst's desk with a name like `Setup.exe` and nothing else. It could be a legitimate installer a user downloaded five minutes ago, or it could be a dropper staged to look exactly like one. Nothing about the name alone proves anything, and treating either possibility as the default answer wastes the sixty minutes the room's scenario allows. Assume benign and a real dropper sits on a workstation collecting credentials while the analyst moves on to the next ticket. Assume malicious and the SOC burns response cycles isolating a host that was never a threat, training the team to distrust its own alerts a little more each time it happens.

Hashes and vendor intelligence exist to break that ambiguity, but only when an analyst pulls them in the right order. Filepath and filename analysis costs seconds and needs no external lookup, so it comes first. Hash generation comes next because it converts a file that attackers can rename at will into an identifier that never changes. VirusTotal and MalwareBazaar enrichment comes after that, turning a bare hash into vendor verdicts, malware family tags, and known infrastructure. Sandbox detonation comes last, reserved for cases where static evidence alone will not settle the question, because it costs the most time and still carries real limitations.

The room's own scenario names this sequence explicitly: verify that the sample and hash in hand are the ones actually flagged, enrich with the fastest source first and the slowest source only when needed, then decide. Skipping straight to sandbox detonation on every file in a sixty-file sweep burns the shift before lunch. Working the cheap checks first and reserving detonation for genuine ambiguity is what makes the sixty-minute constraint survivable.

The skill this room builds shows up constantly in day-to-day defense. CrowdStrike's 2026 Global Threat Report found that 82 percent of detections in 2025 involved no malware file at all, adversaries moving through valid credentials and built-in tools instead of dropping an executable, up from 51 percent in 2020. File and hash intelligence will never catch that majority on its own. It remains essential for the minority of intrusions that still drop a binary, and knowing how to work a hash quickly is what separates a confirmed verdict from a guess when one does show up.

## How it works

**Step 1: Reading the file before you touch it**

A filepath and filename cost nothing to inspect and often carry attacker tradecraft in plain sight. Storage location matters first. The system drive root and profile folders such as `C:\Users\Public` invite persistence and cross-user access because they sit in locations every account can reach. Directories like `C:\Users\Public\Public Downloads`, `C:\Windows\Temp\`, and `C:\ProgramData\` see enough legitimate write activity that a dropped payload can hide in the noise.

Filenames carry their own heuristics.

- Double extensions, `invoice.pdf.exe`, exploit Windows' default setting that hides known file extensions, so the file displays as a harmless PDF.
- System binary impersonation, `scvhost.exe` instead of `svchost.exe`, banks on a user's familiarity with core process names. An allowlist built on legitimate file paths catches this better than one built on filenames alone.
- High-entropy strings, `jh8F21.exe`, point to automated packing or polymorphic generation, common in high-volume phishing operations.
- Masquerading through routine-sounding names such as `backup-2300.exe`, or through single-character substitution that looks correct at a glance, reduces suspicion without needing any technical evasion at all.

Running that checklist against the room's sample set turns up `payroll.pdf` sitting in the case files folder. Its file properties show a type of `Application (.exe)` behind a name that displays as a PDF, a textbook double extension. None of this proves malicious intent by itself. A legitimate installer can sit in a temp directory and a poorly named internal tool can trip the high-entropy heuristic without being hostile. Filepath and filename analysis buys an analyst triage priority instead of proof: which of the sixty files in a queue get hashed and enriched first, and which can wait.

**Step 2: Fingerprinting the binary**

It is worth working from a copy in an isolated environment from this point forward. Nothing in hashing or lookup requires execution, but habit matters more than any single step, and building the habit of isolating a sample before touching it prevents the one time an analyst forgets and it costs them. A filename proves nothing once an attacker can rename the file at will. A cryptographic hash does, because any change to a single byte changes the entire hash. SHA256 and MD5 cover most SOC workflows, and every major OS ships a way to generate them.

| Platform | Command |
|---|---|
| Windows (cmd) | `certutil -hashfile bl0gger.exe SHA256` |
| Windows (PowerShell) | `Get-FileHash -Algorithm SHA256 bl0gger.exe` |
| Linux | `sha256sum bl0gger.exe` |

MD5 still shows up in older tooling and legacy threat feeds, but SHA256 is the default for new investigations; MD5's known collision weaknesses make it usable for quick lookups against existing databases but a poor choice as the primary identifier in a report meant to hold up under scrutiny. A few habits keep hash-based investigation clean beyond picking the right algorithm. Store hashes in lowercase, since mixed case creates false mismatches during comparison. Hash everything that matters to the case, not just the final payload; if malware ships inside a ZIP archive, hash the archive and the extracted binary separately. Never record a bare hash string without noting where and when it was encountered, since a hash without provenance is nearly as useless as no hash at all.

Running `Get-FileHash -Algorithm SHA256` against `bl0gger.exe` returns `2672b6688d7b32a90f9153d2ff607d6801e6cbde61f509ed36d0450745998d58`, the identifier that carries through the rest of the investigation regardless of what the file gets renamed to later.

**Step 3: Enriching a hash with VirusTotal**

VirusTotal aggregates scan results from dozens of antivirus vendors into a single report, and it functions as a tactical pivot point rather than a single yes-or-no answer. A raw detection ratio like 12/71 tells an analyst almost nothing on its own; a 12/71 on a file uploaded ten minutes ago reads completely differently from the same ratio on a file that has sat in the database for a year. Reading the report well means knowing which sections carry signal and which carry noise, and treating the detection score as one input among several rather than the whole verdict.

| Section | Key question | Red flags | Analyst consideration |
|---|---|---|---|
| Detection score and labels | How many vendors flag this as malicious? | Five or more solid detections; conflicting classifications like "Trojan" versus "PUA" | New malware often shows low initial detection; recheck after 24 hours |
| Upload time | When was the file first submitted? | Uploaded days ago with high detection counts already; a sudden spike after weeks of quiet | Vendors need 48 to 72 hours for full analysis to mature |
| Signatures | Is the file properly signed? | Invalid or missing certificate; a certificate issued to an unrelated entity | Even valid certificates can be stolen or abused |
| Properties | Are there anomalies in the file data? | Compile timestamps at odd hours; entropy above 7.5 in non-media files | Legitimate packers like UPX also raise entropy |
| Relations | What infrastructure does the malware touch? | Known-bad IPs in VirusTotal's graph; DGA-style domains | Legitimate CDNs sometimes host malware unknowingly |
| Behavioral | What happens after execution? | Modified critical registry keys; process injection attempts | Some admin tools touch the registry legitimately too |

Two sections outside that table round out a full submission: contained domains and IPs, which cover the sample's network infrastructure, and contained files, which list anything embedded or dropped during execution. Both matter more once a sandbox run is available to confirm which of those static artifacts actually get touched at runtime, but pulling them at the VirusTotal stage means the sandbox step later has something specific to verify rather than a blank slate to explore.

Submitting the bl0gger.exe hash returns a threat classification of `trojan.graftor/flystudio` and a first submission timestamp of `2025-05-15 12:03:49`, both pulled straight from the Detection and Details tabs rather than inferred from behavior.

**Step 4: Cross-referencing with MalwareBazaar**

MalwareBazaar, a project from abuse.ch, is a free, community-fed repository built specifically for confirmed malware samples rather than general file reputation, and as of mid-2026 it holds more than 1.1 million submitted samples. Three features matter most for triage. Malware family tagging groups files by the family they belong to: the room's own example is a sample carrying only five out of seventy VirusTotal detections that still gets tagged `#IcedID` in MalwareBazaar, a low score that should not talk an analyst out of treating the file as malicious once the family tag is visible. YARA rule integration surfaces detection rules attached to related samples, worth pulling into the EDR or SIEM for future hunting rather than filing away as a one-off finding. Campaign attribution tags, such as `#TA551` marking a sample as belonging to a known threat actor group, link an isolated file back to that adversary's broader operation and can reveal whether one alert is an isolated event or a piece of a coordinated campaign already hitting other organizations.

Running the same lookup against the Morse-Code-Analyzer sample surfaces `CyberFortress` as the one vendor that classified the file as non-malicious, a useful reminder that a single clean verdict does not override a consensus of detections elsewhere. The Behavior tab flags `T1574.002`, Hijack Execution Flow: DLL Side-Loading, under persistence and privilege escalation, MITRE's designation for planting a malicious DLL alongside a legitimate application so the loader picks it up automatically.

**Step 5: Detonating safely in a sandbox**

Static properties establish identity. They do not establish impact, which is why an L1 analyst turns to sandbox detonation for three specific outcomes: confirming the file actually executes rather than sitting inert as a decoy, extracting runtime indicators like domains, mutexes, and dropped payloads, and mapping observed behavior directly to ATT&CK technique IDs. Hybrid Analysis and Joe Sandbox cover most of this ground, and the choice between them usually comes down to how much time the reader on the other end has. Hybrid Analysis produces a clean behavior tree and an ATT&CK heatmap suited to a fast executive summary an L1 analyst can generate and hand off inside a single shift. Joe Sandbox goes deeper into system calls, strings, and memory dumps, better suited to reverse engineers and detection engineers who need more than a verdict and have the time budget to read a longer report. An L1 analyst leans on the lookup and summary features of either tool to move fast; the deeper reverse engineering work stays with senior analysts who own that stage of the pipeline.

The Hybrid Analysis report for bl0gger.exe returns a threat score of 100 out of 100, tagged `BlackMoon, Discovery, windows-server-utility`. The command-line section shows the stealth execution: `regsvr32 %WINDIR%\Media\ActiveX.ocx /s`, an instance of `T1218.010` System Binary Proxy Execution: Regsvr32, a living-off-the-land technique that abuses a signed Microsoft binary to register a malicious payload while blending into normal system activity. The process tree shows `werfault.exe`, Windows' own error reporting process, spawned alongside it, which by itself looks benign but next to a stealth regsvr32 call reads as the malware either crashing something on purpose or triggering a crash handler as a side effect of its injection.

Beyond the headline verdict, the full report carries file composition data, imports, called processes, and network connections that a static hash lookup alone never surfaces. That detail is what turns a sandbox run into something worth attaching to an internal threat intelligence report rather than a one-line verdict passed up the chain.

Running the same workflow against `payroll.pdf` returns a masquerading indicator flagging the binary as an impersonation of a core Windows system process, the exact filename heuristic Step 1 already covers. The report also lists an associated URL, `hxxp://121.182.174.27:3000/server.exe`, and 454 extracted strings from the sandbox run, both worth pulling into the case file as supporting indicators even though the masquerading target itself needs a second look before it goes in a final report.

**Step 6: Knowing where the sandbox lies**

Sandbox output is not ground truth, and treating it as such produces false negatives. Four limitations matter most.

Sandbox evasion comes first. Malware increasingly checks for signs of virtualization or debugging before running its real payload: querying for known virtual hardware identifiers, counting CPU cores or installed RAM against thresholds no analysis VM ever meets, checking for a debugger attached to the process, or simply refusing to execute if the environment looks too clean to be a real victim machine. A clean sandbox run under these conditions does not mean a clean file; it can mean the file recognized the sandbox and declined to show its hand.

Limited execution time and coverage comes second. Most sandboxes cap analysis at two to five minutes, a window multi-stage payloads and time-delayed attacks can simply outlast. Malware that sleeps for ten minutes before unpacking its second stage passes through a five-minute sandbox looking completely inert.

Encrypted and obfuscated traffic comes third. Sandboxes that cannot decrypt SSL/TLS see HTTPS command-and-control traffic only as a destination with no payload content, and DNS tunneling that hides data inside query fields rarely trips a traditional network signature at all.

Fileless and living-off-the-land malware comes fourth, and it undercuts the entire premise of file-based sandboxing. Attacks that run entirely through PowerShell or WMI never touch disk, so a sandbox instrumented to watch file writes and registry changes has nothing to catch.

**Step 7: Working the Akira case end to end**

The room's timed practical drops a sample named `Challenge.bin.sample` in front of the analyst with no other context, forcing the full workflow from Steps 2 through 5 in sequence rather than one task at a time. Hashing the file and searching TryDetectThis returns a SHA256 of `43b0ac119ff957bb209d86ec206ea1ec3c51dd87bebf7b4a649c7e6c7f3756e7`, tagged with VirusTotal family labels `akira` and `filecryptor`, the second tag a reminder that the sample's job is encryption rather than credential theft or reconnaissance. The Behavior tab shows a text file named `akira_readme.txt` dropped during execution, the ransom note pattern that gives the sample away even before the encryption routine finishes running. The process list captures a PowerShell command executed shortly after the drop: `Get-WmiObject Win32_Shadowcopy | Remove-WmiObject`, a WMI query piped directly into a deletion call rather than a call to the more commonly monitored `vssadmin.exe`, the kind of native-tool substitution that lets a payload dodge a detection rule written only for the obvious command.

That command maps directly to `T1490`, Inhibit System Recovery. Deleting Volume Shadow Copies through WMI removes the built-in Windows restore points a victim would otherwise use to recover encrypted files without paying, and it is one of the most consistent behaviors ransomware operators execute just before or during encryption. Recognizing that single line of PowerShell for what it does, rather than what it looks like, is what turns a sandbox log into a MITRE-mapped finding an L2 analyst or incident responder can act on immediately.

**Step 8: Writing the finding up**

None of the work in Steps 1 through 7 helps anyone if it stays in the analyst's own notes. The room's own closing guidance is to translate findings into a brief that lists indicators by type, summarizes observed behavior in plain language, and closes with a proportionate recommendation the reader can act on without re-running the investigation themselves. For the Akira sample, that brief lists the SHA256 hash and VirusTotal family tags under Indicators, states plainly that the sample drops a ransom note and deletes shadow copies before encrypting files under Behavior, maps the shadow-copy deletion to `T1490` under Technique, and recommends isolating the host and rotating any credentials visible on it under Recommendation. This is the same Dissemination discipline the CTI lifecycle room covers: tailor the depth to the reader, whether that reader is an L2 analyst who needs the technical detail or a manager who needs three sentences and a verdict. A brief that skips straight to "malicious, escalate" without the supporting indicators forces the next person in the chain to redo work already done; a brief buried in raw sandbox output forces them to dig for the one line that actually matters. The proportionate version sits between those two failure modes.

## Why it matters

The Akira theme in this room's practical is not a random choice. Akira has grown into one of the most active ransomware-as-a-service operations running today, and the group's Windows affiliates favor the same shadow-copy deletion pattern the room's practical asks the analyst to recognize. CISA's updated joint advisory from November 2025, issued with the FBI, DC3, HHS, and international partners, ties the group to more than $244 million in ransom payments since it emerged in March 2023, and reporting from Halcyon in April 2026 puts Akira's time from initial access to full network encryption at under four hours in some cases. The group posted 84 victims in March 2026 alone, its second-busiest month on record, and sat in second place globally behind only Qilin for total ransomware victims in early 2026. A PowerShell one-liner that deletes shadow copies is not an academic MITRE mapping exercise here. It is the same technique this specific, currently active threat actor runs against real organizations across manufacturing, education, healthcare, and financial services, the sectors the CISA advisory names by name.

Sandbox limitations deserve equal weight. Picus Security's Red Report 2026 found that Virtualization and Sandbox Evasion, `T1497`, returned to the top ten most observed techniques after two years outside it, a clear sign that malware authors are building analysis-awareness back into their payloads rather than assuming a sandbox will never see the sample. Step 6's four limitations are not a defensive disclaimer tacked onto the room. They describe a trend that is actively getting worse, and an analyst who treats a clean sandbox verdict as final without cross-checking VirusTotal and MalwareBazaar first is the analyst that resurgent evasion technique is designed to fool.

File and hash intelligence also has a ceiling worth naming honestly. CrowdStrike's 2026 Global Threat Report puts malware-free detections at 82 percent of everything observed in 2025, adversaries moving through valid credentials, remote management tools, and built-in Windows utilities rather than dropping a novel executable at all. The skills in this room address the remaining share of intrusions that still drop a binary, and they remain the fastest, most conclusive path to a verdict when one does. A hash match against a known family in MalwareBazaar, or a sandbox confirming shadow-copy deletion, closes a question in minutes that behavioral analysis alone might take hours to settle. Pairing that speed with the identity and behavior-based detection covered elsewhere in this series, and with the CTI lifecycle's discipline for turning a verdict into a properly labeled, disseminated finding, gives an analyst coverage across both halves of the threat landscape instead of just the half that still leaves a file behind.

The tools in this room also outlast any single vendor relationship, the same pattern the CTI lifecycle post noted about frameworks. A SOC that swaps VirusTotal for a competing multi-scanner service, or drops MalwareBazaar for a paid alternative, still expects an analyst to read a detection ratio in context, recognize a family tag that overrides a low score, and know the difference between what a sandbox confirms and what it merely fails to catch. That judgment travels between platforms in a way that familiarity with one vendor's dashboard layout never does.

## Key takeaways

- Filepath and filename analysis costs nothing and comes first. Double extensions, system binary impersonation, high-entropy names, and masquerading are all visible before a single hash gets generated, and they set triage priority for everything that follows.
- A hash survives renaming; a filename does not. Generate one early with SHA256 as the default algorithm, store it in lowercase, and record where and when it was encountered so it holds up in a report months later.
- VirusTotal's detection score is a starting point, not a verdict. A low score on a fresh upload and a low score on a well-aged sample mean very different things, and the upload timestamp matters as much as the ratio itself.
- MalwareBazaar's family tags override a thin VirusTotal detection count. A known family with five detections is still a known family, and a campaign attribution tag can connect one alert to a broader operation already hitting other organizations.
- Sandbox detonation confirms execution, extracts runtime IOCs, and maps behavior to ATT&CK, but it cannot see what evasion-aware malware refuses to do in front of it, and its two-to-five-minute window misses anything built to wait that out.
- The same MITRE ID that shows up in a sandbox report, `T1490` for shadow copy deletion in this room, shows up in advisories for currently active ransomware groups. The mapping is not theoretical, and neither is the group behind it.
- A finding only has value once it reaches the person who needs it. Close every investigation with a brief that lists indicators by type, states the behavior in plain language, and ends with a recommendation proportionate to the evidence.
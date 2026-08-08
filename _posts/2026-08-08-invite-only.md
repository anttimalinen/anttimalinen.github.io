---

title: Invite Only

date: 2026-08-08 22:00 +0300

categories: [Foundations, Threat Intelligence]

tags: [ioc-pivoting, asyncrat, clickfix, discord-invite-hijacking, cookie-theft, malware-attribution]

description: "A TryHackMe SOC Level 1 writeup on pivoting from a flagged hash and IP through a full malware drop chain using a threat intel platform, then cross-referencing the findings against a public Check Point report to reconstruct a Discord invite hijacking campaign delivering AsyncRAT."

---

## Description

"Invite Only" sits further along the SOC Level 1 threat intelligence track than "Intro to Cyber Threat Intel," "File and Hash Threat Intel," and "IP and Domain Threat Intel." Those three rooms each isolate one skill: learn the CTI vocabulary, enrich a file hash, enrich an IP or a domain. This room drops both indicator types into a single ticket and asks the analyst to combine both skills, then push one step further and confirm the finding against public research. Source: TryHackMe, room "Invite Only," part of the SOC Level 1 learning path. The room ships as a single task and sits behind TryHackMe's premium tier, a detail confirmed by comparing the task structure across several independent walkthroughs rather than trusting one source alone.

The scenario places the analyst inside TrySecureMe, a managed service provider running SOC coverage for external clients. An L1 analyst on the early shift flagged two indicators, an IP address and a SHA256 hash, and escalated them without further context. That escalation lands on the desk of an analyst supporting L3 investigations, along with the name of a tool: TryDetectThis2.0. TryDetectThis2.0 behaves like a rebranded VirusTotal, complete with a Details tab, a Relations tab mapping how files connect to each other, and a Community tab where researchers leave comments and family attributions. The task asks for a documented threat profile built from those two bare strings: the malware family involved, the delivery mechanism, and the tradecraft the attackers used once a victim ran the payload.

The title doubles as a small joke once the investigation resolves. "Invite Only" describes both the room's premium access requirement and the attack vector waiting at the end of the drop chain: an invitation link that only looks like an open door.

That last requirement sets this room apart from its two predecessors. Enriching a hash or an IP is a lookup. Reconstructing a campaign from a lookup plus a piece of public research is investigation, and it matches the version of the job an L1 or L2 analyst does every time a flagged indicator turns out to be part of something bigger than a single alert.

## The problem

An escalation from L1 rarely arrives with a narrative attached. It shows up as a pair of strings, an IP address and a hash, sitting in a ticket with a timestamp and a note that something looked wrong. The analyst who picks up that ticket has no idea yet whether it describes a single infected laptop, a compromise already sitting in a dozen client environments, or a false positive thrown by an overzealous signature. Finding out is the job.

The scale of that job across a modern SOC makes the stakes concrete. Microsoft and Omdia's 2026 State of the SOC report found that 46 percent of all alerts turn out to be false positives, meaning close to half of an analyst's queue produces no security value at all. A separate 2026 study on SOC operations put real investigation capacity even lower: the average enterprise SOC manages to fully investigate only 37 percent of its daily alert volume, and each alert that does receive proper attention consumes 20 to 30 minutes of manual work. A managed service provider like TrySecureMe multiplies that pressure. A single flagged hash is never just one endpoint. It carries a question underneath it: is the malware family behind this filename already sitting in three other client networks under a different name.

L1 analysts train to move fast, not to finish the story. Their job stops at recognizing that something looks wrong and routing it to whoever handles investigation next, which means every escalation arrives stripped of the context an L1 shift did not have time to build. That handoff point is deliberate. An L1 analyst who spends forty minutes fully investigating one indicator processes far fewer alerts across a shift, and the SOC's overall detection capacity drops as a result. The tradeoff pushes the deep-dive work downstream to whoever picks up the ticket next, which in this room's scenario is the analyst supporting L3.

Two bare indicators cannot answer that question by themselves. An IP address without context is a number. A SHA256 hash without context is a fingerprint with no name attached. The value comes from pivoting: using the relationships a threat intelligence platform tracks between files, IPs, domains, and the malware families researchers have already documented, then building outward from two strings until they connect to something an analyst can act on. Skip that step and a SOC ends up choosing between two bad options: escalate every flagged indicator to full incident response and burn hours the team does not have, or close the ticket on a guess and let the alert that mattered slide into the backlog.

## How it works

**Step 1: Pivot from a hash to a filename**

A flagged SHA256 hash carries no readable information on its own. It is a 64-character fingerprint, and unless an analyst recognizes it on sight, that fingerprint alone does not say whether the file behind it is a printer driver, a spreadsheet, or a backdoor. The first move in TryDetectThis2.0, and in the real VirusTotal it mirrors, pastes the hash into the search bar and reads back a generated report.

The report for the flagged hash `5d0509f68a9b7c415a726be75a078180e3f02e59866f193b0a99eee8e39c874f` identifies the file as `syshelpers.exe`, a name built to blend into a Windows systems folder rather than draw attention to itself. The Details tab, under Basic Properties, lists the file type as Win32 EXE: a native Windows executable rather than a script or a document carrying an embedded payload.

| Field | Value |
|---|---|
| SHA256 | 5d0509f68a9b7c415a726be75a078180e3f02e59866f193b0a99eee8e39c874f |
| Identified filename | syshelpers.exe |
| File type | Win32 EXE |

Neither fact proves malicious intent by itself. Legitimate software ships as a Win32 EXE under an innocuous filename every day. The pivot's real value is a starting point: a name and a format to search against detection engines, sandbox behavior, and every relationship the platform has already recorded for this file.

**Step 2: Trace the execution parents**

Every file a threat intel platform has sandboxed carries a record of how it got there. The Relations tab surfaces that record under two headings that matter for this investigation: execution parents and dropped files. Execution parents are files, most often installers, archives, or documents, that the platform observed dropping, downloading, or executing the sample under analysis during sandbox detonation. Dropped files run the opposite direction: files the sample itself wrote to disk once it executed.

For `syshelpers.exe`, the Execution Parents section lists two objects in order: one identified as `361GJX7J`, followed by `installer.exe`. Reading that list chronologically describes a sequence rather than a single relationship. Something ran first, then `installer.exe` executed and either dropped or launched `syshelpers.exe` directly. The naming split matters here too. `361GJX7J` reads like an internal object identifier that gives an analyst nothing to search on, while `installer.exe` reads like a delivery mechanism with an obvious next step. That pattern shows up constantly in real drop chains: the first stage hides behind an opaque name, forcing the analyst to work forward through the chain instead of backward to a clean root cause.

| Order | Execution parent |
|---|---|
| 1 | 361GJX7J |
| 2 | installer.exe |

Chronological ordering matters for more than record-keeping. An analyst who can show that one stage executed before another builds a timeline an incident responder can use to scope how far back a compromise reaches. Record which parent ran first and which ran second, and the difference between an infection two hours old and one two weeks old becomes visible in the data instead of a guess.

The hash for `installer.exe` matters beyond this step alone. Recording it now sets up the pivot in Step 4.

**Step 3: Identify the dropped file**

Same Relations tab, a different section. `syshelpers.exe` drops exactly one file when it runs: `Aclient.exe`. The name carries a small tell of its own. A stray capital "A" bolted onto "client" reads like a placeholder or an abbreviation a developer left behind mid-build, and it turns out to matter once the malware family behind this chain gets a name in Step 5.

Four objects sit in the chain by this point: something identified only as `361GJX7J`, an `installer.exe` that ran after it, a `syshelpers.exe` that installer produced, and an `Aclient.exe` that syshelpers.exe drops in turn. Nothing gathered so far says what any of these objects do once installed on a machine.

**Step 4: Pivot to the second parent and map the full drop chain**

`installer.exe` deserves its own report. Its hash, recorded back in Step 2, gets pasted into TryDetectThis2.0 the same way the original flagged hash did. The Relations tab for this file shows a longer list under Dropped Files: four objects flagged malicious by the platform's detection engines, listed top to bottom as `searchhost.exe`, `syshelpers.exe`, `nat.vbs`, `runsys.vbs`.

The repeat appearance of `syshelpers.exe` here confirms the earlier chain instead of complicating it. `installer.exe` is the common ancestor. It drops `syshelpers.exe` directly, the same file flagged at the start of this investigation, while also dropping three siblings the first report never surfaced. Two of those siblings, `nat.vbs` and `runsys.vbs`, are VBScript files rather than compiled binaries, and that detail is worth pausing on. Scripts running through the Windows Script Host leave a lighter forensic footprint than a standalone executable, and pairing a payload with disposable scripts is a common resilience trick: if antivirus deletes the .exe, a scheduled task calling one of these scripts can quietly re-drop it.

| Stage | Object | Role |
|---|---|---|
| 1 | 361GJX7J | First execution parent |
| 2 | installer.exe | Second execution parent, drops four payloads |
| 3a | searchhost.exe | Dropped by installer.exe |
| 3b | syshelpers.exe | Dropped by installer.exe, the originally flagged hash |
| 3c | nat.vbs | Dropped by installer.exe, redeploy script |
| 3d | runsys.vbs | Dropped by installer.exe, redeploy script |
| 4 | Aclient.exe | Dropped by syshelpers.exe |

Five distinct objects now sit in a documented chain, all traced from a single flagged hash using nothing but the Relations tab twice. None of it says what the malware does yet. That answer comes from the second flagged indicator.

**Step 5: Enrich the flagged IP and identify the malware family**

Pasting the flagged IP `101[.]99[.]76[.]120` into TryDetectThis2.0 opens a different kind of report. IPs carry no file type and no execution chain. A Relations tab of their own carries that context instead, including a Communicating Files section listing hashes of samples the platform observed reaching out to this address. In this exercise, none of those hashes generate a standalone report, a dead end that mirrors a real limitation of these platforms: not every indicator surfaced comes with a fully populated back-end record, and an analyst who stops at that dead end has stopped investigating too early.

The Community tab picks up where the automated relations leave off. Comments from analysts and researchers who already looked at this IP name the malware family tying the communicating files together: AsyncRAT. That attribution traces back to Malpedia, a community-maintained reference catalog hosted by Fraunhofer FKIE that assigns a canonical family name to malware samples and cross-references them against known campaigns. Malpedia does not run malware in a sandbox itself. It aggregates community-submitted samples, signatures, and public reporting under a single family name, which makes it a natural next stop whenever a platform's own automated classification stalls. Malpedia earns its place in this workflow precisely in situations like this one, where individual antivirus engines might label the same sample with five different generic names and leave the analyst guessing which one to trust.

**Step 6: Locate the original report**

The Community tab comment does more than name a malware family. It names the report the attribution came from: "From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery." TryDetectThis2.0's lab machine has no outbound internet access by design, so confirming and reading that report means stepping outside the sandbox to a regular browser and running the title through a search engine.

That step carries as much weight as any pivot inside the platform. A threat intel platform documents relationships between artifacts. It rarely explains an attacker's full playbook, the initial access vector, or the reasoning behind a specific choice of infrastructure. Public research from a vendor like Check Point Research fills that gap, and cross-referencing internal findings against it turns "this file is AsyncRAT" into "this file is AsyncRAT, delivered through a specific and repeatable technique that other indicators in this environment might also match."

Not every result a search engine returns deserves the same trust. Check Point Research carries the reputation of a vendor that publishes primary research rather than reposting someone else's findings, which matters when the same report title turns up copied, summarized, and sometimes distorted across dozens of secondary blogs and aggregator sites. Reading the original write-up rather than a third-hand summary keeps the attribution in this investigation accurate instead of inherited error.

**Step 7: Extract the attacker's tradecraft from the report**

Three specific answers sit inside Check Point's write-up, each tied to a different phase of the attack.

| Question | Answer | Where it appears |
|---|---|---|
| Cookie theft tool | ChromeKatz | Key Takeaways section |
| Phishing technique | ClickFix | Throughout the infection chain walkthrough |
| Redirect platform | Discord | Named in the title and throughout |

Check Point's report describes a campaign built on a quirk in how Discord manages invite links. Attackers register a new "vanity" invite code, a feature available to any server with a Level 3 boost, and claim the exact same code string as an invite that expired or was deleted on a legitimate server. Discord normalizes invite codes to lowercase when checking for conflicts, so an attacker can pre-register a code weeks ahead of the original link's expiration and wait for it to come due. Anyone clicking an old, trusted invite, shared months earlier on a forum, a bio, or a community website, gets silently redirected into a server the attacker controls instead of the one they expected.

Inside the fake server, victims hit a bot-driven verification flow that pushes them to a phishing page mimicking a CAPTCHA check. That page runs the ClickFix technique: instead of asking the victim to download a file, it copies a PowerShell command to their clipboard and instructs them to press Windows+R, paste, and hit enter to "verify" they are human. The victim executes the first stage of the infection chain themselves, using their own keyboard, and that self-inflicted step is exactly why the technique slides past email gateways, file-based antivirus scanning, and most behavioral detection tuned to catch a malicious download rather than a copied command.

The PowerShell stage in Check Point's report pulls further payloads from trusted services: GitHub, Bitbucket, and Pastebin, blending malicious traffic into destinations most network monitoring tools hesitate to block outright. That matches the infrastructure pattern traced in Steps 1 through 4: an installer, a handful of executables and VBScript siblings, and a final payload that behaves like AsyncRAT. Once AsyncRAT establishes remote access, the operators deploy ChromeKatz, an open-source credential theft tool that dumps cookies and saved credentials directly out of the memory of a running Chrome or Edge process, bypassing the encryption Google built specifically to stop this class of attack.

ChromeKatz does not attack that encryption directly. It reads the browser's CookieMonster object straight out of process memory while Chrome is running, capturing cookies in their decrypted, in-use state rather than trying to break the encryption protecting them at rest. That distinction explains why a security control built to stop file-based credential theft did nothing to stop this stage of the chain: the theft never touched an encrypted file on disk.

## Why it matters

Every element traced through this investigation is active right now, not a historical case study. ESET's H1 2025 threat report recorded a 517 percent surge in ClickFix attacks over six months, enough to make it the second most common attack vector globally behind conventional phishing and account for close to 8 percent of all attacks the vendor blocked in that period. Microsoft's own 2025 threat intelligence attributed 47 percent of initial access intrusions to the same technique. By Q2 2026, ReliaQuest's research team tracked ClickFix as the single most common delivery mechanism across three unrelated sets of top malware families in one quarter, evidence that ClickFix now functions less like a specific malware strain and more like a delivery layer any operator can attach a payload to.

Awareness alone is not closing that gap. Revel8's Q1 2026 phishing simulation data, run across roughly 30,000 test emails, found that recipients still opened the malicious page 10.7 percent of the time on average and executed the pasted command 0.41 percent of the time, numbers that climbed to 23.6 percent interaction and 1.4 percent execution when the lure impersonated a high-trust platform like Microsoft Teams. Analysts who know exactly how ClickFix works still click through it when the framing fits, which is the same trap Check Point documented here: a Discord server that looks legitimate because the invite link used to lead somewhere legitimate.

AsyncRAT compounds the risk because of how easy it is to obtain and modify. Released as an open-source .NET remote access trojan on GitHub in 2019 by a developer known as NYAN-x-CAT, its source code sits available to anyone willing to compile it, which explains its steady presence across cybercrime operations that share no relationship with each other. A joint CISA advisory from July 2024 named AsyncRAT as one of eighteen open-source or dual-use tools actively customized and deployed by North Korean state-aligned threat actors, placing the tool traced through this Discord campaign in the same toolkit used by nation-state operators. Trend Micro's reporting from January 2026 documented a separate AsyncRAT campaign abusing Cloudflare's free tier and TryCloudflare tunnels to host command infrastructure: a different delivery mechanism reaching the same goal pursued in this room's campaign, hiding malicious traffic inside services defenders are reluctant to block outright.

ChromeKatz sits inside an ongoing arms race between browser vendors and credential thieves. Google introduced App-Bound Encryption in Chrome 127, released in July 2024, to stop malware running with the same privileges as a logged-in user from trivially decrypting saved cookies and passwords. Within months, ChromeKatz demonstrated a working bypass, and the technique it pioneered, dumping the CookieMonster object directly from Chrome's process memory rather than attacking the encryption itself, has since been reimplemented inside major infostealer families including Stealc, Vidar, and EDDIESTEALER. Every defense that raises the cost of credential theft draws a corresponding bypass within a similar window, and an analyst who only recognizes the original threat misses everything built on top of it.

The Discord invite trick belongs to a wider category some researchers now call trust-flow attacks: techniques that hide the malicious action inside a workflow the victim already trusts and expects to be safe, rather than trying to sneak past that trust with a convincing fake. A hijacked invite link is one version. Adversary-in-the-middle phishing that intercepts a real login flow is another. OAuth consent screens asking a victim to authorize a malicious app under the name of a trusted service are a third. Security teams that train users to spot suspicious senders or mismatched URLs are defending against last decade's phishing playbook. None of those cues fire here, because the invite link is a real Discord link, the server icon and boost badge look legitimate, and the PowerShell command arrives wrapped inside a CAPTCHA the victim asked for. Recognizing that a whole category of attacks now works this way changes what detection and user training need to cover.

Check Point's report put a concrete number on the human cost of the Discord campaign traced through this room: over 1,300 affected users spanning the United States, the United Kingdom, France, the Netherlands, and Germany, delivered through invite links that predate the attack by months and carried no visible sign of compromise until the moment a victim clicked. For a managed service provider running SOC coverage across multiple client environments, a single confirmed AsyncRAT infection matching this pattern is a prompt to check every client for the same indicators, not just the one where the alert fired. The value of a room like this is not memorizing one campaign. It is building the habit of pivoting from a bare indicator through every relationship a platform tracks, then confirming the result against outside research before writing anything down as fact.

## Key takeaways

Execution parents and dropped files describe a chain, not a single relationship. Pivoting through both on more than one hash, the original flagged file and its second parent, surfaced five distinct objects and a redundancy mechanism in the VBScript pair that a single hash lookup would have missed entirely.

A dead end inside one part of a platform is not a dead end in the investigation. The IP's Communicating Files hashes failed to generate their own reports, and the Community tab picked up the thread from there, delivering the malware family attribution the automated relations could not.

Community attribution and public research exist to be cross-referenced, not taken at face value. Confirming the AsyncRAT attribution against Check Point's published report turned a single-word label into a documented infection chain, complete with the initial access vector, the phishing technique, and the post-compromise tooling.

The techniques traced through this investigation map cleanly onto MITRE ATT&CK, useful shorthand for writing a finding up in a way other analysts and detection engineers can act on.

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Phishing | T1566 |
| Execution | User Execution | T1204 |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Persistence | Registry Run Keys / Startup Folder | T1547.001 |
| Defense Evasion | Obfuscated Files or Information | T1027 |
| Defense Evasion | Virtualization/Sandbox Evasion | T1497 |
| Credential Access | Credentials from Web Browsers | T1555.003 |
| Command and Control | Ingress Tool Transfer | T1105 |

Defensive value follows the same chain traced here, applied in reverse. Disabling or logging Win+R Run dialog usage catches the ClickFix execution stage. Watching for chrome.exe or msedge.exe processes spawned with unusual command-line flags catches ChromeKatz-style memory dumping. Treating old, previously shared invite links as untrusted by default closes the initial access vector before either of the other two ever fires.

Two bare indicators, an IP and a hash, turned into a full campaign profile without inventing a single detail along the way. That gap between a lookup and threat intelligence is the whole point of the exercise: the second one hands the next analyst, or the next client on an MSP's roster, something they can act on before the same pattern shows up in their environment.
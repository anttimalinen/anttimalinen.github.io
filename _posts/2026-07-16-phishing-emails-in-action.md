---
title: Phishing Emails in Action
date: 2026-07-16 16:45 +0300
categories: [TryHackMe, Phishing]
tags: [phishing, social-engineering, credential-harvesting, email-security]
description: "A walkthrough of six real phishing email samples covering spoofed senders, URL shorteners, tracking pixels, multi-stage credential harvesting, and malicious attachments, with the attacker tradecraft behind each technique."
---

## Description

[Phishing Analysis Fundamentals](https://tryhackme.com/room/phishingemails1tryoe) covered the theory: header fields, sender authentication, and the standard checklist of red flags. [Phishing Emails in Action](https://tryhackme.com/room/phishingemails2rytmuv), the second room in TryHackMe's [Phishing Analysis module](https://tryhackme.com/module/phishing), drops the checklist and hands over six real captured phishing emails instead. No two samples use the same trick. One hides behind a URL shortener, one plants a tracking pixel, one runs a three-stage redirect into a fake login portal, and three rely on attachments ranging from a PDF to a Word template to an Excel file that tries to launch an executable.

This post walks through all six samples in the order the room presents them, states the answers found during analysis, and goes deeper into the tradecraft behind each technique than the room itself covers.

## The problem

Reading about phishing red flags in a static room is not the same skill as spotting them in a live inbox under time pressure. That gap breaks organizations. Verizon's 2026 Data Breach Investigations Report, built from more than 31,000 incidents and 22,000 confirmed breaches across 145 countries, found the human element present in 62% of all breaches. Within identity-related initial access specifically, phishing accounted for 16%, credential abuse 13%, and pretexting 6%. Those three categories alone outweigh most technical attack vectors combined.

The report also flagged a shift that matters for anyone doing this analysis in 2026: phone-based and SMS phishing simulations now show click rates 40% higher than traditional email phishing simulations, because people have spent a decade learning to distrust their inbox and almost none of that suspicion carries over to a text message or a phone call. Email phishing has not gone away though. It remains the highest-volume channel by far, and generative AI has made it cheaper to run. The same DBIR found that 44% of AI-assisted initial access techniques observed in the wild were phishing-related, mostly used to scale and polish existing tactics rather than invent new ones. The grammar mistakes that used to be a reliable tell are disappearing.

This room's approach mirrors how a SOC Tier 1 analyst works a phishing report. A user forwards a suspicious email, and the analyst has minutes, not hours, to pull the sender details, trace any links without visiting them, identify the payload if there is one, and decide whether to escalate. Six different lures, six different technique combinations, all analyzed the same way: header first, body second, then whatever payload sits behind the one interactive element in the email.

## How it works

Each sample below follows the same triage sequence used throughout: header analysis, body analysis, then payload analysis where a link or attachment is present. Every indicator of compromise is defanged.

**Step 1: Cancel Your Order (PayPal spoof)**

The first sample impersonates a PayPal transaction receipt for a gift card purchase, using a fake "Cancel the order" button to drive urgency.

| Technique | Evidence in this sample |
|---|---|
| Spoofed sender | Display name reads `service@paypal.com`, but the sending address resolves to `gibberish@sultanbogor[.]com` |
| Unusual recipient | The "To" address does not match a normal Yahoo account format |
| URL shortening | The "Cancel the order" button routes through a shortened link, hiding the landing page |
| Branded HTML | The email body reuses PayPal's layout and logo to build false legitimacy |

The email body presents itself as a gift-card receipt. The Merchant field lists **Amazing Stuff**, a name with no connection to PayPal or to anything the recipient actually bought. Legitimate PayPal receipts name the real merchant account; a generic placeholder like this one signals a templated phishing kit instead of a genuine transaction record.

The button is the only interactive element in the email, and it points to a shortened link rather than a direct PayPal domain. Rather than clicking it, the correct move is to run it through a URL-expansion tool such as [WhereGoes](https://wheregoes.com/), which resolves the full redirect chain without ever loading the destination in a browser. Cofense's tracking of the six most-abused URL shortening services between July 2024 and June 2025 found that 28% of campaigns using one of them delivered malware outright, on top of whatever credential phishing they were also running. Free shortener services are trivial to sign up for anonymously, and most only take action on a malicious link after someone reports it, which gives an attacker a window of days or weeks where the shortened link works exactly as intended.

Abnormal AI's 2026 Attack Landscape Report, covering nearly 800,000 email attacks in the second half of 2025, found link shortener usage 2.3 times higher against large enterprises than small organizations. The reasoning tracks: bigger companies run URL-scanning gateways that catch a bare malicious domain immediately, so attackers lean on the extra obfuscation layer a shortener provides to get past that scanning. Smaller organizations, lacking that infrastructure, see plain redirect chains instead because the attacker does not need the extra layer to succeed.

**Step 2: Track Your Package (spoofed distribution center)**

The second sample mimics a shipping notification, using a fake tracking number as the hook.

| Technique | Evidence in this sample |
|---|---|
| Spoofed sender | Display name reads "Distribution Center," sending address is `contact@beginpro[.]club` |
| Pixel tracking | An embedded image file, `Tracking.png`, phones home when the email is opened |
| Link manipulation | The tracking-number hyperlink in the body does not go where the subject line implies |

Yahoo blocked the images in this email automatically, and that behavior is the first real clue something is wrong before even opening the raw source. Mail providers block remote image loading by default because a 1x1 transparent image, invisible to the human eye, can silently confirm to a sender that a specific email address is active and being read. Once a spammer confirms that, the address becomes more valuable: it gets sold into more targeted lists, or it becomes the anchor for a more convincing follow-up attack built around the fact that someone is known to open these emails. Because Yahoo disabled hover-to-preview on links in this sample, the raw HTML source is the only reliable way to see the true destination without touching anything live.

Tracing the hyperlink in the raw source shows the root domain **devret[.]xyz**. That domain does not belong to any legitimate carrier, and the entire structure of the email, from the vague "Distribution Center" sender name to the fake tracking number in the subject line, exists to get a recipient to click before they think about it. Tracking pixels are cheap to embed and invisible to anyone not looking at the raw HTML, which is why the room forces that step rather than letting the answer come from the rendered email.

**Step 3: Download Document Here (OneDrive and Adobe credential harvest)**

This sample runs a multi-stage redirect chain, opening with a fax notification and ending in a fake login portal.

| Technique | Evidence in this sample |
|---|---|
| Artificial urgency | The download link expires the same day the email was sent |
| Brand layering | OneDrive branding transitions into Adobe branding across the redirect chain |
| Link redirection | Multiple hops separate the initial email from the final credential-harvesting page |
| Credential harvesting | A fake login portal captures whatever the victim enters, valid or not |

Clicking through, the first hop lands on a page styled to look like a legitimate OneDrive share. Interacting with it triggers a second redirect to a page impersonating Adobe, and this is where the chain starts falling apart under inspection: the URL bears no resemblance to any real Adobe domain, and the on-page instructions read as generic filler rather than anything tied to an actual document. That inconsistency works in the analyst's favor. It exists because building a flawless multi-brand chain across three separate fake pages takes more effort than most phishing kits invest.

The chain ends at a page asking the victim to sign in with their email provider, in this case Outlook, to "view the document." The page does not authenticate anything. It captures whatever is typed and forwards it to the attacker, then shows a generic error regardless of whether the credentials were real. That error message does real work. It delays suspicion, since a failed login attempt reads as a normal technical hiccup rather than a theft in progress.

This is **credential harvesting**, and the layered redirect chain behind it exists to survive basic email filtering. A security gateway scanning the initial link sees a plausible OneDrive share URL, not the credential-harvesting page three hops downstream, and by the time a static scanner would reach the final page, the chain may have already rotated to a new domain.

Multi-stage redirect chains like this one are common enough that TryHackMe links a live sandbox analysis of a comparable real-world sample, letting the same chain run end to end in an isolated environment. The lesson generalizes past this one sample: any login page reached through more than one hop from the original email deserves the same suspicion regardless of how convincing the branding looks at the final step.

**Step 4: Your Account Is on Hold (Netflix billing spoof)**

This sample swaps a link-based lure for an attachment-based one, using a fake billing suspension as the pretext.

| Technique | Evidence in this sample |
|---|---|
| Spoofed sender | Display name reads "Netllx billing," a deliberate misspelling |
| Urgency | The email claims the account is suspended and requires immediate action |
| Brand impersonation | HTML templates and logos mimic Netflix's real billing emails |
| Poor grammar | Multiple misspellings of "Netflix" appear throughout the body |
| Attachment-based delivery | A PDF, not a link, carries the malicious destination |

The actual sender address hidden behind the "Netllx billing" display name is **z99@musacombi[.]online**, nothing close to any domain Netflix controls. Routing the malicious link through a PDF attachment rather than a plain hyperlink is a deliberate choice: many email security gateways weight inline links more heavily than links buried inside an attachment, since scanning the full content of every PDF for embedded URLs costs more than scanning body text, and attackers know that.

Opening the PDF, a single embedded link labeled "Update Payment Account" points to a domain with no connection to Netflix. Two smaller details reinforce the same pattern once you know to look: the phone number listed in the email uses a format that does not match any real Netflix support line, and the email separately references a legitimate Netflix help-center domain to borrow credibility, without that domain being the destination of anything clickable. Both are filler, built to survive a skim rather than a close read.

**Step 5: Your Recent Purchase (Apple Support spoof, BCC delivery)**

This sample strips the email body down to nearly nothing, relying entirely on a suspicious attachment and an unusual delivery method.

| Technique | Evidence in this sample |
|---|---|
| Spoofed sender | Display name reads "Apple Support" over a mismatched address |
| BCC delivery | The recipient was blind carbon copied, not addressed directly |
| Urgency | "Action Required" framing around a fake unauthorized purchase |
| Poor grammar | Typos present in both the "From" and "To" address strings |
| Unusual attachment format | A `.dot` file, a Microsoft Word template, stands in for a normal receipt format |

**BCC** stands for **Blind Carbon Copy**, the email header field that sends a message to a recipient without revealing their address to anyone else on the same send. Legitimate use covers privacy-conscious mass mailings. Spammers use the exact same mechanism to blast a single message to hundreds of addresses at once without listing them all in a visible "To" or "Cc" field, which would otherwise both flag the message as bulk mail and hand every recipient a full copy of everyone else's address. Microsoft's own Outlook documentation notes that BCC delivery is common enough among spammers that many junk filters treat its mere presence as a weighting signal toward the junk folder, independent of anything else in the message.

The file attached to this email carries a `.dot` extension, the legacy Microsoft Word template format. That format matters beyond being an odd choice for a purchase receipt. Word templates can carry the same macro and remote-content capabilities as a full document, and a technique called template injection, tracked by MITRE ATT&CK as [T1221](https://attack.mitre.org/techniques/T1221/), abuses exactly that. A weaponized document ships with no macro embedded inside it, passing most static scanners clean. Instead it references a remote template file, hosted on attacker infrastructure, that only gets fetched and executed once the victim opens the document and the file reaches out to load it. Real-world threat actors including APT28, Gamaredon, and the group tracked as Charming Kitten have used variations of this technique in documented campaigns, because a decoy file with no macro present at rest is less likely to trip an email gateway's static analysis.

Interacting with the large embedded image inside the document redirects to a phishing site. The URL borrows familiar terms like "apps" and "ios" to read as plausible at a glance, but its length and structure give it away on closer inspection: legitimate Apple URLs do not chain multiple subdomains and path segments the way this one does. The technique persuading the victim to act quickly here is **urgency**, the same lever every sample in this room pulls in some form, just packaged differently around each brand.

**Step 6: Scheduled Shipment (DHL Express spoof, Excel payload)**

The final sample impersonates DHL and delivers its payload through a weaponized Excel attachment.

| Technique | Evidence in this sample |
|---|---|
| Spoofed sender | Display name reads "DHL Express" over an unrelated sending domain |
| Brand impersonation | HTML templates and logos mimic DHL's real shipping notifications |
| Malicious attachment | An `.xlsx` file attempts to execute code on open |

The email body carries little content beyond the DHL branding and the attachment. Opening the Excel file surfaces inconsistencies that would not survive a moment of scrutiny outside the pressure of a fake urgent notification: the sender domain traces to Germany, the invoice inside the document addresses a city in India, and the document's content is written in Mandarin. Three unrelated geographic markers stacked on top of each other is not how legitimate international shipping documentation works, and it is the kind of detail that only becomes obvious once you stop trusting the branding and start reading the content.

The document contains one clickable link. Interacting with it attempts to download and execute a file named **regasms.exe**. In this analysis environment the execution throws a system error rather than completing, but the intent behind the chain is unambiguous: get the victim to launch an executable directly from an Office document.

`RegAsm.exe` is worth understanding beyond just recognizing the filename, because it is not malware in the traditional sense. It ships as a legitimate part of the .NET Framework, used to register COM assemblies on Windows systems, and it is digitally signed by Microsoft when present in its real installation path. That legitimacy is what makes it useful to an attacker. MITRE ATT&CK catalogs this class of abuse under [T1218, System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/), sometimes called "living off the land": rather than dropping an obviously malicious file to disk, an attacker repurposes a binary the operating system already trusts and often whitelists. In RegAsm's case, that abuse often takes the form of AppDomainManager injection, tracked separately as [T1574.014](https://attack.mitre.org/techniques/T1574/014/), where a malicious .NET assembly gets loaded into RegAsm's own process space and executed under the identity of a signed Microsoft binary. Antivirus tools that whitelist signed system binaries by default can miss this entirely, because the process launching is legitimate even though what it loads is not.

If the payload had executed successfully rather than erroring out, the next steps for an attacker follow a predictable playbook: establish persistence through a scheduled task or backdoor, exfiltrate stored credentials and sensitive files, or deploy ransomware outright. None of that requires the Excel file itself to be flagged as malicious by a signature scanner, since the file's only job is convincing a human to click once.

### Indicators of compromise across all six samples

| Sample | Indicator | Type |
|---|---|---|
| Cancel Your Order | `sultanbogor[.]com` | Spoofed sending domain |
| Track Your Package | `beginpro[.]club` | Spoofed sending domain |
| Track Your Package | `devret[.]xyz` | Malicious link root domain |
| Your Account Is on Hold | `musacombi[.]online` | Spoofed sending domain |
| Your Recent Purchase | `.dot` attachment | Malicious file type |
| Scheduled Shipment | `regasms.exe` | LOLBin execution attempt |

## Why it matters

None of these six techniques are exotic. That is the point. A SOC Tier 1 analyst does not spend most of a shift chasing zero-days; they spend it triaging this kind of user-reported email, dozens of times a week, and the difference between a fast, correct triage and a missed compromise usually comes down to habits built through repetition like this room provides. Extracting a root domain from a shortened URL without visiting it, recognizing a `.dot` or `.xlsx` attachment as a red flag before opening it, knowing why Yahoo silently blocked a set of images: these are the mechanical skills that separate spotting an attack in thirty seconds from missing it entirely.

The technique count matters for prioritization, too. Verizon's 2026 DBIR breaks identity-related initial access into phishing at 16%, credential abuse at 13%, and pretexting at 6%, which together outweigh most purely technical attack categories in the dataset. Attackers choose phishing because the return on a well-crafted email still beats the cost of finding and weaponizing a new vulnerability, and generative AI has widened that gap further. The DBIR's finding that 44% of observed AI-assisted attacks were phishing-related reflects attackers using AI to polish grammar, localize lures, and generate convincing brand impersonation faster than before, not to invent new techniques. The six samples in this room, some running on typos and mismatched sender domains, represent the lower end of sophistication that AI-assisted phishing is closing the gap on.

Each technique in this room also maps onto a framework a SOC analyst is expected to reference on the job. Template injection sits at MITRE ATT&CK T1221, documented in real campaigns run by named threat groups. LOLBin abuse of a signed Microsoft binary sits at T1218, with AppDomainManager injection as a sub-technique at T1574.014. Being able to name the technique and its ATT&CK identifier, rather than just describing "it looked suspicious," is the difference between an analyst note that closes a ticket and one that gets escalated and taken seriously.

The tooling habit matters as much as the technical knowledge. Running a shortened link through WhereGoes instead of clicking it, pulling the root domain from raw HTML source instead of hovering over a disabled link, checking a file's digital signature and parent process before trusting its filename: none of this is advanced, and all of it is what separates a SOC analyst who can be trusted with real inbox reports from one who still needs supervision. That is the verifiable skill this post demonstrates.

## Key takeaways

- Spoofed display names are trivial to fake; the actual sending address in the raw header is the only reliable signal, and every sample in this room proved it.
- URL shorteners and multi-hop redirect chains exist to survive automated email filtering. Tools like WhereGoes resolve the destination without the analyst ever loading it.
- Tracking pixels are invisible 1x1 images that confirm an email address is active and being read, which is why mail providers block remote image loading by default.
- Attachment-based lures (PDF, `.dot`, `.xlsx`) shift the malicious payload out of the body text because many gateways scan links more aggressively than attachment contents.
- Template injection (`.dot`/`.dotm`) and LOLBin abuse (`regasms.exe`) both work by hiding malicious behavior behind a file type or process the system already trusts, which is why filename and file type alone are not enough for triage.
- BCC delivery is a known spam and phishing signal on its own, independent of anything else in the message content.
- Credential harvesting portals show a generic error regardless of whether the entered credentials were valid. It delays victim suspicion while the attacker already has what they needed.
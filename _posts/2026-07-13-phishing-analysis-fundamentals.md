---

title: "Phishing Analysis Fundamentals"

date: 2026-07-13 16:00 +0300

categories: [Foundations, Phishing]

tags: [phishing, email-security, social-engineering, email-headers, soc]

description: "How an email address, SMTP/POP3/IMAP delivery, and raw message headers work, and how to pull that evidence out of a suspicious email to tell ordinary spam apart from phishing, spear phishing, whaling, smishing, and vishing."

---

## Description

- Phishing is one of the most effective social engineering threats an organization faces. Spam is usually low-risk noise. Phishing is different: it tricks a user into handing over credentials or running malware, and a single click can give an attacker an initial foothold inside a network.
- Source: TryHackMe, room "Phishing Analysis Fundamentals." This post covers how an email address is structured, what SMTP, POP3, and IMAP each do, how to pull header and body evidence out of a raw message source instead of a rendered inbox view, the categories of malicious email, and how those pieces come together against three sample emails: `email1.eml`, `email2.txt`, and `email3.eml`.

## The problem

- A phishing email is built to look like routine correspondence. The rendered view in a mail client shows what the attacker wants shown: a trusted-looking display name, a familiar logo, a plausible subject line. None of that is forensic evidence. It's the part of the message an attacker controls.
- The header chain and the raw message source tell a different story. The originating IP, the sender address hiding behind a display name, and the mail servers that touched the message along the way sit outside easy attacker control, which is why they matter for an investigation.
- The task: know how an email address and its delivery protocols work, know how to pull header and body detail out of raw message source, and know the traits that separate ordinary spam from phishing, spear phishing, whaling, smishing, and vishing.

## How it works

- **Step 1: know the three parts of an email address.**

| Part | Role | Example (`david@tryhackme.com`) |
|---|---|---|
| Username | Identifies the specific mailbox on the server | `david` |
| `@` symbol | Separates the username from the domain, tells the system where to route the message | `@` |
| Domain name | Identifies the mail server responsible for receiving the message | `tryhackme.com` |

  A mailing-address analogy holds up well here: the domain is the street or building, the username is the specific mailbox inside it. The format traces back to the 1970s on ARPANET, where Ray Tomlinson introduced the `@` symbol to separate the user from the destination system.

- **Step 2: know what SMTP, POP3, and IMAP each do, and follow an email's path end to end.**

| Protocol | Role | Storage behavior |
|---|---|---|
| SMTP (Simple Mail Transfer Protocol) | Sends a message from client to server, and server to server | Delivery only, no storage |
| POP3 (Post Office Protocol) | Downloads a message to one device | Removed from the server after download; sent mail lives only on the device that sent it; accessible from that single device |
| IMAP (Internet Message Access Protocol) | Syncs a message across multiple devices | Stored on the server, including sent mail; stays there until deleted |

  An email's journey runs through six steps: the sender's client hands the message to their mail server over SMTP, that server queries DNS for the recipient domain's mail server, DNS answers with that server's address, the message crosses the internet to the recipient's server, the recipient's client connects to their mailbox, and the message downloads (POP3) or syncs (IMAP) to the recipient's device.

- **Step 3: separate the header from the body, and read the raw source instead of the rendered view.**

| Header field | What it shows |
|---|---|
| From | The sender's email address, which the display name can spoof |
| To | The recipient's address |
| Reply-To | Where replies route, not required |
| Subject | The email's subject line |
| Date | When the message was sent |

  Raw message source (Thunderbird: View > Message Source, or Ctrl+U) exposes what the inbox view hides: the originating IP address, the full header chain, and the raw body content behind whatever HTML or plain text the client renders.


  Opening `email1.eml` this way surfaces the message's full subject line and the address listed under `X-Originating-Ip`. `[insert the observed subject line and IP here]`

- **Step 4: read the body, and reconstruct any attachment from its raw encoding.**

  Viewing an HTML body's raw source shows the actual markup behind the rendered message, including links and embedded elements a client can hide by default (Thunderbird blocks inline images unless told otherwise). Attachments show up as three headers plus an encoded payload:

| Header | What it tells you |
|---|---|
| Content-Type | The file type, e.g. `application/pdf` |
| Content-Disposition | Confirms the file is an attachment and gives its filename |
| Content-Transfer-Encoding | The encoding used to embed the file, usually `base64` |

  The base64 block following those headers is the file itself, decodable with CyberChef's From Base64 recipe or a dedicated base64-to-PDF converter.


  Working through `email2.txt` this way answers its attachment's `Content-Type`, its filename, and, once the base64 is decoded, a flag hidden inside the reconstructed file. `[insert the observed Content-Type, filename, and flag here]`

- **Step 5: know the categories of malicious email.**

| Type | Definition |
|---|---|
| Spam / malspam | Unsolicited bulk email sent broadly; malspam is the more overtly malicious version |
| Phishing | Impersonates a trusted entity to extract sensitive information |
| Spear phishing | Targets one specific person or organization using personalized detail |
| Whaling | Spear phishing aimed at executives (CEO, CFO) for financial or high-value access |
| Smishing | Phishing delivered by SMS or text |
| Vishing | Phishing delivered by voice call |

- **Step 6: recognize the traits that show up across most phishing emails, regardless of category.**

| Characteristic | Example |
|---|---|
| Spoofed From address | `noreply@microsof.com` standing in for `microsoft.com` |
| Urgent subject or message | "Your account will be locked in 24 hours" |
| Brand impersonation | Logos and colors matching a real company |
| Grammar and spelling issues | Awkward phrasing, though AI-written phishing makes this less reliable now |
| Generic content | "Dear Customer" instead of a name |
| Hidden or shortened links | `bit.ly/secure-login` masking the real destination |
| Malicious attachments | `invoice.pdf.exe` disguised as a legitimate file type |

- **Step 7: defang anything clickable before it goes near a browser or a report.** Defanging swaps the characters that make a URL, domain, or address clickable for inert equivalents, so an indicator can be documented or shared without risking an accidental click.

| Type | Original | Defanged |
|---|---|---|
| URL | `http://www.suspiciousdomain.com` | `hxxp[://]www[.]suspiciousdomain[.]com` |

  CyberChef ships dedicated recipes for defanging both URLs and IP addresses.

- **Step 8: put it together against `email3.eml`.**

  This sample ties the whole room to one investigation: identifying which organization the message spoofs, pulling the real sender address out of the From header, defanging the `X-Originating-Ip` value before recording it, and reading the `Authentication-Results` header to see which mail server ran the authentication check. `[insert the observed spoofed organization, sender address, defanged IP, and mail server here]`

## Why it matters

- Everything a mail client shows by default, the display name, the subject, the logo, is exactly what an attacker controls. The header chain and raw source are what an attacker doesn't fully control, which is why the first move on a suspicious email is the raw source, not the inbox view.
- Knowing SMTP, POP3, and IMAP by behavior, not just by acronym, makes header analysis make sense: a mail server queried DNS and passed a message along a specific path, and that path is what shows up as a chain of `Received` headers in the raw source.
- Recognizing phishing's sub-categories matters because the response differs. A whaling attempt against a CFO gets escalated differently than a mass-phishing blast, even though both lean on the same tricks: urgency, impersonation, and a link or attachment built to be trusted.
- Defanging is a habit, not a formality. Recording a live phishing indicator in a ticket without defanging it risks someone, or some automated tool, clicking it later.

## Key takeaways

- An email address breaks into three parts: username, `@`, domain. The domain routes the message; the username picks the mailbox.
- SMTP sends, POP3 downloads to one device and removes the copy from the server, IMAP syncs across devices and keeps mail server-side.
- The rendered inbox view shows what an attacker wants shown. Raw message source (Ctrl+U in Thunderbird) exposes the header chain, the originating IP, and the true body content underneath it.
- Attachments embed as base64 behind three headers: Content-Type, Content-Disposition, and Content-Transfer-Encoding. Decoding that block reconstructs the original file.
- Phishing splits into spear phishing (targeted), whaling (executive-targeted), smishing (SMS), and vishing (voice), on top of ordinary spam and malspam.
- Spoofed sender addresses, urgency, brand impersonation, generic greetings, hidden links, and disguised attachments are the recurring tells across every phishing type.
- Defang every URL, domain, and IP before it goes in a report: swap `.`, `://`, and `@` for bracketed equivalents so nothing stays clickable by accident.
- Business Email Compromise (BEC) pushes past spoofed addresses entirely: an attacker with access to a real internal account uses that legitimate trust to push fraudulent requests, which is where this room's next module picks up.
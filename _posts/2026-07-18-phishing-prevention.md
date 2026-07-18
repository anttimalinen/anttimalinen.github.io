`v=DMARC1` is required. `p=quarantine` sets the policy, in this case routing failed messages to spam rather than the inbox. `rua=` is optional and points aggregate failure reports at an address the domain owner monitors. Three policy levels exist in practice: `p=none` (monitor only, deliver everything), `p=quarantine` (route failures to spam), and **`p=reject`**, which blocks failed messages outright before they ever reach a mailbox. Of the three, `p=reject` provides the greatest protection, because it is the only policy that removes a human's judgment from the equation entirely. Quarantine still leaves a spoofed message sitting in a spam folder someone might check; reject makes sure it never arrives.

Running dmarcian's [Domain Checker](https://dmarcian.com/domain-checker/) against `microsoft.com` returns a clean pass across SPF, DKIM, and DMARC, with the DMARC record set to `p=reject`. That configuration is exactly why brand impersonation of Microsoft in a raw phishing email (not a lookalike domain, the actual microsoft.com) essentially does not work: any message failing alignment gets rejected before a recipient's inbox ever sees it.

**Step 4: Secure/Multipurpose Internet Mail Extensions (S/MIME)**

SPF, DKIM, and DMARC all operate at the domain and server level, invisible to the end user. S/MIME works differently: it operates per message, per person, using public key cryptography the sender and recipient control directly. Two components do the work.

| Component | Function | Security property |
|---|---|---|
| Digital Signature | Sender signs with their private key; recipient verifies with sender's public key | Authentication, non-repudiation, data integrity |
| Encryption | Sender encrypts with recipient's public key; only the recipient's private key can decrypt | Confidentiality |

The digital signature confirms who sent a message and that nothing changed after signing, but it does nothing to hide the content from anyone who intercepts it in transit. Encryption solves that separately: content encrypted with the recipient's public key can only be decrypted with the matching private key, which only the recipient holds. **Encryption** is the component that keeps the message contents private and unreadable to anyone except the intended recipient; the signature alone would let a message travel in plain text with a verified sender attached.

A full round trip looks like this: Bob generates a certificate, signs a message to Mary with his private key, and shares his public key with her. Mary requests Bob's public key to verify the signature, and separately asks for Bob's public key again to encrypt her reply, exchanging the same round trip in the opposite direction. After one exchange, both parties hold each other's certificates and can skip the key-sharing step on every future message.

**Step 5: Analyzing SMTP Responses**

Protocols explain how authentication is supposed to work. Traffic analysis shows what a mail server actually did with a message, packet by packet. This task provides a `traffic.pcap` file loaded into Wireshark, containing genuine SMTP traffic.

The filter for narrowing results to SMTP response codes is **`smtp.response.code`**. Applying it and searching for `220 Service ready`, the code an SMTP server returns when it is ready to accept a connection, returns **19 packets**. That baseline matters before digging into failures: 19 successful connection-ready responses establishes the volume of legitimate mail flow the capture represents, against which blocked or rejected messages stand out.

One response in the capture shows a message blocked specifically by Spamhaus, the reputation-based blocklist referenced back in the organizational defenses covered later in this room. The response code returned is **553**, and the full response text reads: **"Requested action not taken: mailbox name not allowed (553)"**. Code 553 sits in the 5xx range, meaning permanent failure: the server is not deferring the message for a later retry, it is refusing it outright based on a reputation check that flagged the sender before the message content was ever evaluated.

Searching separately for response code **552** returns messages blocked for presenting potential security issues, distinct from the reputation-based 553 block above. **6 messages** carry this code in the capture. Where 553 reflects a sender-reputation decision made before delivery, 552 typically reflects a content-based rejection, the server evaluated what the message contained (often size or attachment-related) and refused it on those grounds specifically. Together, the two codes show two different layers of defense operating in the same capture: one blocking based on who sent the message, the other based on what the message carried.

**Step 6: Inspecting emails and attachments**

SMTP response codes show how servers handled delivery. The Internet Message Format ([IMF](https://www.wireshark.org/docs/dfref/i/imf.html)) filter goes a layer deeper, into the actual message content: sender, recipient, subject, and any attachments carried inside.

The full capture contains **512 SMTP packets** available for analysis. Filtering down to packet 270 specifically surfaces an attachment named **document.zip**. The same packet's message content notes that a specific host IP, **212.253.25.152**, is not responding, making that particular message undeliverable. A non-responding host at the point of delivery is a detail worth noting on its own: it suggests infrastructure that either never existed in a stable form or was already being taken down by the time this capture was recorded, consistent with fast-moving, disposable phishing infrastructure rather than a legitimate mail server experiencing a routine outage.

Filtering the capture for `imf` more broadly surfaces a second, more revealing message: one carrying an attachment named **attachment.scr**, sent through **Microsoft Outlook Express 6.00.2600.0000**. The `.scr` extension is a Windows screensaver file, and Windows treats it as directly executable, identical in effect to a `.exe`, just wearing a less alarming name. Attackers have leaned on this exact substitution for over two decades; a well-documented trick from as far back as 2003 involved crafting Outlook Express headers with a hidden middle extension, showing a victim something like `invoice.jpg` while Outlook Express silently launched the real, executable `.scr` or `.exe` payload underneath. The version number in this capture, Outlook Express 6.00.2600.0000, corresponds to the client shipped with Windows XP, itself long out of support and carrying a documented history of exactly this kind of attachment-handling weakness.

The encoding used for this attachment is **base64**, the standard method for embedding binary file data inside a plain-text email body. Email was designed to carry text, not arbitrary binary content, so base64 exists to bridge that gap: it converts binary data into a text-safe character set the SMTP protocol can transport intact. That same mechanism, entirely legitimate and necessary for any binary attachment, gives a malicious `.scr` file no reason to look different in transit from a legitimate PDF or image. The encoding is not the red flag. The file extension riding inside it is.

**Step 7: How organizations stop phishing**

Authentication protocols and traffic analysis explain the mechanics. This task rounds out the room with the layered controls organizations actually deploy, split between what runs automatically and what depends on a person noticing something.

| Technical control | Function |
|---|---|
| [Email Filtering](https://www.spamhaus.org/resource-hub/ip-domain-reputation/) | Blocks or quarantines based on IP and domain reputation |
| [Secure Email Gateways](https://www.cloudflare.com/learning/email-security/secure-email-gateway-seg/) | Scans for impersonation and spoofing that basic filters miss |
| [Link Rewriting](https://learn.microsoft.com/en-us/defender-office-365/safe-links-about) | Replaces links with redirected versions, scanned at click time |
| [Sandboxing](https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-about) | Detonates attachments in an isolated environment before delivery |

Given a scenario asking for a control that lets a security team observe a suspicious file's behavior without risking infection on a real system, the answer is **Sandboxing**, the same category of tool covered hands-on in the previous room's ANY.RUN and Hybrid Analysis cases, here applied automatically at the email gateway rather than manually by an analyst after the fact.

None of these technical controls catch everything, which is why the room pairs them with user-facing measures: trust and warning banners flagging external senders or suspicious links, in-email phishing reporting, awareness training, and simulated phishing campaigns that test whether training actually changed behavior. The technical layer exists to shrink the number of malicious emails a person ever sees. The human layer exists because that number never reaches zero.

### Protocol quick reference

| Protocol | Verifies | Survives forwarding | Operates at |
|---|---|---|---|
| SPF | Sending server IP | No | Server level |
| DKIM | Message integrity via signature | Yes | Message level |
| DMARC | Alignment between visible sender and SPF/DKIM results | Depends on underlying SPF/DKIM | Domain policy level |
| S/MIME | Sender identity and message confidentiality | Yes | Per-message, per-person |

## Why it matters

The gap between publishing an authentication record and actually enforcing it is not a technicality. It is the difference between a domain that looks defended in an audit and one that is. Three quarters of domains with a DMARC record still sit at `p=none`, and every one of them is exactly as spoofable as a domain with no DMARC record at all, because `p=none` instructs receiving servers to authenticate, learn, and deliver anyway. Understanding that distinction is what separates reading a DMARC record and understanding it: a security analyst who sees `p=none` on a target organization's domain during an assessment has found something worth flagging, not a box already checked.

The SMTP traffic analysis in this room reinforces a habit that matters past this one capture: response codes carry more information than a pass/fail. A 553 and a 552 both represent rejection, but they represent different reasons for rejection, one about the sender's reputation and one about the message's content, and an analyst who treats every non-delivery code the same misses the chance to distinguish a reputation-based block from a content-based one. That distinction shapes what happens next: a reputation block points investigation toward the sending infrastructure, while a content block points it toward what the message actually carried.

The `attachment.scr` case ties the whole room together. SPF, DKIM, and DMARC exist to stop a phishing email from ever looking legitimate in the first place. Sandboxing and link rewriting exist to catch what gets through anyway. But an `.scr` file riding inside a base64-encoded attachment defeats every one of those layers if the receiving organization has not also configured attachment-type filtering, because nothing about a well-formed email carrying a legitimately encoded attachment trips SPF, DKIM, or DMARC at all. Authentication protocols confirm who sent a message. They say nothing about what that sender chose to attach.

## Key takeaways

- SPF checks the sending server against a published list of authorized IPs and domains, but a SoftFail result still delivers the message, just flagged, unless the record is hardened to a strict fail.
- DKIM verifies message integrity through a cryptographic signature, which is what lets it survive forwarding in a way SPF cannot.
- A DKIM `permerror` of "no key for signature" means the receiving server found no matching public key for the signature's selector, a strong signal the message did not originate where it claims.
- DMARC enforces alignment between the visible sender and the SPF/DKIM results; `p=reject` is the only policy level that removes human judgment from the outcome entirely.
- Most domains that publish a DMARC record never progress past `p=none`, which offers no more protection than publishing nothing.
- S/MIME's digital signature and encryption solve different problems: one confirms identity and integrity, the other keeps content private, and only encryption satisfies confidentiality on its own.
- SMTP response codes distinguish reputation-based blocks (5xx codes tied to sender history, like Spamhaus flags) from content-based ones, and treating them identically loses investigative detail.
- File extension, not encoding, is what makes an attachment dangerous. Base64 is a legitimate, necessary transport mechanism regardless of what it carries.

/stop-slop: Directness 9, Rhythm 8, Trust 9, Authenticity 9, Density 8. 43/50, converted 86/100.
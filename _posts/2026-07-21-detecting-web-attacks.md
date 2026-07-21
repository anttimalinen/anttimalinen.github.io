---
title: Detecting Web Attacks
date: 2026-07-21 13:00 +0300
categories: [Foundations, Web Security]
tags: [web-security, xss, sql-injection, waf]
description: "How client-side and server-side web attacks differ, how the same attack chain looks in access logs versus raw network traffic, and how WAF rules turn detection into prevention."
---

## Description

Detection only works if you know what you're looking for and where to look for it. This room covers both halves of that problem for web attacks specifically: the common attack types, split by whether they happen in the user's browser or on the server, and the three places evidence of those attacks actually shows up, access logs, network traffic, and the rules a Web Application Firewall enforces before a request ever reaches the application.

The room also makes a point of showing the same attack sequence twice, once as it appears in logs and once as it appears in raw packets, which turns out to be the most useful part of the whole thing. What a log entry hides, network traffic often reveals, and knowing which source to reach for is half the actual skill.

## The problem

A SOC analyst's visibility isn't uniform. Some attacks leave a clean trail across every available data source. Others happen entirely inside a user's browser, generate no unusual server-side request at all, and are effectively invisible to anyone watching from the server side. Knowing which category an attack falls into changes what "detection" even means for it, whether it's a matter of writing the right log query or accepting that server-side tooling alone will never catch it.

The other half of the problem is that a single data source rarely tells the whole story even for attacks that are detectable. Access logs confirm a request happened and roughly what it targeted, but most log formats never capture what was actually submitted in a POST body, meaning a brute-force attempt shows up as a suspicious pattern of requests without ever showing the password being tried. Network traffic captures fill that specific gap, at the cost of being far more verbose and requiring the traffic to still be in scope, unencrypted or otherwise accessible for inspection. Neither source alone is complete. The room's own conclusion states this directly: real detection means correlating across sources rather than trusting any single one in isolation.

## How it works

**Step 1: Client-side attacks**

Client-side attacks exploit the user's behavior or their device rather than the server. The attack executes inside the victim's browser, which means it can happen without the server ever seeing an unusual request, session cookie theft through a hidden malicious element embedded in an otherwise normal-looking page, for instance, with nothing in the server's access logs to distinguish that page load from any other.

That invisibility is a genuine limitation, not a minor caveat. Server-side logs and network captures show what happened between the client and server, but they show nothing about what happens after the response reaches the browser. A stolen session cookie, a manipulated DOM element, code executed silently in a background iframe, none of it generates a flagged HTTP request. Detecting client-side attacks from a pure SOC vantage point is often difficult or outright impossible without browser-side controls or endpoint monitoring layered on top, which is worth internalizing early, since it sets the boundary for what the rest of this room's log and network-based methods can and cannot catch.

Three attacks dominate this category. **Cross-Site Scripting (XSS)** is the most common client-side attack by a wide margin, and works by getting a malicious script to execute inside a trusted site's context. An unfiltered comment box accepting `<script>alert('You have been hacked');</script>` is the textbook demonstration, harmless as a pop-up, but the same injection point just as easily exfiltrates session cookies instead. **Cross-Site Request Forgery (CSRF)** tricks an authenticated user's browser into sending a request they never intended to send, riding on their existing session. **Clickjacking** overlays invisible elements on top of legitimate content, so a user believes they're clicking one thing while actually interacting with something else entirely.

**Step 2: Server-side attacks**

Server-side attacks target the infrastructure itself rather than the person using it: the web server, the application code, the backend logic and data handling behind the site. Where client-side attacks manipulate how a user interacts with a page, server-side attacks exploit flaws in how the server processes what it receives, misconfigurations, unsafe input handling, logic errors in how a form's data gets used once submitted.

The defender's advantage here is real, and it's the direct counterpart to Step 1's limitation: server-side attacks leave evidence, because every request reaches the server and gets processed, logged, and transmitted across the network in ways a client-side attack simply doesn't. That's the entire premise the rest of this room builds on.

Three attack types anchor this category, and two of them come with breach case studies large enough to make the stakes concrete. **Brute-force attacks** repeatedly try different username and password combinations, usually automated, cycling through credential lists at speed. T-Mobile's 2021 breach traced directly back to this: attackers used brute-force access to reach internal servers and exposed personal data belonging to more than 50 million customers. **SQL Injection (SQLi)** targets the database sitting behind an application, exploiting queries built through string concatenation instead of parameterized statements, letting an attacker alter the intended query and read or manipulate data that was never meant to be exposed. A SQLi vulnerability in MOVEit, a widely used file-transfer product, was exploited in 2023 and affected more than 2,700 organizations, including US government agencies, the BBC, and British Airways. **Command Injection** happens when user input gets passed to the underlying system without validation, letting an attacker smuggle in operating system commands that execute with whatever permissions the application itself holds.

**Step 3: Log-based detection**

Access logs record a version of events that's useful but incomplete, which matters as much as what they do capture.

| Log field | What it can indicate |
|---|---|
| Client IP address | Known malicious source, or a location outside the expected geographic range |
| Timestamp and requested page | Requests at unusual hours, or repeated in an abnormally short window |
| Status code | Repeated 404s suggesting a scan for pages that don't exist |
| Response size | Significantly smaller or larger than a normal response for that endpoint |
| Referrer | A referring page that doesn't fit the site's normal navigation flow |
| User-Agent | Outdated browsers, or strings matching known attack tools like sqlmap or wpscan |

The room walks through a condensed illustrative attack chain to show how these fields come together. An attacker first runs a directory fuzz, probing for valid paths and forms, with 200 response codes marking each successful find. From there they move to a brute-force attempt against a login form, visible as repeated POST requests in quick succession, until one request returns a 302 Found instead of the usual failure response, the redirect that confirms a successful login. Once inside the account, the attacker attempts SQL injection payloads against a search form, and if the application builds its SQL queries through string concatenation rather than parameterization, exactly the flaw described in Step 2, the database gets dumped.

That illustrative sequence also demonstrates where logs fall short. A login attempt might appear in an access log as nothing more than a request line and a status code, the actual submitted username and password are absent, because standard access logs don't record POST body content at all. GET requests fare slightly better, full paths and query strings sometimes get logged, but even that depends entirely on the server software and its logging configuration. A log confirms a request happened. It rarely confirms what was inside it.

The room's hands-on investigation puts this to a real test: TryBankMe, a small online banking platform, has been breached, with customer data leaked on a darknet forum, and the job is retracing the attacker's steps through `access.log` on the desktop. Working through it, the attacker's User-Agent during the directory fuzz phase is **FFUF v2.1.0**, a well-known fuzzing tool whose default User-Agent string is exactly the kind of indicator Step 4's table calls out. The brute-force attack targets **/login.php**. And on the `/changeusername.php` form specifically, distinct from the illustrative example's `/search` form, the complete decoded SQLi payload is **%' OR '1'='1**, a classic tautology injection designed to make a WHERE clause evaluate true regardless of the actual stored value.

**Step 4: Network-based detection**

Network traffic analysis picks up exactly where logs leave off. Where a log entry might show a request happened, a packet capture shows the full HTTP headers, POST bodies, cookies, and any files exchanged, the entire conversation rather than a summary of it. The tradeoff is scope: encrypted protocols like HTTPS and SSH limit what's visible in the payload without the decryption keys, so this task's examples focus specifically on plaintext HTTP traffic.

Revisiting the same illustrative attack sequence from Step 3 in Wireshark, filtered to a specific destination IP and using the `http.user_agent` filter, fills in exactly the gap logs left open. The brute-force attempts that showed up as repeated anonymous POST requests in the log now reveal the actual credentials being tried, and the successful login (packet 13 in the room's walkthrough) shows the password the attacker landed on. The first SQL injection attempt, similarly opaque in the log, becomes fully readable in the packet, the `' OR '1'='1` payload and the Users table it dumped, first names and surnames in clear text. Even MySQL protocol traffic itself can be inspected this way in Wireshark, showing both the query and the data returned.

The room's actual investigation continues the TryBankMe case using `traffic.pcap`, picking up where the log analysis left off: the log analysis confirmed an attack happened but couldn't reveal which user was compromised or what data was actually taken. Filtering for HTTP traffic and following the HTTP stream on the relevant packets answers both. The password the attacker successfully identifies in the brute-force attack is **astrongpassword123**, different from the illustrative example's password, since this is the real captured traffic rather than the walkthrough. Following the stream on the SQL injection request reveals the flag the attacker extracted from the database: **THM{dumped_the_db}**.

**Step 5: Web Application Firewall**

Everything up to this point has been detection after the fact. A WAF shifts the timeline earlier: it inspects full request packets before they reach the server, similar in principle to what Wireshark shows, but with the added ability to decrypt TLS traffic and block a request outright rather than just observe it.

WAF rules fall into a handful of categories, each suited to a different kind of threat.

| Rule type | Description | Example |
|---|---|---|
| Block common attack patterns | Blocks known malicious payloads and indicators | Block requests with the User-Agent `sqlmap` |
| Deny known malicious sources | Uses IP reputation, threat intel, or geo-blocking | Block IPs tied to recent botnet activity |
| Custom-built rules | Tailored to a specific application's needs | Allow only GET/POST requests to `/login` |
| Rate-limiting and abuse prevention | Caps request frequency to prevent abuse | Limit login attempts to 5 per minute per IP |

A practical example ties this straight back to Step 3 and Step 4's investigation: repeated GET requests to `/changeusername` carrying the User-Agent `sqlmap/1.9`, an automated SQL injection tool, alongside network traffic confirming the requests contain actual SQLi payloads, is exactly the kind of pattern a custom rule exists to catch. A rule blocking any User-Agent containing "sqlmap" is a rudimentary version of what modern WAFs already do automatically for known-bad signatures, but the same logic scales to whatever pattern a specific application or threat scenario actually needs.

Not every suspicious request deserves an outright block. WAFs can instead challenge a request, a CAPTCHA being the most common form, to confirm a human is behind it rather than a bot, which matters given that malicious bot traffic alone makes up roughly 37% of global web traffic. That challenge-based approach is specifically valuable for rules with a real chance of catching legitimate traffic too, since a false positive that gets challenged and passed costs a user a few seconds, while a false positive that gets blocked outright costs them access entirely.

Modern WAFs rarely rely on hand-written rules alone. Many ship with built-in rulesets targeting the OWASP Top 10 directly, and layer in threat intelligence feeds that automatically block known-malicious IPs and User-Agents, updated continuously against emerging threats, newly disclosed CVEs, and known APT infrastructure. Cloudflare's own curated IP lists, built from botnets, VPNs, anonymizer services, and malware telemetry, are a working example of what that threat-intel layer actually looks like at scale.

Given a practical rule-writing task, blocking any User-Agent matching "BotTHM" translates directly into the same pattern used for sqlmap earlier: **IF User-Agent CONTAINS "BotTHM" THEN block**. And on the conceptual question underlying the whole task: what a WAF fundamentally inspects and filters is **Web Requests**, every one of the rule types above, pattern matching, reputation filtering, custom logic, rate limiting, is just a different lens applied to that same incoming stream.

## Why it matters

The OWASP Top 10:2025, released in November 2025, reshuffled its rankings in a way that lands directly on top of what this room covers. Injection, the category covering both XSS and SQL injection, dropped from third place to fifth, but that drop reflects better upstream prevention, parameterized queries becoming standard practice, frameworks sanitizing input by default, not reduced risk. Injection still gets tested in 100% of applications in some form, and Cross-Site Scripting alone accounts for more than 30,000 recorded CVEs. A ranking drop is not a green light to deprioritize the exact attack types Steps 1 through 4 of this room walk through in detail.

Broken Access Control held the top spot in the 2025 update, and Security Misconfiguration jumped from fifth to second, both worth noting against Step 5's WAF material specifically. A WAF is, at its core, a configuration: rules that decide what gets through and what doesn't. A misconfigured one, or one left on default rules that were never tuned to the application actually behind it, sits precisely inside that now second-ranked risk category. Deploying a WAF is not the same as deploying it correctly.

The log-versus-network distinction covered in Steps 3 and 4 also has a real cost dimension behind it that's easy to underweight until you've hit it directly. A SOC that retains only access logs, common in cost-constrained environments where full packet capture is expensive to store, will confirm an attack happened but frequently cannot answer the two questions that matter most afterward: which credentials were compromised, and what data actually left the building. That's not a hypothetical gap. It's the exact gap the TryBankMe investigation in this room was built to demonstrate, log analysis confirming the attack pattern, network traffic analysis answering what the logs structurally could not.

The client-side blind spot from Step 1 deserves its own weight too, precisely because it doesn't get solved by better logging or more thorough packet capture. No amount of server-side tooling closes a gap that exists entirely inside a user's browser. That's an architectural limitation, not a tooling gap, and it's the reason mature security programs pair server-side detection with endpoint monitoring and browser-level controls rather than treating SOC visibility as complete on its own.

## Key takeaways

- Client-side attacks execute inside the user's browser and often generate no anomalous server-side request at all, meaning server logs and network captures have a real, structural blind spot here, not just a tooling gap.
- XSS is the most common client-side attack; SQLi and brute-force anchor the server-side category, with T-Mobile (2021) and MOVEit (2023) showing what both look like at real scale.
- Access logs confirm a request happened but rarely capture POST body content, meaning brute-force and injection attempts often show up as a suspicious pattern without revealing the actual payload.
- Network traffic analysis fills that gap directly, at the cost of scope: encryption limits visibility without decryption keys, and full packet capture is more expensive to store than log lines.
- The same attack sequence can, and should, be traced across multiple data sources. What one source hides, another often reveals.
- WAF rules span four categories: known-pattern blocking, reputation-based denial, custom application-specific logic, and rate limiting, each suited to a different kind of abuse.
- Challenge-response mechanisms like CAPTCHA exist for rules with a real chance of catching legitimate traffic, turning a potential false positive into a few extra seconds instead of a lost user.
- A WAF's effectiveness depends entirely on its configuration and rule quality; a deployed-but-misconfigured WAF (2025's second-ranked OWASP risk) offers little more than the appearance of protection.
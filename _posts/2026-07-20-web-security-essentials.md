---
title: Web Security Essentials
date: 2026-07-20 07:00 +0300
categories: [Foundations, Web Security]
tags: [web-security, waf, cdn, application-security]
description: "Why web applications became the default attack surface, the three components every web service depends on, and the layered defenses (WAF, CDN, logging, least privilege) that protect each one."
---

## Description

Every web service, no matter how simple, breaks down into the same three pieces: an application, a web server hosting it, and a host machine running that server. Attackers know this too, which is why web applications sit at the top of most organizations' attack surface. This room covers why the shift from desktop to web happened, how the request-response cycle that underlies the entire web actually works, and the specific defenses, at the application, server, and host level, that keep a web service from becoming the next Equifax or Capital One.

This post walks through the room's four core sections, then finishes with a hands-on hardening exercise applying all of it to a sample site.

## The problem

Desktop software used to be the default because bandwidth and browser capability couldn't support anything else. That changed steadily through the 2000s and accelerated hard once cloud computing and SaaS matured in the 2010s. Today almost everything, banking, email, video editing, even running lab machines, happens inside a browser tab. That shift bought real advantages: faster updates, no install step, access from anywhere, lower resource use on the user's end.

It also flipped the risk model entirely. A desktop application only had to defend itself while running on a specific machine, offline half the time. A web application is online permanently, reachable by anyone on the internet at any moment, and usually sits in front of a database holding real customer data. That combination, always exposed, high-value target behind it, is exactly why web applications became attackers' most common entry point, and why a single overlooked vulnerability can cascade into a breach affecting tens of millions of people rather than one compromised machine.

## How it works

**Step 1: Why web?**

The desktop-to-web shift changed who bears responsibility for security, not just where software runs. A useful way to see this: what each side of the relationship is actually exposed to.

| As a web app owner | As a web app user |
|---|---|
| Your application is online 24/7 and must be secured accordingly | Your data lives inside someone else's application, potentially insecurely |
| Anyone worldwide can reach it at any time | A single breach can mean identity theft or financial loss |
| Keeping up with emerging threats is a constant, ongoing job | Your privacy can be permanently compromised |
| You are responsible for securing your users' data, not just your own | Once your browser or account is breached, everything tied to it is at risk |

That last row on the owner's side is the one worth sitting with: responsibility for a user's data sits with the application owner, not the user, regardless of how the breach actually happened. Two real breaches make that concrete.

In 2017, Equifax exposed sensitive data belonging to roughly 147 million Americans, Social Security numbers, birth dates, and addresses among them, after attackers exploited a known vulnerability in Apache Struts (CVE-2017-5638) that Equifax had not yet patched. The flaw let attackers execute commands directly on the server, and from there reach internal databases holding customer records. Equifax later reached a settlement of up to $700 million with US regulators and all 50 states over the incident.

Capital One's 2019 breach followed a different but related path. A former Amazon Web Services employee exploited a misconfigured web application firewall to reach AWS's internal metadata service, retrieved temporary credentials for an over-permissioned role, and used them to pull data on roughly 100 million customers directly out of cloud storage. The vulnerability wasn't in Capital One's application code at all. It was a misconfiguration in the exact tool meant to prevent this kind of attack, which is the detail worth remembering going into the rest of this room: a WAF, CDN, or any other control is only as good as its configuration.

**Step 2: Web infrastructure**

Every web interaction follows the same request-response cycle: your browser sends a request, the server processes it, verifies whatever access is needed, and returns a response, a page, an image, search results, account data. That cycle is simple by design, and that simplicity is exactly what attackers abuse: flooding it with requests, sidestepping the access checks, or crafting a request that tricks the server into executing something it shouldn't.

Any web service depends on three components working together.

| Component | Role |
|---|---|
| Application | The code, images, styles, and logic that define how the site looks and behaves |
| Web Server | Listens for incoming requests and returns responses; hosts the application |
| Host Machine | The underlying OS (Linux or Windows) that runs the web server and application |

The web server sits in the most exposed position of the three, since it's the piece directly facing every incoming request from the public internet, which makes it a natural first target. Three web servers dominate real deployments, each with a different niche:

| Server | Common use |
|---|---|
| Apache | Simple websites and blogs, most commonly WordPress |
| Nginx | High-performance applications; used by Netflix, Airbnb, GitHub |
| IIS (Internet Information Services) | Microsoft-developed, common in enterprise environments |

Knowing which server sits in front of a target matters practically: Apache and IIS both carry a long history of documented, application-specific vulnerabilities, Equifax's breach being the clearest example, and identifying the server in use is often one of the first things an attacker (or a defender doing reconnaissance on their own infrastructure) checks.

**Step 3: Protecting the web**

Security controls split cleanly across the same three components from Step 2, plus two practices that apply to all three at once.

Protecting the application means avoiding insecure functions, handling errors without leaking internal details, validating and sanitizing every piece of user input before it reaches application logic, and enforcing access control based on user roles rather than trusting the client to only request what it's allowed to see.

Protecting the web server means keeping detailed access logs of every request, deploying a web application firewall to filter and block harmful traffic against defined rules, and reducing direct exposure to the origin server through a CDN.

Protecting the host machine means running services under low-privilege users rather than root or administrator, hardening the system by disabling unnecessary services and closing unused ports, and adding antivirus for endpoint-level protection against known malware.

Two practices cut across all three: strong authentication, so access to code, admin panels, and the host machine itself isn't left open, and patch management, keeping application dependencies, the web server, and the host OS current. Equifax's breach is the textbook case for why that second one belongs at the top of the list; the vulnerability that exposed 147 million records had a patch available before attackers used it.

Access logs deserve a closer look, since they're the record that turns "something happened" into "here's exactly what happened." Every request generates a log entry: client IP, timestamp, requested resource, response status, user agent. A simple, benign sequence illustrates what an analyst reconstructs from these fields: a client at `10.10.10.100` visits the homepage (`GET /index.html`), navigates to the login page (`GET /login.html`), submits credentials (`POST` to the login endpoint), then reaches their account page (`GET /myaccount.html`). Nothing in that sequence is remarkable on its own. What makes access logs valuable is that the exact same fields capture the abnormal version of that sequence too, dozens of failed login POSTs from one IP in a few seconds, a request for `/admin.html` from an account that never visited `/login.html` first, and having that data recorded by default, before an incident happens, is what makes reconstruction possible after one does.

**Step 4: Defense systems**

Three specific technologies do most of the heavy lifting for protecting the web server layer described above.

A Content Delivery Network (CDN) caches content on edge servers positioned near users worldwide instead of serving everything from one central origin server. Beyond the speed benefit, a CDN provides real security value: it masks the origin server's actual IP address behind its own edge network, making the real server harder to target directly, absorbs the volume behind DDoS attacks before it ever reaches the origin, enforces HTTPS by default on most implementations, and often bundles an integrated WAF as part of the same service. Cloudflare, Amazon CloudFront, and Azure Front Door all combine these functions in one product.

A Web Application Firewall (WAF) inspects incoming HTTP traffic and blocks or logs requests that match defined security rules, functioning like a bouncer checking every request before it's allowed through. WAFs come in three deployment types.

| WAF type | Deployment | Best fit |
|---|---|---|
| Cloud-based (reverse proxy) | Sits in front of the web server, hosted externally | Fast deployment, high scalability |
| Host-based | Software installed directly on the web server | Fine-grained, per-application control |
| Network-based | Physical or virtual appliance at the network perimeter | Enterprise environments |

Detection itself relies on a handful of complementary methods, none of which fully covers what the others miss.

| Detection method | How it works | Example trigger |
|---|---|---|
| Signature-based | Matches known attack patterns or payloads | A request with a User-Agent matching a known tool, e.g. sqlmap |
| Heuristic-based | Analyzes request context and structure | A query string containing suspicious special characters |
| Anomaly & behavioral | Flags deviations from normal traffic patterns | One IP making repeated login attempts in a short window |
| Location & IP reputation | Filters based on geographic and threat-intel data | A request from outside the application's normal user base |

Signature-based detection is the fastest and most precise of the four against known attacks, and the one most easily defeated by anything genuinely new, which is exactly why real deployments layer multiple detection methods rather than relying on one. Capital One's breach is a useful cautionary note here too: a WAF only filters what its rules are configured to catch, and a misconfigured one provides false confidence rather than actual protection.

Antivirus rounds out host-level protection. AV is often misunderstood as blanket protection, but its actual job is narrower: safeguarding the endpoint itself (the host machine) against known malicious files, primarily through signature-based comparison against a malware database. Since most web attacks target the application layer rather than the underlying host, AV's role here is specific: catching malicious file uploads, web shells, and post-exploitation tools that land on the host after some other control already failed. It's one layer in a defense-in-depth strategy, not a substitute for the rest of it.

**Step 5: Practice scenario**

The room closes with Secure-A-Site, a hands-on exercise applying every control covered above to an actual site under active development, working through the application, web server, and host machine layers in sequence and claiming a flag for each once that layer is properly hardened.

Securing the web application layer returns the flag `THM{web_app_secured!}`. Securing the web server layer returns `THM{server_security_expert!}`. Securing the host machine layer returns `THM{the_final_security_layer!}`. Three flags, one per component, mirrors the exact three-part breakdown the entire room builds on: application, server, host. Nothing in the hardening process is separable from the concepts covered in Steps 3 and 4; each flag is the practical proof that the corresponding control (input validation and access control for the application, WAF and logging for the server, least privilege and system hardening for the host) actually got applied correctly rather than just described.

## Why it matters

Verizon's 2026 Data Breach Investigations Report shows Basic Web Application Attacks dropping from 18% of breaches in 2025 to 10% in 2026, and frames that drop as a trap rather than a win. The same two root causes behind that category, stolen credentials and unpatched internet-facing vulnerabilities, are exactly what now fuels System Intrusion, the multi-step pattern behind most ransomware, which climbed to 61% of breaches in the same report. The controls in this room don't stop mattering because the breach category they're filed under shrank; they matter because the underlying weaknesses they address moved into a more damaging category instead.

The scale of what those weaknesses face has grown sharply too. Indusface's 2026 State of Application Security Report recorded 6.29 billion attacks targeting website vulnerabilities in 2025, up 56% from the year before, with a median time from disclosure to active exploitation now under five days. That figure alone justifies the room's emphasis on patch management as a cross-cutting practice rather than an afterthought: a five-day window between a public vulnerability disclosure and active exploitation leaves very little room for a slow patching cycle.

The credential angle deserves particular weight given how much of this room focuses on access control and authentication. Verizon's 2025 DBIR found that 88% of Basic Web Application Attacks involved stolen credentials, not novel exploits, not zero-days, just a login form and a password an attacker already had. That statistic reframes "strong authentication" from a generic best practice into the single highest-leverage control covered in Step 3. A perfectly configured WAF does nothing to stop an attacker who logs in with a valid, stolen password.

The CDN and WAF material in Step 4 also lands differently against current bot traffic figures. Imperva's 2025 Bad Bot Report found automated bots now account for roughly 51% of all web traffic, with malicious bots making up about 37% of that total, meaning a majority-automated internet is now the baseline environment any public-facing application operates in, not an edge case. Cloudflare alone mitigated 47.1 million DDoS attacks in 2025, a 121% increase year over year. Against that backdrop, a CDN's DDoS absorption and a WAF's signature-based filtering aren't optional hardening steps for high-profile targets; they're baseline requirements for anything reachable from the open internet.

## Key takeaways

- The shift to web applications traded desktop-era isolation for permanent, worldwide exposure, and moved data-security responsibility onto the application owner regardless of how a breach actually occurs.
- Every web service reduces to three components, application, web server, host machine, and each one needs its own distinct set of controls rather than a single blanket defense.
- Equifax (2017) and Capital One (2019) both trace back to gaps this room directly addresses: an unpatched known vulnerability in one case, a misconfigured WAF in the other. Neither required a novel attack technique.
- Access logs turn an incident from a mystery into a reconstructable sequence, but only if they're already being collected before something goes wrong.
- A CDN's security value goes beyond speed: origin IP masking, DDoS absorption, enforced HTTPS, and often a bundled WAF.
- No single WAF detection method covers everything; signature-based catches known attacks fast, while heuristic, behavioral, and reputation-based methods catch what signatures miss.
- 88% of basic web application attacks involve stolen credentials, which makes strong authentication the highest-leverage control in this entire room, ahead of any firewall or filtering rule.
- A security control is only as effective as its configuration. Capital One's WAF existed specifically to prevent the kind of attack that exploited it.
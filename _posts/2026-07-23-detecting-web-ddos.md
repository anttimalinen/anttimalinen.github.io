---

title: "Detecting Web DDoS"

date: 2026-07-23 16:00 +0300

categories: [Foundations, Web Security]

tags: [ddos, dos, waf, cdn, splunk]

description: "How Layer 7 denial-of-service attacks overwhelm web applications, the log and SIEM indicators that expose them, and the CDN, WAF, and application-level defenses that keep services online, illustrated through the BBC, Microsoft, and Dyn attacks and a full Splunk investigation."

---

## Description

A denial-of-service (DoS) attack has one goal: make a web service stop working for legitimate users. It doesn't need to steal data or plant malware to succeed. It just needs to exhaust something the server has a finite amount of, connections, CPU cycles, database queries, bandwidth, faster than the server can recover. A distributed denial-of-service (DDoS) attack is the same idea run through a botnet, a network of compromised devices under one attacker's control, which multiplies the available firepower far beyond what a single machine could generate.

This room stays focused on Layer 7, the application layer of the OSI model, where HTTP requests, login forms, and search queries live, rather than the lower-level network floods that target raw bandwidth. That's a deliberate scope choice, and a useful one, because Layer 7 attacks can bring down a service with a fraction of the traffic a network-layer flood needs, precisely because they target expensive operations instead of raw pipes.

The scale of this problem in 2026 is hard to overstate. Cloudflare alone reports mitigating over 20 million DDoS attacks in the first quarter of 2025, an average of more than 5,000 attacks blocked every hour by year's end, and industry estimates put the global daily total around 44,000 attacks across all providers. Every minute of DDoS-caused downtime costs an average of $22,000 according to 2025 industry research. This isn't a rare, exotic threat. It's background radiation for anything with a public IP address.

This room covers attacker motives, the log-based indicators that reveal a DoS or DDoS attempt, a hands-on raw log investigation, a Splunk-based SIEM investigation into a suspected botnet attack, and the CDN, WAF, and application-level defenses that keep services running under load.

Source: TryHackMe, room "Detecting Web DDoS."

## The problem

**Why the application layer is such an efficient target.** A basic DoS attack from a single machine is capped by that machine's own CPU, memory, bandwidth, and network connection. Scaling past that cap is exactly what turns a DoS into a DDoS: an attacker recruits or rents a botnet, an army of compromised computers, IoT devices, or servers running attacker-controlled malware, and directs it to flood a single target simultaneously. But volume isn't the only lever. A web application's own logic can be turned against it. A search form that queries a database without validating input length can be brought to its knees by a single carefully malformed request, no botnet required, because the server is doing expensive work on the attacker's behalf every time.

| DoS attack type | How it works |
|---|---|
| Slowloris | Sending many partial HTTP requests to tie up server connections |
| HTTP Flood | Sending a large volume of complete HTTP requests to overwhelm the server |
| Cache Bypass | Forcing the origin server to respond by evading CDN edge caching |
| Oversized Query | Forcing the server to process large, resource-intensive requests |
| Login/Form Abuse | Overloading authentication logic with login attempts or password resets |
| Faulty Input Validation Abuse | Exploiting poorly designed input handling to crash or hang the app |

**Slowloris deserves a closer look, because it inverts the usual DDoS assumption.** Most people picture a flood: massive traffic volume overwhelming a pipe. Slowloris does the opposite. It opens a connection to the target and sends a partial HTTP request, the request line and a few headers, but deliberately withholds the blank line that signals "this request is complete." The server, expecting the rest of the request to arrive, keeps that connection open and allocates a thread or resource slot to it. The attacker then sends occasional junk header fragments, just often enough to prevent the connection from timing out, without ever finishing the request. Repeat that across dozens or hundreds of connections and the server's finite connection pool fills up entirely, locking out real visitors, all while consuming a trickle of bandwidth low enough to slip past defenses built to catch traffic floods. It's a "low and slow" attack, and it's part of why request rate alone is an incomplete signal.

**Oversized query abuse has also evolved into something far more dangerous than a single bloated request.** In August 2023, a previously unknown zero-day technique called HTTP/2 Rapid Reset (tracked as CVE-2023-44487) began appearing in attacks against Google, Cloudflare, and AWS. HTTP/2 allows a single TCP connection to carry many concurrent request streams, and it lets a client cancel any stream instantly with a reset signal. Rapid Reset abuses that cancellation feature: the attacker opens a stream, immediately resets it, opens another, resets that too, over and over, on a single connection. Because each stream gets canceled before the server finishes processing it, the attacker never bumps against the connection's stream limit, but the server still did real work initiating and tearing down each one. That mismatch, near-zero cost for the attacker, real CPU cost for the server, let a relatively modest botnet punch far above its weight. Google measured a peak above 398 million requests per second during the attack, more than seven times its own previous largest recorded attack of 46 million rps. Cloudflare and AWS reported peaks of 201 million and 155 million rps respectively in the same wave, each also dwarfing the roughly 71 million rps industry record set just months earlier. Cloudflare's CEO estimated the botnet behind it needed only 10,000 to 20,000 compromised nodes, a modest size by modern botnet standards, which is exactly what made the vulnerability so alarming: a small botnet using this technique could out-punch a massive one using conventional floods.

**Attacker motives, expanded from the room's list:**

| Motive | Description | Example scenario |
|---|---|---|
| Financial Loss | Disrupt services to stop or reduce sales and revenue | Flooding an e-commerce site during peak holiday sales |
| Extortion | Demand payment to stop a current attack | Threatening a bank with a ransom DDoS |
| Hacktivism | Disruption for social or political protest | Attacking government websites during election season |
| Distraction | Redirect defenders' attention while other attacks take place | Launching a DDoS while attacking other infrastructure |
| Competition | Disrupt a rival's service to drive up their costs or gain market share | A competitor launches a DDoS during a product launch |
| Denial of Wallet | Force the victim to rack up service usage costs | Repeatedly hitting metered cloud API endpoints to inflate a victim's bill |
| Reputational Damage | Cause customers to lose trust in a company | Game servers crashing during launch day |

**Three real incidents show how differently these motives play out.**

On New Year's Eve 2015, a group calling itself New World Hacking took the BBC's entire domain, including its iPlayer streaming service, offline for several hours, with residual issues lingering the rest of the day. The group claimed a peak of 602 Gbps, which would have nearly doubled the previous record of 334 Gbps, though the figure was never independently confirmed and is now widely treated as exaggerated. The group described the BBC attack as a capability test ahead of planned operations against ISIS-affiliated sites, and hit Donald Trump's campaign website the same day. The BBC case is a clean example of the "distraction" and "test of power" end of the motive spectrum: the target wasn't chosen for financial or ideological reasons specific to it, just for having enough bandwidth to make a good benchmark.

In June 2023, a threat actor Microsoft tracks as Storm-1359, publicly known as Anonymous Sudan, ran a sustained Layer 7 campaign against Outlook.com, OneDrive, and the Azure portal on three consecutive days, using precisely the three attack types this room covers: HTTP(S) flood, cache bypass, and Slowloris. The group demanded a million-dollar payment to stop, blending extortion with a hacktivist public narrative. Microsoft found no evidence customer data was accessed. The attribution got more complicated afterward: threat intelligence researchers linked the group to KillNet, a pro-Russian hacktivist collective, and in October 2023 a federal indictment charged two Sudanese nationals with operating Anonymous Sudan, alleging roughly 35,000 attacks since the group's formation. The public "hacktivism" framing and the underlying reality of who benefits from an attack aren't always the same thing, which is a useful reminder for any analyst reading motive off a claimed identity rather than off evidence.

A different kind of case entirely: on October 21, 2016, the Mirai botnet, built from roughly 100,000 compromised IoT devices (routers, DVRs, IP cameras) running factory-default credentials, hit Dyn, a major DNS provider, with traffic peaking around 1.2 Tbps. This wasn't a Layer 7 attack against a single application; it targeted DNS infrastructure at the network layer, and because Dyn resolved domain names for a huge share of the internet, the outage cascaded into Twitter, Netflix, Reddit, GitHub, Spotify, and dozens of other unrelated sites going dark for users who had no idea Dyn even existed. Reporting afterward indicated over 14,000 platforms, roughly 8% of Dyn's customer base, moved to other DNS providers in the aftermath. It's outside this room's Layer 7 scope, but it's the clearest illustration of the "reputational damage" motive category playing out at the infrastructure level: the damage didn't stay contained to the attack's actual target.

**Records don't stay records for long.** By September 2025, Cloudflare had already surpassed the 11.5 Tbps figure this room cites, and by the end of that year the bar had moved twice more: to 22.2 Tbps within weeks, then to 31.4 Tbps in a 35-second burst from a botnet tracked as Aisuru-Kimwolf, built substantially from compromised Android TV devices. That's over a 700% increase in roughly fourteen months. The same botnet reappeared weeks later with an HTTP-based campaign exceeding 200 million requests per second against Cloudflare's own infrastructure. Whatever number is current by the time this gets read, it's worth assuming it's already been beaten, since attack scale has been growing faster than most defensive baselines get updated. Some of that growth is attributed to AI-assisted DDoS-as-a-service platforms that let low-skill attackers rent large-scale capability through simple prompts, while defenders lean increasingly on autonomous, AI-driven mitigation systems capable of absorbing hundreds of terabits of traffic and blocking the large majority of attacks without a human in the loop.

## How it works

Detecting a DoS or DDoS attack in progress comes down to reading the shape of traffic, not any single request in isolation. A single malicious-looking request tells you little. A pattern across thousands does.

- **Step 1: know the indicators before opening a log file.** Every major web server, Apache, NGINX, IIS, logs requests in a broadly standardized format, and the same handful of signals show up across almost every DoS and DDoS variant:

| Indicator | Example | What it means |
|---|---|---|
| High request rate | `10.10.10.100` sends 1,000 `GET /login` requests | A resource-heavy endpoint is being flooded to overwhelm authentication logic |
| Odd user agents | `curl/7.6.88` hitting `/index` repeatedly | Automated tooling often carries outdated or bare-bones User-Agent strings |
| Geographic anomalies | Source IPs scattered across dozens of countries | Legitimate traffic usually clusters around a few regions; a global spread suggests a botnet |
| Burst timestamps | 50 requests to `/search` inside one second | A pattern that dense is very unlikely to be human-driven |
| Server errors (5xx) | A spike in `503 Service Unavailable` | The server has run out of capacity to process anything more |
| Logic abuse | `GET /products?limit=999999` | A crafted query designed to force the server to do far more work than a normal request |

  No single indicator proves an attack. A worldwide botnet aimed at one target might generate requests from dozens of countries hitting several resource-heavy endpoints, some sharing a User-Agent string, others varying it to look more human. Layered signals, not one smoking gun, are what build the picture.

- **Step 2: know which endpoints are worth watching before an attack starts.** Not every page costs the same to serve. Static content like product images barely taxes a server. Anything that touches a database, validates input, or writes data costs far more per request, which makes it a preferred target:
  - `/login` and `/register`, authentication and database writes
  - `/search`, complex database queries
  - `/api` endpoints, dynamic content generation
  - `/contact` or `/feedback`, database writes plus possible email/notification triggers
  - `/cart` or `/checkout`, session management, inventory checks, payment processing

  Knowing this list in advance means an analyst can prioritize alerting on these specific paths rather than treating all traffic equally.

- **Step 3: work a raw access log investigation.** Given `access.log` from a bicycle parts e-commerce site with a mix of normal and attacker traffic, filtering for repeated requests to the same page and cross-referencing response codes builds the picture fast.

| Finding | Answer |
|---|---|
| Attacker IP address | `203.12.23.195` |
| Repeatedly targeted page | `/login` |
| Error code returned to legitimate users after the attack | `503` |

  This is the smallest possible version of the investigation: one attacker, one target endpoint, one visible failure mode. Real DDoS incidents usually look far messier, which is exactly why the next step exists.

- **Step 4: scale up with a SIEM when raw grep isn't enough.** A Security Information and Event Management (SIEM) platform centralizes multiple log sources and lets an analyst query and filter by any extracted field instead of scrolling raw text. In Splunk specifically, a search against `index="main"` surfaces extracted fields like `clientip`, `useragent`, and `uri` directly in the sidebar, ready to filter and pivot on. The `timechart` command is the workhorse for spotting bursts: a query like `timechart span=1s count by clientip` buckets events into one-second windows and counts them per source, which turns a wall of raw events into a visual spike the moment request volume crosses from normal into abnormal. Splitting the same data by `useragent` instead of `clientip` can expose a shared signature across many source IPs, one of the more reliable ways to confirm a distributed attack rather than one aggressive individual host.

  Running that investigation against a suspected botnet attack surfaced the following:

| Finding | Answer |
|---|---|
| Most frequently requested `uri` | `/search` |
| `clientip` with the most requests to the target `uri` | `203.0.113.7` |
| Number of IP addresses in the botnet | `60` |
| Most common `useragent` in attacking traffic | `Java/1.8.0_181` |
| Peak requests per second during the attack | `207` |
| First legitimate `clientip` to receive a `503` post-attack | `10.10.0.27` |

  The `Java/1.8.0_181` user agent is worth sitting on for a second. It's not a browser string at all, it's the default signature an HTTP client library embedded in Java-based automation tools sends when nobody bothers to customize it, and seeing it attached to 60 distinct source IPs all hammering the same search endpoint is a textbook shared-tooling fingerprint. That's precisely the kind of pattern a `timechart` split by `useragent` is built to surface.

- **Step 5: recognize what logs and SIEM queries can't fully catch on their own.** Slowloris generates low request volume by design, so a query tuned to flag high request rates alone will miss it entirely; connection duration and count, not request frequency, is the signal that matters there. Attackers spoof User-Agent strings and distribute source IPs specifically to defeat the geographic and signature-based indicators from Step 1. And once an attacker starts appending random query parameters or rotating referrers to evade WAF rules (more on that in Step 8), log-based pattern matching alone starts falling further behind. This is the point where defense has to move beyond detection and into architecture.

- **Step 6: harden the application itself.** Input validation is the first and cheapest layer. A search form that enforces a maximum query length and rejects malformed characters can't be coerced into doing unbounded, expensive work no matter how the request is phrased, the same principle that stops SQL injection also blunts resource-exhaustion abuse. Challenge mechanisms add a second layer: CAPTCHA puzzles cost a human a few seconds and cost a bot a failed attempt, while JavaScript challenges run silently in the background, verifying a real browser is executing real code before granting access, invisible to legitimate users but a wall for scripted tools that don't render JavaScript at all.

- **Step 7: layer network and infrastructure defenses on top.** A Content Delivery Network (CDN) caches content at edge servers physically closer to users, which means the origin server only has to handle a fraction of total requests while the CDN absorbs the rest, and its load-balancing capability spreads traffic across multiple servers so no single one gets overwhelmed. A Web Application Firewall (WAF), commonly bundled with a CDN, inspects incoming requests against rule sets built from known attack signatures and threat intelligence, then allows, challenges, or blocks each one. Rate-limiting rules are the most direct WAF response to the patterns from Step 1: a rule capping `/login.php` at five requests per minute per source IP, for instance, blocks or challenges anything past that threshold automatically, no analyst intervention required. The scale these systems now defend against is enormous: the same infrastructure that handles day-to-day traffic is what autonomously absorbed the multi-terabit attacks described earlier, entirely without a human clicking anything during the actual event.

- **Step 8: know how attackers try to bypass all of the above.** A CDN can only serve a cached copy of a URL it has already cached. Appending a random query string, `/products` becomes `/products?a=abcd`, produces a URL the CDN has never seen, forcing it to fall through to the origin server on every single request, defeating the caching layer's entire purpose. WAF rules built around signatures get evaded the same way logs get evaded: rotating User-Agent strings, spoofing referrer headers, and spreading requests across geographically diverse source IPs all chip away at rule conditions written around a specific fingerprint. None of this makes CDNs or WAFs pointless, it's why rules need regular tuning and why detection stays layered rather than resting on any single control.

## Why it matters

The $22,000-per-minute downtime figure isn't an abstraction, it's the reason every motive in the table above translates directly into dollars, reputation, or both. A financially motivated flood during a holiday sales peak and a hacktivist campaign against a cloud provider's login portal look identical in the access logs, high request rate, odd user agents, geographic spread, but the response calculus differs: one is a business continuity problem, the other can carry political or diplomatic weight depending on who's behind it. The Anonymous Sudan case shows exactly how blurry that line can get in practice: a hacktivist-branded campaign against Microsoft that later intersected with a pro-Russian hacktivist collective and ended in a federal indictment. An analyst reading motive off a claimed identity alone is reading incomplete information.

The layered nature of both attacks and defenses is the core lesson here. Slowloris survives on low bandwidth specifically because it was built to defeat volumetric detection. HTTP/2 Rapid Reset survives on protocol-level abuse that request-rate monitoring alone won't catch, it needed vendor-level patching, not just better logging. Cache bypass survives by exploiting the exact mechanism a CDN uses to reduce load. Every technique in this room's list targets a different assumption defenders commonly rely on, which is precisely why no single control, not a WAF rule, not a rate limit, not a CAPTCHA, stops the full range of what's possible. Layered detection across logs, SIEM correlation, and infrastructure defense isn't redundancy for its own sake. It's coverage for the gaps each individual layer leaves open.

The arms race dimension is worth taking seriously going into any SOC role in 2026. AI-assisted DDoS-as-a-service platforms have lowered the skill floor for launching a serious attack to something close to typing a prompt, while the defensive side has answered with autonomous mitigation systems processing traffic volumes and blocking percentages that would be impossible for a human team to match in real time. That doesn't make the analyst's job obsolete, it changes what the job actually is: less about manually blocking individual IPs during an active flood, more about tuning the rules and thresholds the automated systems run on, and investigating the incidents that need human judgment once the autonomous layer has already absorbed the bulk of the traffic.

For a SOC analyst, the skills this room exercises, reading raw access logs for burst patterns, pivoting a SIEM query by user agent to expose shared tooling across a botnet, and knowing which CDN and WAF controls map to which attack type, are directly transferable to real incident response. DDoS attacks are also unusually well-suited to building genuine pattern-recognition instinct, because unlike a single intrusion, the evidence is often thousands of nearly identical events, and learning to see the signal in that repetition is a skill that generalizes well beyond this specific attack class.

## Key takeaways

- DoS attacks disrupt a single service from one source; DDoS attacks scale that disruption through a botnet, a network of compromised devices under attacker control. This room's scope stays on Layer 7, the application layer, where expensive operations like database queries and authentication logic make efficient targets even at modest traffic volumes.
- Slowloris and HTTP/2 Rapid Reset both prove that raw request volume isn't a reliable universal indicator. Slowloris survives on minimal bandwidth by exhausting connection slots instead of flooding traffic; Rapid Reset abuses HTTP/2's stream cancellation to make a small botnet generate hundreds of millions of requests per second.
- No single log source or defensive control catches everything. Access log indicators (request rate, user agent, geography, burst timing, error codes) flag the obvious cases; a SIEM's field extraction and `timechart` correlation catches distributed patterns raw grepping would miss; CDNs, WAFs, and input validation close gaps neither logging approach can reach on its own.
- Working the raw log investigation traced the attacker to `203.12.23.195` targeting `/login`, with legitimate users receiving `503` errors once the server was overwhelmed. The Splunk investigation identified a 60-host botnet sharing the `Java/1.8.0_181` user agent, targeting `/search`, peaking at 207 requests per second, with `10.10.0.27` the first legitimate client to receive a post-attack `503`.
- Attacker motives range from financial and extortion-driven to hacktivist, and public framing doesn't always match underlying reality, as the Anonymous Sudan case demonstrated. Reading motive from a claimed identity alone is reading incomplete information.
- DDoS scale keeps moving faster than most defensive baselines update. The room's cited 11.5 Tbps record was surpassed twice within months, reaching 31.4 Tbps by the end of 2025, driven partly by AI-assisted attack tooling matched by increasingly autonomous, AI-driven mitigation on the defense side.
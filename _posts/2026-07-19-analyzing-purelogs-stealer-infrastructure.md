---
layout: post
title: Analyzing Adversary Infrastructure
date: 2026-07-19 15:21 +0300
categories: [threat intel]
description: Analyzing threat actor infrastructure to identify additional command & control servers.
---

# The starting point

After completing the Intel-Ops [Hunting Adversary Infrastructure](https://academy.intel-ops.io/courses/hunting-adversary-infra) course I wanted to use the techniques and methods from it to identify threat actor infrastructure. I came across [this article](https://blog.deception.pro/blog/cpuz-trojan-stxrat-purelogs-data-exfil-april-2026) detailing a campaign of various malware being delivered inside trojanized software. The article outlines the infection chain, the threat actor's activities, defensive recommendations, and indicators of compromise.

During my initial review of the article one detail stood out to me. Two of the malware listed had their Command & Control servers (C2s) in the same network, this is not very common as threat actors often attempt to spread out their infrastructure among different service provides or only have a single C2 server per campaign.

![Indicators of Compromise](assets/img/posts/2026-07-19-analyzing-purelogs-stealer-infrastructure/indiactors.png){: w="500" h="300" .normal }

These two IP addresses became the starting point for my investigation:

```
176.65.144[.]84
176.65.144[.]46
```



# Finding the first pivot points

After identifying interesting points to investigate I first queried Shodan and Modat to determine if they were currently hosting any services, they were not. This was not a surprise as threat actors or the hosting providers they use take down their infrastructure after it has been mentioned publicly. I then examined historical data for the hosts from Validin and FOFA. Interestingly the services showed that ***both*** IP addresses had hosted a service on port **8443** shortly before the article was published (April 13th), while the article listed only one of them hosting a C2 at port **8443**. Another thing to note is neither host showed a service at the port **65001** that was mentioned in the article, however this could be due to limitation of the platforms available to us. 

Both services at port 8443 responded with identical headers, same JARM and HTML hashes, as well as with a similar certificate with seemingly sensible but clearly fake details.

![First Pivot](assets/img/posts/2026-07-19-analyzing-purelogs-stealer-infrastructure/first_pivot.png){: w="820" h="420" .normal }

# Pivoting to identify live servers from Shodan

The two hosts no longer had the services live on port 8443 so it was necessary to use the information from the first pivot points to identify live servers. As the hash for the HTTP headers and the HTML body differ between FOFA and Shodan other identifying data points had to be used. Using just **three** specific it was possible to build an initial Shodan search query to find some live servers with the same C2. The **JARM fingerprint value**, which is a [method](https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a/) for fingerprinting different TLS implementations, the **port 8443** and the **content length** visible in the HTTP headers.



```
ssl.jarm:"2ad2ad16d00000022c2ad2ad2ad2ad46ff59a659b30fd8aeaa6755c67691b4" port:8443 "Content-Length: 18"
```

At the time of writing this query returns **19 hosts**. It is possible to quickly identify the hosts have a similar service running with identical headers and similar nonsensical certificate details.

![Initial results](assets/img/posts/2026-07-19-analyzing-purelogs-stealer-infrastructure/shodan_results1.png){: w="620" h="220" .normal }


# Tweaking the Shodan search query

After identifying live servers with the C2 services visible it was necessary to further tweak the Shodan search query. When doing infrastructure analysis relying on more vague search terms such as common port numbers or header content length values can lead to falsely identifying servers as C2s, though they can be very useful to identify initial pivot points. Currently Shodan reports ~6.5 million servers with port 8443 and ~29.9 million servers responding with the header length 18. Using these for the search query could easily leave in false positive findings.

The certificate details visible to Shodan for the hosts were all different, seemingly due to some randomized certificate generator. However, the **HTTP header hash** and **HTML hash** were found to be identical among the hosts with the known identifiers of the C2 server so they were used to improve the search query.

```
http.html_hash:1929577144 http.headers_hash:707481832
```

At the time of writing this query returns **26 hosts** with 24 hosts on port 8443, suggesting the JARM fingerprint chosen initally was a limiting factor in the previous query.


# Analyzing and grouping the results

After going through the data of the remaining hosts this can be clearly seen as the remaining hosts had 8 different JARM values.

![JARM results](assets/img/posts/2026-07-19-analyzing-purelogs-stealer-infrastructure/jarm.png)

Another way to group the remaining hosts is by using the **JA3S** value, which is an [alternative method](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/) to **JARM** for fingerprinting TLS implementations. When grouping by the **JA3S** value the hosts are split into groups of 12 and 14 hosts, this is due to the ciphers preferred by the hosts as demonstrated here.

![JA3S values](assets/img/posts/2026-07-19-analyzing-purelogs-stealer-infrastructure/ja3s.png)

This also very nicely demonstrates how the **JA3S** value changes along due to the cipher suite of the TLS connection as the cipher is one of the building blocks the JA3S is based on.

![JA3S description](assets/img/posts/2026-07-19-analyzing-purelogs-stealer-infrastructure/ja3s-text.png){: w="650" h="300" .normal }

It is possible to see the same phenomenon with the **JARM** values. As the first 30 digits of the value is: 

> *"made of the cipher and TLS version chosen by the server for each of the 10 client hello’s sent. A “000” denotes that the server refused to negotiate with that client hello."*

As we know the 12 of the hosts use **ECDHE-RSA-AES256-GCM-SHA384** while the remaining 14 use **TLS_AES_256_GCM_SHA384**. Focusing only on the first 30 digits it is possible to see that the first **JARM** value shown is clearly different from the rest. The remaining ones are very similar, especially when you take into account that **000** means the server refused the negotiation for some reason and most of the hosts having responded with **42d** at least once but just at different times. This means the 14 hosts have a quite similar TLS implementation, possibly only set up differently.

![JARM value similarities](assets/img/posts/2026-07-19-analyzing-purelogs-stealer-infrastructure/jarm2.png)

This allows us to cluster these hosts based on their similarity and various aspects of their fingerprints. One clearly different cluster with all 12 hosts having very similar TLS implementations and another cluster/multiple smaller clusters of hosts with different TLS implementations.

![Maltego graph](assets/img/posts/2026-07-19-analyzing-purelogs-stealer-infrastructure/maltego.png)

# Conclusion

Starting from the two hosts that no longer hosted the C2s, performing infrastructure analysis it was possible to identify 26 additional hosts with live C2s. Most of the C2 IP addresses were clean as far as Virustotal was concerned, some had multiple reports for different malware. This shows the value of proactive infrastructure analysis, it is possible to map out additional C2s before they are identified as malicious or used in attacks. 

The analysis also allowed the grouping of the 26 hosts into different clusters. We identified 12 hosts which are almost certainly set up in identically. This could be a sign of a campaign that is of significant size or it could be a bunch of lazy operators who have not changed the settings on their C2. Depending on the context of the investigation and the initial starting point this type of information would be useful to for example perform attribution, to fully understand the campaign, track the threat actor or to map out their infrastructure.

```

Broad search query

http.html_hash:1929577144 http.headers_hash:707481832

Cluster #1

http.html_hash:1929577144 http.headers_hash:707481832 ssl.jarm:2ad2ad16d00000022c2ad2ad2ad2ad46ff59a659b30fd8aeaa6755c67691b4 ssl.ja3s:ae4edc6faf64d08308082ad26be60767 

Cluster #2-8

http.html_hash:1929577144 http.headers_hash:707481832 ssl.ja3s:6c2811f7ba8e88604ea41a2bf9fa5ad7

All hosts identified at the time of writing this

167.17.76[.]105
31.76.251[.]246
172.96.172[.]79
5.101.84[.]18
185.199.198[.]72
91.92.241[.]78
85.17.7[.]40
45.225.135[.]24
84.201.20[.]74
46.161.0[.]57
198.46.142[.]201
5.101.81[.]224
191.101.131[.]12
194.233.79[.]130
111.90.145[.]132
65.109.115[.]25
217.217.254[.]63
15.235.174[.]249
128.90.123[.]241
128.90.108[.]49
178.16.53[.]240
23.94.232[.]8

```
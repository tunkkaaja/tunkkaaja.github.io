---
layout: post
title: Analyzing Adversary Infrastructure
date: 2026-07-21 19:45 +0300
categories: [threat intel]
description: Analyzing threat actor infrastructure to identify additional command & control servers.
---

# The starting point

After completing the Intel-Ops [Hunting Adversary Infrastructure](https://academy.intel-ops.io/courses/hunting-adversary-infra) course I wanted to use the techniques and methods I learned from it to identify live threat actor infrastructure. I came across [this article](https://blog.deception.pro/blog/cpuz-trojan-stxrat-purelogs-data-exfil-april-2026) detailing a campaign of various malware being delivered with trojanized software. The article outlines the infection chain, the threat actor's activities, defensive recommendations, and indicators of compromise (IOC).

During my initial review of the article one detail about the IOCs stood out to me. Two of the malware listed had their Command & Control servers (C2s) in the same network, this is not very common as threat actors often attempt to spread out their infrastructure among different service provides or only have a single C2 server per campaign.

![Indicators of Compromise](assets/img/posts/2026-07-19-analyzing-purelogs-stealer-infrastructure/indiactors.png){: w="500" h="300" .normal }

These two IP addresses became the starting point for my investigation:

```
176.65.144[.]84
176.65.144[.]46
```



# Finding the first pivot points

After identifying interesting points to investigate I first queried Shodan and Modat to determine if they were currently hosting any services, they were not. This was not a surprise as threat actors, or the hosting providers they use, often take down their infrastructure after it has been mentioned publicly. Next step was examining historical data for the hosts from Validin and FOFA. Interestingly the services showed that ***both*** IP addresses had hosted a service on port **8443** shortly before the article was published (April 13th). The article listed only one of them hosting a C2 at port **8443** with the other being present on port **65001**. Another thing to note is neither host showed a service at the port **65001**, however this could also be due to limitation of the platforms.

Quick look reveals both services at port 8443 responded with identical headers, same JARM and HTML hashes, as well as with a similar certificate with seemingly sensible but clearly fake details. These services are almost certainly at least similar if not identical.

![First Pivot](assets/img/posts/2026-07-19-analyzing-purelogs-stealer-infrastructure/first_pivot.png){: w="820" h="420" .normal }

# Pivoting to identify live servers from Shodan

The two hosts no longer had the services live on port 8443 so it was necessary to use the historical data from the first pivot points we identified to find live servers. As the hash for the HTTP headers and the HTML body are not calculated in the same way for FOFA and Shodan some other identifying data points had to be used. Using just **three** specific identifiers from the FOFA data it was possible to build an initial Shodan search query to find some live servers with the same C2. The **JARM fingerprint value**, which is a [method](https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a/) for fingerprinting different TLS implementations, the **port 8443** and the **content length** visible in the HTTP headers.

This resulted in the search query:

```
ssl.jarm:"2ad2ad16d00000022c2ad2ad2ad2ad46ff59a659b30fd8aeaa6755c67691b4" port:8443 "Content-Length: 18"
```

At the time of writing this query returns **19 hosts**. It is possible to quickly identify the hosts have a similar service, almost certainly a C2 server, running with identical headers and similar nonsensical certificate details.

![Initial results](assets/img/posts/2026-07-19-analyzing-purelogs-stealer-infrastructure/shodan_results1.png){: w="620" h="220" .normal }


# Tweaking the Shodan search query

After identifying live servers with the C2 services visible it was necessary to further tweak the Shodan search query. When doing infrastructure analysis it is risky to use more vague search terms, such as common port numbers or header content length values, as they can lead to falsely identifying servers as C2s. Though they can be very useful to identify initial pivot points. For example currently Shodan reports ~6.5 million servers with port 8443 and ~29.9 million servers responding with the header length 18. Using these in the search query could easily leave in false positive findings if you are not careful.

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

This also very nicely demonstrates how the **JA3S** value changes due to the cipher suite in the TLS connection, as the cipher is one of the building blocks the JA3S is calculated from.

![JA3S description](assets/img/posts/2026-07-19-analyzing-purelogs-stealer-infrastructure/ja3s-text.png){: w="650" h="300" .normal }

It is also possible to see the same phenomenon with the **JARM** values. As the first 30 digits of the value is: 

> *"made of the cipher and TLS version chosen by the server for each of the 10 client hello’s sent. A “000” denotes that the server refused to negotiate with that client hello."*

This means that 10 TLS client hello packets are sent to the server and the specific attributes in the responses to each of the 10 responses is hashed and represented by 3 digits, adding up to 30 digits at the start of each JARM value. As we know the 12 of the hosts use **ECDHE-RSA-AES256-GCM-SHA384** while the remaining 14 use **TLS_AES_256_GCM_SHA384**. Focusing only on the first 30 digits it is possible to see that the first **JARM** value listed is clearly different from the rest. The remaining ones are very similar, especially when you take into account that **000** means the server refused the negotiation for some reason and most of the hosts having responded with **42d** at least once but just at different times. This means that the 14 hosts have a quite similar TLS implementation, possibly only set up differently, slightly different versions of the same C2, maybe running on different operating systems or with different libraries being used.

![JARM value similarities](assets/img/posts/2026-07-19-analyzing-purelogs-stealer-infrastructure/jarm2.png)

This information allows us to cluster these hosts based on their similarity and various aspects of their fingerprints. One clearly different cluster with all 12 hosts having identical TLS implementations and another cluster/multiple smaller clusters of hosts with slightly different TLS implementations.

![Maltego graph](assets/img/posts/2026-07-19-analyzing-purelogs-stealer-infrastructure/maltego.png)

# Conclusion

Although the two hosts identified from the article were no longer hosting the C2 infrastructure, pivoting from them through infrastructure analysis revealed 26 additional hosts with active C2 servers. Most of the identified C2 IP addresses were clean as far as Virustotal was concerned, some had multiple reports for different malware. This shows some of the value of proactive infrastructure analysis, it is possible to map out additional C2s before they are identified as malicious or even used in attacks.

The analysis of the data also allowed the grouping of the 26 hosts into different clusters. We identified 12 hosts which are almost certainly set up identically and running the same software. This could be a sign of a campaign that is quite significant in size or it could be a bunch of lazy operators who have not changed the settings on their C2. The 14 remaining hosts were slightly different, some being unique and some in smaller clusters. This could represent a bunch of different campaigns set up by the same threat actor or just a bunch of different threat actors running the same software and having set up them differently.

Depending on the scope and context of the investigation and the initial point of entry, this type of information can be used to support attribution, comprehensively map and understand the campaign, track the threat actor, and identify the extent of their infrastructure.

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
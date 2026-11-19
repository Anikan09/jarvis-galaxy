# OSINT module

Passive, public lookups of domains and IP addresses, and a check of what a photo or PDF gives away before you share it.

**Switch it on:** `"modules": { "osint": true }` in `config.json`. Optional extras: `pip install dnspython` (MX, TXT, NS, CAA and DMARC records; A/AAAA work without it) and `pip install pillow` (photos; PDFs need nothing).

| Say | What happens | What leaves the PC |
|---|---|---|
| "Whois example.com" / "DNS records for example.com" / "SSL certificate of example.com" | Registration (RDAP), DNS records with SPF/DMARC checks, and the TLS certificate. Points out new domains, missing mail protection, expiring or broken certificates. | The domain, to the public RDAP registry and DNS; one ordinary TLS handshake with the site |
| "Who hosts example.com?" / "Threat intel on example.com" | As above, plus what the live web says about it (blocklists, abuse reports, the provider). | Additionally the domain and the lookup results, to Claude and its web search |
| "IP reputation of 8.8.8.8" | Reverse DNS, the network that owns it, its abuse contact, and public reporting from the live web. | The address, to RDAP, DNS and Claude's web search |
| "Check the metadata of C:\…\cv.pdf" / "Is C:\…\photo.jpg safe to share?" | GPS, camera serial numbers, author and owner names, software, user folders hidden in paths, saved revisions, comments and attachments, with how to share a clean copy. | Nothing |

## Limits, in code

- **Registrant names, e-mails, phones and addresses are never shown**, even when a registry publishes them. This is for infrastructure, not for profiling people. The web research is told the same.
- **Private, loopback and reserved addresses** (192.168.x.x, 10.x.x.x, localhost) are answered locally: nothing is looked up anywhere.
- **No scanning, no brute force, no zone transfers.** The only contact with a target is one TLS handshake.
- **Private mode** declines the live-web part; the passive lookups still work.

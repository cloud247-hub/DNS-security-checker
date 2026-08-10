# DomainGuard — DNS & Email Security Checker

A static, GitHub Pages-compatible web app that checks public DNS and email-security records for a domain.

## Checks

- DNSSEC (DNSKEY / DS + resolver AD validation)
- MX
- SPF
- DKIM (custom selector + optional scan of common selectors)
- DMARC
- MTA-STS DNS record
- SMTP TLS reporting (TLS-RPT)
- CAA
- BIMI (`default._bimi`)
- A / AAAA / NS / SOA overview

## How it works

The site is fully static. Browser-side JavaScript queries Cloudflare's public DNS-over-HTTPS JSON endpoint. There is no application backend and no API key.

> Note: DKIM selectors are not standardized. A failed selector scan does **not** prove that a domain has no DKIM. Enter the selector used by the sender for a definitive record lookup.

> Note: The MTA-STS check in this version verifies the `_mta-sts` TXT record only. It does not fetch and validate the HTTPS policy file.


## Privacy

Domain names entered into the checker are sent from the browser to Cloudflare's public DNS resolver in order to perform DNS lookups. The app itself stores no server-side data because there is no backend.

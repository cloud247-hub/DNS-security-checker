# DomainGuard

DomainGuard er en statisk webapp for kontroll av DNS- og e-postsikkerhet for et domene.

## Kontroller

- DNSSEC
- MX
- SPF
- DKIM
- DMARC
- MTA-STS
- SMTP TLS-RPT
- CAA
- BIMI
- A / AAAA
- NS / SOA

Appen viser også norske forklaringer og konkrete forslag til hvordan mangler kan rettes. For SPF, DKIM, MX og enkelte andre kontroller brukes plassholdere der den riktige verdien må hentes fra e-post- eller DNS-leverandøren.

## Personvern og teknikk

DNS-oppslag gjøres direkte fra brukerens nettleser mot Cloudflares offentlige DNS-over-HTTPS-endepunkt. Det kreves ingen egen backend eller API-nøkkel.

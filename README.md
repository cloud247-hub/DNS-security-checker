# DomainGuard – norsk versjon

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

## GitHub Pages

1. Opprett et GitHub-repository.
2. Last opp alle filene i denne mappen til roten av repoet.
3. Gå til **Settings → Pages**.
4. Velg **Deploy from a branch**.
5. Velg `main` og `/(root)`.
6. Lagre.

Appen bruker relative filstier og inkluderer `.nojekyll`, så den fungerer også når den publiseres under et prosjektnavn, for eksempel:

`https://brukernavn.github.io/domainguard/`

## Personvern og teknikk

DNS-oppslag gjøres direkte fra brukerens nettleser mot Cloudflares offentlige DNS-over-HTTPS-endepunkt. Det kreves ingen egen backend eller API-nøkkel.

## Viktig

Forslagene til DNS-poster er veiledende. Ikke publiser plassholderverdier som `<SPF-VERDI-FRA-E-POSTLEVERANDØR>` eller `<VERDI-FRA-E-POSTLEVERANDØREN>`. Bruk verdiene fra den faktiske tjenesten som sender eller mottar e-post for domenet.

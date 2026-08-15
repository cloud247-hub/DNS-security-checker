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


## Vipps – «Spander meg en kaffe»

Nederst på siden ligger en støtteknapp på **20,- kr** som åpner denne Vipps-lenken:

```text
https://qr.vipps.no/box/90e4bd01-a470-474a-98fa-8b48f69b0f4e/pay-in
```

Knappen åpner Vipps-betalingssiden i en ny fane.

## Cloud247-design

Denne utgaven bruker samme visuelle system som Cloud247 CAA Record Generator: Cloud247-logo, mørkeblå/gul header og hero, panelstil, responsiv mobilvisning og lenke til øvrige verktøy på `https://cloud247.no/`. Logoen er sentrert på mobil. Eksisterende verktøyfunksjonalitet er beholdt.

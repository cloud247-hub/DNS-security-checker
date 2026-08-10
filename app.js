const DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query';
const TYPES = { A:1, NS:2, CNAME:5, SOA:6, MX:15, TXT:16, AAAA:28, DS:43, RRSIG:46, DNSKEY:48, CAA:257 };
const commonSelectors = ['selector1','selector2','google','default','s1','s2','k1','dkim','mail','smtp'];
const state = { report: null };

const $ = (id) => document.getElementById(id);
const escapeHtml = (s='') => String(s).replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));

function normalizeDomain(value) {
  let v = String(value || '').trim().toLowerCase();
  v = v.replace(/^https?:\/\//, '').split('/')[0].split(':')[0].replace(/\.$/, '');
  if (!v || v.length > 253 || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$/i.test(v)) {
    throw new Error('Skriv inn et gyldig domene, for eksempel eksempel.no.');
  }
  return v;
}

async function dnsQuery(name, type, opts={}) {
  const params = new URLSearchParams({ name, type, do: opts.do === false ? 'false' : 'true' });
  if (opts.cd) params.set('cd','true');
  const res = await fetch(`${DOH_ENDPOINT}?${params.toString()}`, { headers: { accept:'application/dns-json' } });
  if (!res.ok) throw new Error(`DNS-tjeneren svarte med HTTP ${res.status}.`);
  return res.json();
}

function answers(r, typeName) {
  const type = TYPES[typeName];
  return (r?.Answer || []).filter(x => x.type === type);
}
function txtValues(r) {
  return answers(r,'TXT').map(x => String(x.data).replace(/^"|"$/g,'').replace(/"\s+"/g,''));
}
function firstTxtByPrefix(r, prefix) {
  return txtValues(r).find(v => v.toLowerCase().startsWith(prefix.toLowerCase())) || '';
}
function parseTagRecord(record) {
  const out = {};
  String(record || '').split(';').map(x => x.trim()).filter(Boolean).forEach(part => {
    const i = part.indexOf('=');
    if (i > -1) out[part.slice(0,i).trim().toLowerCase()] = part.slice(i+1).trim();
  });
  return out;
}
function status(severity, label, subtitle, detail='', records=[]) {
  return { severity, label, subtitle, detail, records };
}

function evaluateDnssec(ds, dnskey) {
  const dsRecords = answers(ds,'DS');
  const keys = answers(dnskey,'DNSKEY');
  if (dnskey.Status === 2) return status('bad','Validering feilet','DNSSEC ser ut til å være ødelagt','Den validerende DNS-tjeneren returnerte SERVFAIL ved oppslag av DNSKEY. Dette kan tyde på en feil i DNSSEC-kjeden.', []);
  if (keys.length && dnskey.AD) return status('good','Validert','DNSSEC er aktivert','DNSKEY-poster ble returnert og autentisert av den validerende DNS-tjeneren.', keys.map(x=>x.data));
  if (keys.length) return status('warn','Finnes, men ikke validert','DNSKEY ble funnet','DNSKEY finnes, men svaret ble ikke autentisert. Kontroller DS-posten hos parent-sonen og signeringskjeden.', keys.map(x=>x.data));
  if (dsRecords.length) return status('bad','DS uten DNSKEY','Mulig DNSSEC-feil','En DS-post finnes hos parent-sonen, men ingen DNSKEY ble returnert for domenet.', dsRecords.map(x=>x.data));
  return status('warn','Ikke aktivert','Ingen DNSSEC-signering funnet','Det ble ikke funnet DNSKEY for domenet.', []);
}

function evaluateMx(r) {
  const rows = answers(r,'MX').map(x => {
    const m = String(x.data).match(/^(\d+)\s+(.+)$/);
    return { priority:m?Number(m[1]):0, host:(m?m[2]:x.data).replace(/\.$/,'') };
  }).sort((a,b)=>a.priority-b.priority);
  if (!rows.length) return { ...status('bad','Mangler','Ingen MX-poster','Det ble ikke funnet MX-poster. Domenet er kanskje ikke konfigurert for å motta e-post.'), parsed:[] };
  if (rows.length === 1 && rows[0].host === '') return { ...status('info','Null MX','Domenet mottar ikke e-post','Domenet publiserer en null MX-post og oppgir dermed at det ikke skal motta e-post.'), parsed:rows };
  return { ...status('good','Konfigurert',`${rows.length} e-postserver${rows.length===1?'':'e'}`,'MX-poster er publisert og angir hvilke servere som mottar e-post for domenet.', rows.map(x=>`${x.priority} ${x.host}`)), parsed:rows };
}

function evaluateSpf(r) {
  const all = txtValues(r).filter(v=>/^v=spf1\b/i.test(v));
  if (!all.length) return status('bad','Mangler','Ingen SPF-policy','Publiser én SPF TXT-post som beskriver hvilke systemer som har lov til å sende e-post på vegne av domenet.');
  if (all.length > 1) return status('bad','Flere poster',`${all.length} SPF-poster funnet`,'SPF skal normalt publiseres som én samlet v=spf1-post. Flere SPF-poster kan føre til PermError.', all);
  const rec = all[0];
  let sev='good', label='Konfigurert', sub='SPF-policy funnet';
  if (/\s\+all(?:\s|$)/i.test(rec)) { sev='bad'; label='Usikker'; sub='+all tillater alle avsendere'; }
  else if (/\s~all(?:\s|$)/i.test(rec)) { sev='warn'; label='Softfail'; sub='SPF avsluttes med ~all'; }
  else if (!/\s-all(?:\s|$)/i.test(rec)) { sev='warn'; label='Bør vurderes'; sub='Ingen hard fail (-all) funnet'; }
  return status(sev,label,sub,'SPF styrer hvilken utsendingsinfrastruktur som er autorisert for domenet.',[rec]);
}

function evaluateDmarc(r) {
  const rec = firstTxtByPrefix(r,'v=DMARC1');
  if (!rec) return status('bad','Mangler','Ingen DMARC-policy','DMARC bruker SPF/DKIM-alignment til å beskytte domenet mot spoofing og kan sende rapporter om autentisering.');
  const tags = parseTagRecord(rec);
  const p=(tags.p||'').toLowerCase();
  if (p==='reject') return status('good','Reject','Sterk DMARC-håndheving','Meldinger som ikke består DMARC blir bedt avvist av mottakende e-postserver.',[rec]);
  if (p==='quarantine') return status('warn','Quarantine','Delvis DMARC-håndheving','Meldinger som feiler DMARC blir bedt satt i karantene. Vurder reject når alle legitime avsendere er verifisert.',[rec]);
  if (p==='none') return status('warn','Overvåking','DMARC-policy er p=none','DMARC samler innsyn, men ber ikke mottakere håndheve en beskyttende policy.',[rec]);
  return status('warn','Bør vurderes','DMARC-posten bør kontrolleres','En DMARC-post finnes, men policyen kunne ikke klassifiseres sikkert.',[rec]);
}

function evaluateDkim(results, selectors) {
  const found=[];
  results.forEach((r,i)=>{
    const rec=firstTxtByPrefix(r,'v=DKIM1') || txtValues(r).find(v=>/\bp=/.test(v));
    if(rec) found.push({selector:selectors[i],record:rec});
  });
  if (!found.length) return { ...status('warn','Ikke funnet','Ingen DKIM-nøkkel funnet','DKIM-selectorer er ikke standardiserte. Ingen nøkkel ble funnet med selectorene som ble testet. Det beviser ikke at domenet mangler DKIM.'), found:[] };
  const revoked=found.filter(x=>/\bp=\s*(?:;|$)/i.test(x.record));
  if (revoked.length===found.length) return { ...status('warn','Tilbakekalt',`${found.length} selector${found.length===1?'':'er'} funnet`,'De oppdagede DKIM-postene ser ut til å ha tom offentlig nøkkel.',found.map(x=>`${x.selector}: ${x.record}`)), found };
  return { ...status('good','Funnet',`${found.length} DKIM-selector${found.length===1?'':'er'} funnet`,'Minst én offentlig DKIM-nøkkel ble funnet blant selectorene som ble kontrollert.',found.map(x=>`${x.selector}: ${x.record}`)), found };
}

function evaluateMtaSts(r) {
  const rec=firstTxtByPrefix(r,'v=STSv1');
  return rec ? status('good','Publisert','MTA-STS DNS-post funnet','_mta-sts TXT-posten finnes. Denne nettleserbaserte kontrollen validerer ikke selve HTTPS-policyfilen.',[rec]) : status('warn','Mangler','Ingen MTA-STS TXT-post','MTA-STS kan hjelpe avsendende e-postservere med å kreve autentisert TLS ved levering.');
}

function evaluateTlsRpt(r) {
  const rec=firstTxtByPrefix(r,'v=TLSRPTv1');
  return rec ? status('good','Publisert','TLS-RPT er aktivert','Domenet annonserer en adresse for rapporter om SMTP TLS-feil.',[rec]) : status('warn','Mangler','Ingen TLS-RPT-post','TLS-RPT kan gi rapporter om feil i TLS-forhandling og transportpolicy.');
}

function evaluateCaa(r) {
  const rows=answers(r,'CAA').map(x=>x.data);
  return rows.length ? status('good','Begrenset',`${rows.length} CAA-post${rows.length===1?'':'er'}`,'CAA kan begrense hvilke sertifikatutstedere som får utstede sertifikater for domenet.',rows) : status('info','Ikke satt','Ingen CAA-poster','Uten CAA er sertifikatutstedelse ikke begrenset av en CAA-policy på dette domenenavnet.');
}

function evaluateBimi(r) {
  const rec=firstTxtByPrefix(r,'v=BIMI1');
  return rec ? status('good','Publisert','BIMI-post funnet','En BIMI TXT-post ble funnet på default._bimi.',[rec]) : status('info','Ikke funnet','Ingen standard BIMI-post','BIMI er valgfritt og krever normalt sterk DMARC-håndheving.');
}

async function runScan(domain, customSelector, scanCommon) {
  $('loadingText').textContent='Henter sentrale DNS-poster';
  const names = {
    dmarc:`_dmarc.${domain}`,
    mtasts:`_mta-sts.${domain}`,
    tlsrpt:`_smtp._tls.${domain}`,
    bimi:`default._bimi.${domain}`
  };
  const [a,aaaa,ns,soa,mx,txt,ds,dnskey,caa,dmarc,mtasts,tlsrpt,bimi] = await Promise.all([
    dnsQuery(domain,'A'), dnsQuery(domain,'AAAA'), dnsQuery(domain,'NS'), dnsQuery(domain,'SOA'),
    dnsQuery(domain,'MX'), dnsQuery(domain,'TXT'), dnsQuery(domain,'DS'), dnsQuery(domain,'DNSKEY'),
    dnsQuery(domain,'CAA'), dnsQuery(names.dmarc,'TXT'), dnsQuery(names.mtasts,'TXT'), dnsQuery(names.tlsrpt,'TXT'), dnsQuery(names.bimi,'TXT')
  ]);

  let selectors=[];
  if (customSelector) selectors.push(...customSelector.split(',').map(s=>s.trim()).filter(Boolean));
  if (scanCommon) selectors.push(...commonSelectors);
  selectors=[...new Set(selectors.map(s=>s.replace(/\._domainkey.*$/,'').toLowerCase()).filter(s=>/^[a-z0-9_-]{1,63}$/i.test(s)))].slice(0,15);
  $('loadingText').textContent = selectors.length ? `Sjekker ${selectors.length} DKIM-selector${selectors.length===1?'':'er'}` : 'Vurderer policyer';
  const dkimResults = selectors.length ? await Promise.all(selectors.map(s=>dnsQuery(`${s}._domainkey.${domain}`,'TXT'))) : [];

  const checks = {
    dnssec:evaluateDnssec(ds,dnskey), mx:evaluateMx(mx), spf:evaluateSpf(txt), dkim:evaluateDkim(dkimResults,selectors), dmarc:evaluateDmarc(dmarc),
    mtasts:evaluateMtaSts(mtasts), tlsrpt:evaluateTlsRpt(tlsrpt), caa:evaluateCaa(caa), bimi:evaluateBimi(bimi)
  };
  const raw={a,aaaa,ns,soa,mx,txt,ds,dnskey,caa,dmarc,mtasts,tlsrpt,bimi,dkim:dkimResults};
  return { domain, scannedAt:new Date().toISOString(), selectorsChecked:selectors, checks, raw };
}

const severityIcon = { good:'✓', warn:'!', bad:'×', info:'i' };
const severityRank = { bad:0, warn:1, info:2, good:3 };

function scoreReport(checks) {
  const weights={dnssec:15,mx:10,spf:15,dkim:15,dmarc:20,mtasts:8,tlsrpt:7,caa:5,bimi:5};
  const factor={good:1,info:.65,warn:.4,bad:0};
  let score=0;
  Object.entries(weights).forEach(([k,w])=>score+=w*(factor[checks[k].severity]??0));
  return Math.round(score);
}
function scoreLabel(score) {
  return score>=85?'Sterk':score>=70?'God':score>=50?'Bør forbedres':'Høy risiko';
}
function checkMeta(key) {
  return {
    dnssec:['DNSSEC','DNS-integritet'],
    mx:['MX','E-postruting'],
    spf:['SPF','Autoriserte avsendere'],
    dkim:['DKIM','Kryptografisk e-postsignering'],
    dmarc:['DMARC','Autentiseringspolicy'],
    mtasts:['MTA-STS','SMTP-transportpolicy'],
    tlsrpt:['TLS-RPT','Rapportering av TLS-feil'],
    caa:['CAA','Policy for sertifikatutstedere'],
    bimi:['BIMI','Logo og merkevareindikator']
  }[key];
}
function summaryCard(key,check) {
  const [name]=checkMeta(key);
  return `<article class="summary-card"><div class="summary-top"><h4>${name}</h4><span class="status-icon ${check.severity}">${severityIcon[check.severity]}</span></div><div class="summary-value">${escapeHtml(check.label)}</div><p>${escapeHtml(check.subtitle)}</p></article>`;
}

function findingText(key,c) {
  if (c.severity==='good') return null;
  const map={
    dnssec:{bad:'DNSSEC-valideringen feiler.',warn:'DNSSEC er ikke fullt validert.',info:'Kontroller DNSSEC-status.'},
    mx:{bad:'E-postruting er ikke konfigurert.',warn:'MX-konfigurasjonen bør kontrolleres.',info:'Domenet oppgir at det ikke mottar e-post.'},
    spf:{bad:'SPF mangler eller er ugyldig.',warn:'SPF-policyen kan styrkes.',info:'Kontroller SPF.'},
    dkim:{bad:'DKIM-nøklene ser ugyldige ut.',warn:'Ingen DKIM-nøkkel ble funnet med selectorene som ble testet.',info:'Kontroller DKIM.'},
    dmarc:{bad:'DMARC-beskyttelse mangler.',warn:'DMARC finnes, men er ikke på full håndheving.',info:'Kontroller DMARC.'},
    mtasts:{bad:'MTA-STS krever oppfølging.',warn:'MTA-STS er ikke annonsert.',info:'Kontroller MTA-STS.'},
    tlsrpt:{bad:'TLS-rapportering krever oppfølging.',warn:'SMTP TLS-rapportering er ikke aktivert.',info:'Kontroller TLS-RPT.'},
    caa:{bad:'CAA krever oppfølging.',warn:'Kontroller CAA.',info:'Ingen CAA-begrensning er publisert.'},
    bimi:{bad:'BIMI krever oppfølging.',warn:'Kontroller BIMI.',info:'BIMI ble ikke funnet. Dette er valgfritt.'}
  };
  return map[key]?.[c.severity] || c.subtitle;
}

function renderFindings(checks) {
  const priority=['dnssec','dmarc','spf','dkim','mx','mtasts','tlsrpt','caa','bimi'];
  const items=priority.map(k=>({k,c:checks[k],text:findingText(k,checks[k])})).filter(x=>x.text).sort((a,b)=>severityRank[a.c.severity]-severityRank[b.c.severity]);
  const goodCore=['dnssec','mx','spf','dkim','dmarc'].filter(k=>checks[k].severity==='good');
  if (goodCore.length>=4) items.push({k:'mx',c:{severity:'good',subtitle:'De viktigste kontrollene ser sunne ut.'},text:`${goodCore.length} av 5 sentrale DNS-/e-postkontroller besto.`});
  $('findingCount').textContent=items.length;
  $('findingsList').innerHTML=items.length ? items.map(x=>`<div class="finding"><span class="finding-icon ${x.c.severity}">${severityIcon[x.c.severity]}</span><div><strong>${escapeHtml(x.text)}</strong><p>${escapeHtml(x.c.subtitle)}</p></div></div>`).join('') : '<div class="finding"><span class="finding-icon good">✓</span><div><strong>Ingen tydelige problemer funnet</strong><p>Kontrollene som ble utført ser sunne ut.</p></div></div>';
}

function fixData(key, c, domain) {
  if (c.severity === 'good') return null;
  const rua = `dmarc@${domain}`;
  const tlsrua = `tlsrpt@${domain}`;
  const data = {
    dmarc: {
      title:'Slik kommer du i gang med DMARC',
      steps:[
        'Kontroller først at alle legitime e-posttjenester bruker SPF og/eller DKIM riktig.',
        'Opprett DMARC-posten i DNS og start med overvåking (p=none).',
        'Les DMARC-rapportene og identifiser alle legitime avsendere.',
        'Når alt legitimt passerer DMARC, øk gradvis til p=quarantine og deretter p=reject.'
      ],
      records:[{name:`_dmarc.${domain}`,type:'TXT',value:`v=DMARC1; p=none; rua=mailto:${rua}; pct=100`}],
      warning:`E-postadressen ${rua} er et eksempel. Opprett den eller bruk en DMARC-rapporttjeneste. Ikke gå rett til p=reject før du vet at legitime avsendere består DMARC.`
    },
    spf: {
      title:'Slik retter du SPF',
      steps:[
        'Lag en liste over alle tjenester som faktisk sender e-post for domenet, for eksempel Microsoft 365, Google Workspace, nyhetsbrev eller fagsystemer.',
        'Finn den offisielle SPF-include-verdien hos hver leverandør.',
        'Slå alle tillatte avsendere sammen i én SPF-post.',
        'Publiser bare én v=spf1-post på rotdomenet og test på nytt.'
      ],
      records:[{name:domain,type:'TXT',value:'v=spf1 include:<SPF-VERDI-FRA-E-POSTLEVERANDØR> -all'}],
      warning:'Ikke kopier eksempelverdien direkte. En feil SPF-post kan føre til at legitim e-post havner i søppelpost eller avvises. Domenet skal normalt bare ha én SPF-post.'
    },
    dkim: {
      title:'Slik konfigurerer du DKIM',
      steps:[
        'Åpne administrasjonssiden hos e-postleverandøren og aktiver DKIM for domenet.',
        'Leverandøren oppgir en selector og en offentlig nøkkel eller en CNAME-post.',
        'Publiser nøyaktig DNS-posten leverandøren oppgir.',
        'Skriv selector-navnet i DomainGuard-feltet og kjør testen på nytt.'
      ],
      records:[{name:`<selector>._domainkey.${domain}`,type:'TXT eller CNAME',value:'<VERDI-FRA-E-POSTLEVERANDØREN>'}],
      warning:'DomainGuard kan ikke generere en ekte DKIM-nøkkel for e-postsystemet ditt. Selector og nøkkel må komme fra tjenesten som signerer utgående e-post.'
    },
    dnssec: {
      title:'Slik aktiverer eller reparerer du DNSSEC',
      steps:[
        'Aktiver DNSSEC hos DNS-leverandøren som drifter den autoritative sonen.',
        'Kopier DS-informasjonen fra DNS-leverandøren til domeneregistraren dersom dette ikke gjøres automatisk.',
        'Vent på DNS-oppdatering og kjør kontrollen på nytt.',
        'Hvis DNSSEC allerede er aktivert og valideringen feiler, kontroller at DS hos registraren matcher gjeldende DNSKEY.'
      ],
      records:[],
      warning:'Feil DS-verdier kan gjøre domenet utilgjengelig for DNSSEC-validerende klienter. Endre ikke DS manuelt uten å følge instruksjonene fra DNS-leverandøren.'
    },
    mx: {
      title:'Slik konfigurerer du MX',
      steps:[
        'Finn MX-verdiene i dokumentasjonen til e-postleverandøren din.',
        'Opprett MX-postene med riktig prioritet.',
        'Fjern gamle MX-poster som ikke lenger skal motta e-post.',
        'Test domenet på nytt etter at DNS er oppdatert.'
      ],
      records:[{name:domain,type:'MX',value:'<PRIORITET> <MX-SERVER-FRA-E-POSTLEVERANDØR>'}],
      warning:'MX-servernavn og prioritet er leverandørspesifikke. Bruk verdiene fra e-postleverandøren.'
    },
    mtasts: {
      title:'Slik kommer du i gang med MTA-STS',
      steps:[
        'Opprett TXT-posten _mta-sts med en unik id-verdi.',
        `Konfigurer HTTPS på mta-sts.${domain} med gyldig sertifikat.`,
        'Publiser policyfilen på /.well-known/mta-sts.txt.',
        'Start gjerne med mode: testing før du går over til mode: enforce.'
      ],
      records:[{name:`_mta-sts.${domain}`,type:'TXT',value:'v=STSv1; id=20260810'}],
      warning:'MTA-STS krever også en HTTPS-policyfil. DNS-posten alene er ikke nok.'
    },
    tlsrpt: {
      title:'Slik aktiverer du TLS-RPT',
      steps:[
        'Velg en e-postadresse eller rapporttjeneste som skal motta TLS-rapportene.',
        'Opprett TXT-posten på _smtp._tls.',
        'Kontroller at mottaksadressen håndterer rapporter og at postkassen overvåkes.'
      ],
      records:[{name:`_smtp._tls.${domain}`,type:'TXT',value:`v=TLSRPTv1; rua=mailto:${tlsrua}`}],
      warning:`Adressen ${tlsrua} er et eksempel. Opprett postkassen eller bruk adressen fra TLS-rapporttjenesten din.`
    },
    caa: {
      title:'Slik begrenser du sertifikatutstedelse med CAA',
      steps:[
        'Finn hvilke sertifikatutstedere som faktisk brukes for domenet og tjenestene dine.',
        'Publiser CAA-poster som tillater disse utstederne.',
        'Kontroller også tredjepartstjenester før du gjør policyen for streng.'
      ],
      records:[{name:domain,type:'CAA',value:'0 issue "<DIN-SERTIFIKATUTSTEDER>"'}],
      warning:'Ikke publiser en tilfeldig CA. En for streng CAA-policy kan hindre fornyelse eller utstedelse av sertifikater.'
    },
    bimi: {
      title:'Slik kommer du i gang med BIMI',
      steps:[
        'Sørg først for at DMARC er på en håndhevende policy og at e-postautentisering fungerer stabilt.',
        'Gjør logoen tilgjengelig i korrekt SVG-format på HTTPS.',
        'Opprett BIMI TXT-posten på default._bimi.',
        'Kontroller kravene hos e-postleverandørene du ønsker logo hos; enkelte kan kreve et verifisert merke-sertifikat.'
      ],
      records:[{name:`default._bimi.${domain}`,type:'TXT',value:'v=BIMI1; l=https://<DITT-DOMENE>/logo.svg;'}],
      warning:'BIMI er valgfritt. Prioriter SPF, DKIM og DMARC før du bruker tid på BIMI.'
    }
  };
  return data[key] || null;
}

function dnsTemplate(record, index, key) {
  const payload = `${record.name}\t${record.type}\t${record.value}`;
  return `<div class="dns-template">
    <div class="dns-template-head"><strong>Forslag til DNS-post</strong><button class="copy-button" type="button" data-copy="${escapeHtml(payload)}">Kopier</button></div>
    <dl>
      <div><dt>Navn</dt><dd>${escapeHtml(record.name)}</dd></div>
      <div><dt>Type</dt><dd>${escapeHtml(record.type)}</dd></div>
      <div><dt>Verdi</dt><dd>${escapeHtml(record.value)}</dd></div>
    </dl>
  </div>`;
}

function remediationHtml(key, c, domain) {
  const fix=fixData(key,c,domain);
  if (!fix) return '';
  const steps=fix.steps.map(s=>`<li>${escapeHtml(s)}</li>`).join('');
  const records=fix.records.map((r,i)=>dnsTemplate(r,i,key)).join('');
  return `<div class="fix-box">
    <h4>${escapeHtml(fix.title)}</h4>
    <ol class="fix-steps">${steps}</ol>
    ${records}
    ${fix.warning ? `<div class="fix-warning"><strong>Før du publiserer:</strong> ${escapeHtml(fix.warning)}</div>` : ''}
  </div>`;
}

function renderChecks(checks, domain) {
  const order=['dnssec','mx','spf','dkim','dmarc','mtasts','tlsrpt','caa','bimi'];
  $('checksList').innerHTML=order.map(k=>{
    const c=checks[k], [name,desc]=checkMeta(k);
    const recs=(c.records||[]).map(r=>`<div class="record-box">${escapeHtml(r)}</div>`).join('');
    return `<article class="check-item">
      <button class="check-toggle" type="button">
        <span class="status-icon ${c.severity}">${severityIcon[c.severity]}</span>
        <span class="check-name"><strong>${name}</strong><span>${desc}</span></span>
        <span class="check-status ${c.severity}">${escapeHtml(c.label)}</span>
        <span class="chevron">⌄</span>
      </button>
      <div class="check-detail">
        <p>${escapeHtml(c.detail||c.subtitle)}</p>
        ${recs || '<div class="record-box">Ingen samsvarende DNS-post ble returnert.</div>'}
        ${remediationHtml(k,c,domain)}
      </div>
    </article>`;
  }).join('');

  document.querySelectorAll('.check-toggle').forEach(btn=>btn.addEventListener('click',()=>btn.parentElement.classList.toggle('open')));
  document.querySelectorAll('.copy-button').forEach(btn=>btn.addEventListener('click', async ()=>{
    const value=btn.dataset.copy || '';
    try {
      await navigator.clipboard.writeText(value);
      const old=btn.textContent;
      btn.textContent='Kopiert';
      setTimeout(()=>btn.textContent=old,1200);
    } catch {
      btn.textContent='Kunne ikke kopiere';
    }
  }));
}

function renderOverview(report) {
  const {raw}=report;
  const ns=answers(raw.ns,'NS').map(x=>x.data.replace(/\.$/,''));
  const a=answers(raw.a,'A').map(x=>x.data);
  const aaaa=answers(raw.aaaa,'AAAA').map(x=>x.data);
  const soa=answers(raw.soa,'SOA')[0]?.data || 'Ikke returnert';
  const rows=[
    ['IPv4',a.join(', ')||'Ingen'],
    ['IPv6',aaaa.join(', ')||'Ingen'],
    ['Navneservere',ns.length?`${ns.length} funnet`:'Ingen'],
    ['SOA',soa]
  ];
  $('dnsOverview').innerHTML=rows.map(([k,v])=>`<div><dt>${k}</dt><dd>${escapeHtml(v)}</dd></div>`).join('');
  const mx=report.checks.mx.parsed||[];
  $('mxList').innerHTML=mx.length ? mx.map(x=>`<div class="mini-item"><strong>${escapeHtml(x.host||'(null MX)')}</strong><span>Prioritet ${x.priority}</span></div>`).join('') : '<div class="empty-mini">Ingen MX-servere ble returnert.</div>';
}

function renderReport(report) {
  state.report=report;
  const {checks}=report;
  const score=scoreReport(checks);
  $('resultDomain').textContent=report.domain;
  $('scanTime').textContent=`Kontrollert ${new Date(report.scannedAt).toLocaleString('nb-NO')}`;
  $('scoreNumber').textContent=score;
  $('scoreLabel').textContent=scoreLabel(score);
  $('scoreRing').style.setProperty('--score',`${score*3.6}deg`);
  $('summaryGrid').innerHTML=['dnssec','mx','spf','dkim','dmarc'].map(k=>summaryCard(k,checks[k])).join('');
  renderFindings(checks);
  renderChecks(checks,report.domain);
  renderOverview(report);
  $('results').classList.remove('hidden');
  setTimeout(()=>$('results').scrollIntoView({behavior:'smooth',block:'start'}),50);
}

function setBusy(busy) {
  $('scanButton').disabled=busy;
  $('loading').classList.toggle('hidden',!busy);
}
function showError(message) {
  $('errorPanel').textContent=message;
  $('errorPanel').classList.remove('hidden');
}

$('scanForm').addEventListener('submit', async (e)=>{
  e.preventDefault();
  $('errorPanel').classList.add('hidden');
  $('results').classList.add('hidden');
  try {
    const domain=normalizeDomain($('domainInput').value);
    $('domainInput').value=domain;
    setBusy(true);
    const report=await runScan(domain,$('dkimSelector').value.trim(),$('scanCommonSelectors').checked);
    renderReport(report);
    const url=new URL(location.href);
    url.searchParams.set('domain',domain);
    history.replaceState({},'',url);
  } catch(err) {
    showError(err?.message || 'Kontrollen kunne ikke fullføres.');
  } finally {
    setBusy(false);
  }
});

$('expandAll').addEventListener('click',()=>{
  const items=[...document.querySelectorAll('.check-item')];
  const allOpen=items.every(i=>i.classList.contains('open'));
  items.forEach(i=>i.classList.toggle('open',!allOpen));
  $('expandAll').textContent=allOpen?'Vis alle':'Skjul alle';
});

$('exportJson').addEventListener('click',()=>{
  if(!state.report) return;
  const blob=new Blob([JSON.stringify(state.report,null,2)],{type:'application/json'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download=`${state.report.domain}-domainguard-rapport.json`;
  a.click();
  URL.revokeObjectURL(a.href);
});

const initial=new URLSearchParams(location.search).get('domain');
if(initial) $('domainInput').value=initial;

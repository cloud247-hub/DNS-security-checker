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
    throw new Error('Enter a valid domain such as example.com.');
  }
  return v;
}

async function dnsQuery(name, type, opts={}) {
  const params = new URLSearchParams({ name, type, do: opts.do === false ? 'false' : 'true' });
  if (opts.cd) params.set('cd','true');
  const res = await fetch(`${DOH_ENDPOINT}?${params.toString()}`, { headers: { 'accept':'application/dns-json' } });
  if (!res.ok) throw new Error(`DNS resolver returned HTTP ${res.status}`);
  return res.json();
}

function answers(r, typeName) {
  const type = TYPES[typeName];
  return (r?.Answer || []).filter(x => x.type === type);
}
function txtValues(r) {
  return answers(r,'TXT').map(x => String(x.data).replace(/^"|"$/g,'').replace(/"\s+"/g,''));
}
function firstTxtByPrefix(r, prefix) { return txtValues(r).find(v => v.toLowerCase().startsWith(prefix.toLowerCase())) || ''; }
function parseTagRecord(record) {
  const out = {};
  String(record || '').split(';').map(x => x.trim()).filter(Boolean).forEach(part => {
    const i = part.indexOf('=');
    if (i > -1) out[part.slice(0,i).trim().toLowerCase()] = part.slice(i+1).trim();
  });
  return out;
}
function status(severity, label, subtitle, detail='', records=[]) { return { severity, label, subtitle, detail, records }; }

function evaluateDnssec(ds, dnskey) {
  const dsRecords = answers(ds,'DS');
  const keys = answers(dnskey,'DNSKEY');
  if (dnskey.Status === 2) return status('bad','Validation failed','DNSSEC appears broken','The validating resolver returned SERVFAIL while requesting DNSKEY. This can indicate a broken DNSSEC chain.', []);
  if (keys.length && dnskey.AD) return status('good','Validated','DNSSEC is enabled','DNSKEY records were returned and authenticated by the resolver.', keys.map(x=>x.data));
  if (keys.length) return status('warn','Present, not validated','DNSKEY found','DNSKEY records exist, but this response was not authenticated by the resolver. Check the parent DS record and signing chain.', keys.map(x=>x.data));
  if (dsRecords.length) return status('bad','DS without DNSKEY','Possible DNSSEC error','A parent DS record exists but no DNSKEY was returned for the zone.', dsRecords.map(x=>x.data));
  return status('warn','Not enabled','No DNSSEC signing detected','No DNSKEY record was found for this domain.', []);
}
function evaluateMx(r) {
  const rows = answers(r,'MX').map(x => {
    const m = String(x.data).match(/^(\d+)\s+(.+)$/); return { priority:m?Number(m[1]):0, host:(m?m[2]:x.data).replace(/\.$/,'') };
  }).sort((a,b)=>a.priority-b.priority);
  if (!rows.length) return { ...status('bad','Missing','No MX records','No MX records were found. This domain may not be configured to receive email.'), parsed:[] };
  if (rows.length === 1 && rows[0].host === '') return { ...status('info','Null MX','Domain does not accept mail','The domain publishes a null MX record.'), parsed:rows };
  return { ...status('good','Configured',`${rows.length} mail server${rows.length===1?'':'s'}`,'Mail exchanger records are published.', rows.map(x=>`${x.priority} ${x.host}`)), parsed:rows };
}
function evaluateSpf(r) {
  const all = txtValues(r).filter(v=>/^v=spf1\b/i.test(v));
  if (!all.length) return status('bad','Missing','No SPF policy','Publish an SPF TXT record to declare which systems may send mail for the domain.');
  if (all.length > 1) return status('bad','Multiple records',`${all.length} SPF records found`,'SPF should normally have exactly one v=spf1 record; multiple records can cause PermError.', all);
  const rec = all[0];
  const lower = rec.toLowerCase();
  let sev='good', label='Configured', sub='SPF policy found';
  if (/\s\+all(?:\s|$)/i.test(rec)) { sev='bad'; label='Unsafe'; sub='+all allows any sender'; }
  else if (/\s~all(?:\s|$)/i.test(rec)) { sev='warn'; label='Softfail'; sub='SPF ends with ~all'; }
  else if (!/\s-all(?:\s|$)/i.test(rec)) { sev='warn'; label='Review'; sub='No hard-fail -all found'; }
  return status(sev,label,sub,'SPF controls which sending infrastructure is authorized for the domain.',[rec]);
}
function evaluateDmarc(r) {
  const rec = firstTxtByPrefix(r,'v=DMARC1');
  if (!rec) return status('bad','Missing','No DMARC policy','DMARC adds alignment and policy on top of SPF/DKIM and can provide aggregate reporting.');
  const tags = parseTagRecord(rec); const p=(tags.p||'').toLowerCase();
  if (p==='reject') return status('good','Reject','Strong DMARC enforcement','Messages that fail DMARC are requested to be rejected.',[rec]);
  if (p==='quarantine') return status('warn','Quarantine','Partial DMARC enforcement','Failing mail is requested to be quarantined. Consider moving toward reject when ready.',[rec]);
  if (p==='none') return status('warn','Monitoring','DMARC policy is p=none','DMARC is collecting visibility but does not request enforcement.',[rec]);
  return status('warn','Review','DMARC record needs review','A DMARC record exists but its policy could not be classified.',[rec]);
}
function evaluateDkim(results, selectors) {
  const found=[];
  results.forEach((r,i)=>{ const rec=firstTxtByPrefix(r,'v=DKIM1') || txtValues(r).find(v=>/\bp=/.test(v)); if(rec) found.push({selector:selectors[i],record:rec}); });
  if (!found.length) return { ...status('warn','Not discovered','No DKIM key found','DKIM selectors are not standardized. No key was found for the selectors checked; this does not prove the domain has no DKIM.'), found:[] };
  const revoked=found.filter(x=>/\bp=\s*(?:;|$)/i.test(x.record));
  if (revoked.length===found.length) return { ...status('warn','Revoked',`${found.length} selector${found.length===1?'':'s'} found`,'The discovered DKIM keys appear to have empty public keys.',found.map(x=>`${x.selector}: ${x.record}`)), found };
  return { ...status('good','Discovered',`${found.length} DKIM selector${found.length===1?'':'s'} found`,'At least one DKIM public key was found for the selectors checked.',found.map(x=>`${x.selector}: ${x.record}`)), found };
}
function evaluateMtaSts(r) {
  const rec=firstTxtByPrefix(r,'v=STSv1');
  return rec ? status('good','Published','MTA-STS DNS record found','The _mta-sts TXT record is present. This checker does not fetch the HTTPS policy file.',[rec]) : status('warn','Missing','No MTA-STS TXT record','MTA-STS can help sending servers require authenticated TLS for mail delivery.');
}
function evaluateTlsRpt(r) {
  const rec=firstTxtByPrefix(r,'v=TLSRPTv1');
  return rec ? status('good','Published','TLS-RPT reporting enabled','The domain advertises an SMTP TLS reporting destination.',[rec]) : status('warn','Missing','No TLS-RPT record','TLS-RPT can provide reports about TLS negotiation and policy failures.');
}
function evaluateCaa(r) {
  const rows=answers(r,'CAA').map(x=>x.data);
  return rows.length ? status('good','Restricted',`${rows.length} CAA record${rows.length===1?'':'s'}`,'CAA can restrict which certificate authorities may issue certificates for the domain.',rows) : status('info','Not set','No CAA records','Without CAA, certificate issuance is not restricted by a CAA policy at this name.');
}
function evaluateBimi(r) {
  const rec=firstTxtByPrefix(r,'v=BIMI1');
  return rec ? status('good','Published','BIMI record found','A BIMI TXT record was found at default._bimi.',[rec]) : status('info','Not found','No default BIMI record','BIMI is optional and commonly depends on strong DMARC enforcement.');
}

async function runScan(domain, customSelector, scanCommon) {
  $('loadingText').textContent='Querying core DNS records';
  const names = {
    apex: domain, dmarc:`_dmarc.${domain}`, mtasts:`_mta-sts.${domain}`, tlsrpt:`_smtp._tls.${domain}`, bimi:`default._bimi.${domain}`
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
  $('loadingText').textContent = selectors.length ? `Checking ${selectors.length} DKIM selector${selectors.length===1?'':'s'}` : 'Evaluating policies';
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
  let score=0; Object.entries(weights).forEach(([k,w])=>score+=w*(factor[checks[k].severity]??0));
  return Math.round(score);
}
function scoreLabel(score) { return score>=85?'Strong':score>=70?'Good':score>=50?'Needs work':'At risk'; }
function checkMeta(key) {
  return {
    dnssec:['DNSSEC','DNS integrity'], mx:['MX','Mail routing'], spf:['SPF','Sender authorization'], dkim:['DKIM','Cryptographic mail signing'], dmarc:['DMARC','Authentication policy'],
    mtasts:['MTA-STS','SMTP transport policy'], tlsrpt:['TLS-RPT','TLS failure reporting'], caa:['CAA','Certificate authority policy'], bimi:['BIMI','Brand indicators']
  }[key];
}
function summaryCard(key,check) {
  const [name]=checkMeta(key); return `<article class="summary-card"><div class="summary-top"><h4>${name}</h4><span class="status-icon ${check.severity}">${severityIcon[check.severity]}</span></div><div class="summary-value">${escapeHtml(check.label)}</div><p>${escapeHtml(check.subtitle)}</p></article>`;
}
function findingText(key,c) {
  if (c.severity==='good') return null;
  const map={
    dnssec:{bad:'DNSSEC validation is failing.',warn:'DNSSEC is not fully validated.',info:'Review DNSSEC status.'},
    mx:{bad:'Mail routing is not configured.',warn:'Review the MX configuration.',info:'This domain declares that it does not accept email.'},
    spf:{bad:'SPF is missing or invalid.',warn:'The SPF policy could be strengthened.',info:'Review SPF.'},
    dkim:{bad:'DKIM keys appear invalid.',warn:'No DKIM key was discovered with the selectors checked.',info:'Review DKIM.'},
    dmarc:{bad:'DMARC protection is missing.',warn:'DMARC exists but is not at full enforcement.',info:'Review DMARC.'},
    mtasts:{bad:'MTA-STS needs attention.',warn:'MTA-STS is not advertised.',info:'Review MTA-STS.'},
    tlsrpt:{bad:'TLS reporting needs attention.',warn:'SMTP TLS reporting is not enabled.',info:'Review TLS-RPT.'},
    caa:{bad:'CAA needs attention.',warn:'Review CAA.',info:'No CAA restriction is published.'},
    bimi:{bad:'BIMI needs attention.',warn:'Review BIMI.',info:'BIMI was not found; this is optional.'}
  };
  return map[key]?.[c.severity] || c.subtitle;
}
function renderFindings(checks) {
  const priority=['dnssec','dmarc','spf','dkim','mx','mtasts','tlsrpt','caa','bimi'];
  const items=priority.map(k=>({k,c:checks[k],text:findingText(k,checks[k])})).filter(x=>x.text).sort((a,b)=>severityRank[a.c.severity]-severityRank[b.c.severity]);
  const goodCore=['dnssec','mx','spf','dkim','dmarc'].filter(k=>checks[k].severity==='good');
  if (goodCore.length>=4) items.push({k:'mx',c:{severity:'good',subtitle:'Core controls look healthy.'},text:`${goodCore.length} of 5 core DNS/email controls passed.`});
  $('findingCount').textContent=items.length;
  $('findingsList').innerHTML=items.length?items.map(x=>`<div class="finding"><span class="finding-icon ${x.c.severity}">${severityIcon[x.c.severity]}</span><div><strong>${escapeHtml(x.text)}</strong><p>${escapeHtml(x.c.subtitle)}</p></div></div>`).join(''):'<div class="finding"><span class="finding-icon good">✓</span><div><strong>No notable issues found</strong><p>The checked controls all look healthy.</p></div></div>';
}
function renderChecks(checks) {
  const order=['dnssec','mx','spf','dkim','dmarc','mtasts','tlsrpt','caa','bimi'];
  $('checksList').innerHTML=order.map(k=>{ const c=checks[k], [name,desc]=checkMeta(k); const recs=(c.records||[]).map(r=>`<div class="record-box">${escapeHtml(r)}</div>`).join(''); return `<article class="check-item"><button class="check-toggle" type="button"><span class="status-icon ${c.severity}">${severityIcon[c.severity]}</span><span class="check-name"><strong>${name}</strong><span>${desc}</span></span><span class="check-status ${c.severity}">${escapeHtml(c.label)}</span><span class="chevron">⌄</span></button><div class="check-detail"><p>${escapeHtml(c.detail||c.subtitle)}</p>${recs || '<div class="record-box">No matching record returned.</div>'}</div></article>`; }).join('');
  document.querySelectorAll('.check-toggle').forEach(btn=>btn.addEventListener('click',()=>btn.parentElement.classList.toggle('open')));
}
function renderOverview(report) {
  const {raw}=report;
  const ns=answers(raw.ns,'NS').map(x=>x.data.replace(/\.$/,''));
  const a=answers(raw.a,'A').map(x=>x.data); const aaaa=answers(raw.aaaa,'AAAA').map(x=>x.data);
  const soa=answers(raw.soa,'SOA')[0]?.data || 'Not returned';
  const rows=[['IPv4',a.join(', ')||'None'],['IPv6',aaaa.join(', ')||'None'],['Name servers',ns.length?`${ns.length} found`:'None'],['SOA',soa]];
  $('dnsOverview').innerHTML=rows.map(([k,v])=>`<div><dt>${k}</dt><dd>${escapeHtml(v)}</dd></div>`).join('');
  const mx=report.checks.mx.parsed||[];
  $('mxList').innerHTML=mx.length?mx.map(x=>`<div class="mini-item"><strong>${escapeHtml(x.host||'(null MX)')}</strong><span>Priority ${x.priority}</span></div>`).join(''):'<div class="empty-mini">No MX servers returned.</div>';
}
function renderReport(report) {
  state.report=report; const {checks}=report; const score=scoreReport(checks);
  $('resultDomain').textContent=report.domain; $('scanTime').textContent=`Checked ${new Date(report.scannedAt).toLocaleString()}`;
  $('scoreNumber').textContent=score; $('scoreLabel').textContent=scoreLabel(score); $('scoreRing').style.setProperty('--score',`${score*3.6}deg`);
  $('summaryGrid').innerHTML=['dnssec','mx','spf','dkim','dmarc'].map(k=>summaryCard(k,checks[k])).join('');
  renderFindings(checks); renderChecks(checks); renderOverview(report);
  $('results').classList.remove('hidden');
  setTimeout(()=>$('results').scrollIntoView({behavior:'smooth',block:'start'}),50);
}
function setBusy(busy) { $('scanButton').disabled=busy; $('loading').classList.toggle('hidden',!busy); }
function showError(message) { $('errorPanel').textContent=message; $('errorPanel').classList.remove('hidden'); }

$('scanForm').addEventListener('submit', async (e)=>{
  e.preventDefault(); $('errorPanel').classList.add('hidden'); $('results').classList.add('hidden');
  try {
    const domain=normalizeDomain($('domainInput').value); $('domainInput').value=domain; setBusy(true);
    const report=await runScan(domain,$('dkimSelector').value.trim(),$('scanCommonSelectors').checked); renderReport(report);
    const url=new URL(location.href); url.searchParams.set('domain',domain); history.replaceState({},'',url);
  } catch(err) { showError(err?.message || 'The scan could not be completed.'); } finally { setBusy(false); }
});
$('expandAll').addEventListener('click',()=>{ const items=[...document.querySelectorAll('.check-item')]; const allOpen=items.every(i=>i.classList.contains('open')); items.forEach(i=>i.classList.toggle('open',!allOpen)); $('expandAll').textContent=allOpen?'Expand all':'Collapse all'; });
$('exportJson').addEventListener('click',()=>{ if(!state.report)return; const blob=new Blob([JSON.stringify(state.report,null,2)],{type:'application/json'}); const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=`${state.report.domain}-domain-security-report.json`; a.click(); URL.revokeObjectURL(a.href); });

const initial=new URLSearchParams(location.search).get('domain'); if(initial){ $('domainInput').value=initial; }

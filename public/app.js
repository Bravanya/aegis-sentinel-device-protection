/* Aegis Sentinel — portfolio SOC dashboard. All telemetry is locally simulated. */
const $ = (selector, scope = document) => scope.querySelector(selector);
const $$ = (selector, scope = document) => [...scope.querySelectorAll(selector)];
const clamp = (n, min, max) => Math.max(min, Math.min(max, n));
const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];
const random = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
const formatNumber = (n) => n.toLocaleString('en-US');

const APP = {
  activeView: 'overview',
  initialized: false,
  lastCorrelationToast: 0,
  eventSeverity: 'all',
  selectedIncident: null,
  commandIndex: 0,
  eventCount: 2840000000,
  threats: 48291,
  traffic: { ingest: [], anomaly: [], contained: [] },
  mapFlows: [],
};

const incidents = [
  { id:'INC-2048', severity:'critical', title:'Potential credential abuse against identity infrastructure', status:'Investigating', owner:'A. Perera', entity:'idp-prod-02', technique:'T1078', time:'4m ago', score:92, summary:'Multiple privileged authentication events followed by an unexpected session origin change.', evidence:[['Identity Provider','7 anomalous logins across 2 privileged accounts'],['VPN Gateway','Geovelocity deviation: 9,204 km in 11 minutes'],['EDR','No endpoint execution associated with activity']], actions:[['Contain sessions','Revoke associated IdP sessions'],['Force step-up MFA','Require reauthentication for affected identities'],['Start threat hunt','Search correlated activity across identity logs'],['Assign escalation','Notify identity security owner']] },
  { id:'INC-2046', severity:'critical', title:'Ransomware-like encryption behavior on finance workstation', status:'Containment', owner:'You', entity:'fin-ws-047', technique:'T1486', time:'18m ago', score:96, summary:'Behavior analytics detected rapid document modification and suspicious recovery inhibition commands.', evidence:[['EDR','1,821 file rename events in 73 seconds'],['Network','Outbound connection blocked by egress policy'],['Backup Service','Host snapshot captured before isolation']], actions:[['Keep isolated','Maintain endpoint quarantine'],['Collect package','Acquire triage bundle'],['Block indicator','Add derived hashes to prevent list'],['Open recovery task','Validate user data recovery']] },
  { id:'INC-2041', severity:'high', title:'Cloud access key used from atypical network', status:'Triage', owner:'S. Kumar', entity:'aws-prod-billing', technique:'T1528', time:'31m ago', score:81, summary:'A production cloud credential was observed from a new ASN and outside its established access window.', evidence:[['CloudTrail','API key used to enumerate billing configuration'],['Identity Baseline','First use of this ASN'],['Threat Intel','ASN has elevated proxy reputation']], actions:[['Rotate key','Disable and rotate access key'],['Review policy','Inspect IAM privilege changes'],['Search account','Pivot on related API activity'],['Contact owner','Verify business justification']] },
  { id:'INC-2038', severity:'high', title:'Suspicious PowerShell encoded command', status:'Investigating', owner:'M. Silva', entity:'eng-lt-112', technique:'T1059.001', time:'47m ago', score:78, summary:'Endpoint telemetry captured a highly obfuscated command line spawned from an office process.', evidence:[['EDR','Encoded command launch prevented'],['Email Security','Document was delivered from a newly registered domain'],['Sandbox','No execution outside controlled environment']], actions:[['Isolate device','Place endpoint in network isolation'],['Search hash','Check prevalence across estate'],['Block domain','Add delivery domain to mail controls'],['Notify user','Request confirmation of email intent']] },
  { id:'INC-2031', severity:'medium', title:'External scan targeting remote access gateway', status:'Monitoring', owner:'Unassigned', entity:'vpn-gw-01', technique:'T1595', time:'1h ago', score:62, summary:'Repeated probe sequence against public-facing gateway endpoints was rate-limited.', evidence:[['Firewall','842 blocked requests from 3 source ranges'],['WAF','No successful exploit signatures'],['Threat Intel','Sources match commodity scanning infrastructure']], actions:[['Tighten WAF','Enable temporary challenge policy'],['Add watchlist','Track source infrastructure'],['Review logs','Check any successful authentication'],['Close case','Document baseline activity']] },
  { id:'INC-2022', severity:'medium', title:'Data staging anomaly on shared storage', status:'Triage', owner:'N. Fernando', entity:'files-prod-01', technique:'T1074', time:'2h ago', score:55, summary:'An unusual archive creation pattern was detected in a folder with sensitive engineering files.', evidence:[['File Analytics','Large archive created by service account'],['Identity','Service account has valid scheduled workflow'],['Network','No suspicious outbound transfer seen']], actions:[['Validate job','Confirm with application owner'],['Watch location','Enable focused monitoring'],['Review history','Compare prior workflow behavior'],['Close case','Mark as expected activity']] },
];

const liveEvents = [
  { severity:'critical', detection:'Privilege escalation chain', entity:'idp-prod-02', mitre:'T1078 · Valid Accounts', time:'just now', incident:'INC-2048' },
  { severity:'high', detection:'Suspicious cloud API enumeration', entity:'aws-prod-billing', mitre:'T1528 · Cloud Accounts', time:'1m ago', incident:'INC-2041' },
  { severity:'critical', detection:'Rapid file encryption behavior', entity:'fin-ws-047', mitre:'T1486 · Data Encrypted', time:'2m ago', incident:'INC-2046' },
  { severity:'high', detection:'Encoded PowerShell execution', entity:'eng-lt-112', mitre:'T1059.001 · PowerShell', time:'4m ago', incident:'INC-2038' },
  { severity:'medium', detection:'Internet-facing service scan', entity:'vpn-gw-01', mitre:'T1595 · Active Scanning', time:'7m ago', incident:'INC-2031' },
  { severity:'low', detection:'New SaaS OAuth consent', entity:'mktg-tenant', mitre:'T1528 · Cloud Accounts', time:'9m ago', incident:'INC-2022' },
];

const riskData = [
  ['Identity abuse', 92, 'critical'],
  ['Cloud control plane', 76, 'high'],
  ['Ransomware activity', 61, 'high'],
  ['Public attack surface', 38, 'medium'],
];

const intelligence = [
  { source:'AEGIS FUSION', time:'12m ago', title:'Identity-focused intrusion set shifts to session token replay', description:'Recent tradecraft emphasizes valid session reuse after phishing and trusted device registration.', label:'HIGH CONFIDENCE', color:'orange' },
  { source:'COMMUNITY FEED', time:'36m ago', title:'New commodity loader targets browser credential stores', description:'Observed delivery uses signed archive files and benign-looking invoice templates.', label:'MONITOR', color:'purple' },
  { source:'CLOUD WATCH', time:'1h ago', title:'Misconfigured object storage exposures trending lower', description:'Current surface scan shows a 14% week-over-week reduction in publicly accessible resources.', label:'POSTURE', color:'green' },
  { source:'MALWARE RESEARCH', time:'2h ago', title:'Ransomware affiliates reuse remote tooling before deployment', description:'Early indicators include remote management session bursts and backup service tampering.', label:'ACTIONABLE', color:'red' },
];

const assets = [
  ['idp-prod-02','Identity Platform','Tier 1','High','2m ago','Protected'],
  ['aws-prod-billing','Cloud FinOps','Tier 1','Medium','4m ago','Watch'],
  ['fin-ws-047','Finance','Tier 2','High','6m ago','Isolated'],
  ['vpn-gw-01','Infrastructure','Tier 1','Medium','1m ago','Protected'],
  ['files-prod-01','Engineering','Tier 2','Low','3m ago','Protected'],
  ['k8s-core-01','Platform Team','Tier 1','Low','2m ago','Protected'],
  ['crm-app-03','Revenue Ops','Tier 2','Medium','9m ago','Watch'],
  ['mail-sec-01','Security','Tier 1','Low','1m ago','Protected'],
];

const playbooks = [
  ['Credential abuse containment','Revoke sessions, require MFA, pivot on identity activity','⌁'],
  ['Ransomware endpoint isolation','Quarantine host, preserve evidence, block derived IOCs','⬡'],
  ['Suspicious cloud key activity','Disable key, inspect policy changes, verify owner','☁'],
  ['Phishing delivery response','Block sender, remove messages, search similar campaigns','✉'],
  ['Data exfiltration investigation','Validate destination, isolate transfer, preserve telemetry','⇄'],
  ['Public exposure remediation','Restrict service, open owner task, re-scan asset','◫'],
];


const AUTH = { currentUser: null };
const DEVICE = { base:'http://127.0.0.1:43821', token:sessionStorage.getItem('aegis_device_agent_token') || '', connected:false, status:null };

async function requestJSON(path, options = {}) {
  const response = await fetch(path, {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || 'The server could not complete that request.');
  return data;
}

function normaliseEmail(email) { return String(email || '').trim().toLowerCase(); }
function userInitials(name) {
  return String(name || 'Aegis User').split(/\s+/).filter(Boolean).slice(0,2).map(part => part[0]).join('').toUpperCase() || 'AU';
}

function init() {
  if (APP.initialized) return;
  APP.initialized = true;
  updateClock(); setInterval(updateClock, 1000);
  renderRisk(); renderEvents(); renderControls(); renderMitre(); renderEndpoints(); renderCases(); renderBrief(); renderIncidents(); renderDetectionLab(); renderIntel(); renderAssets(); renderPlaybooks();
  setupNavigation(); setupButtons(); setupTerminal(); setupCommandPalette(); setupCanvas(); animateCounters(); setupProfileMenu(); setupContact(); setupDeviceProtection();
  connectRealtime();
}

document.addEventListener('DOMContentLoaded', bootApplication);

async function bootApplication() {
  setupAuthentication();
  try {
    const result = await requestJSON('/api/auth/me');
    if (result.user) enterWorkspace(result.user, false);
    else showAuthGate('signin');
  } catch {
    showAuthGate('signin');
    setAuthMessage('Server connection could not be verified. Start the Node server, then refresh this page.');
  }
}

function setAuthMessage(message='', type='') {
  const notice = $('#authNotice');
  if (!notice) return;
  notice.textContent = message;
  notice.className = `auth-notice${message ? ' show' : ''}${type ? ` ${type}` : ''}`;
}
function setAuthView(view) {
  const copy = {
    signin: ['WELCOME BACK', 'Sign in to Aegis Sentinel', 'Use your secure Aegis Sentinel account to continue.'],
    signup: ['CREATE YOUR WORKSPACE', 'Start your analyst journey', 'Create a server-backed account and receive full simulator access.'],
  };
  const [kicker, title, subtitle] = copy[view] || copy.signin;
  $('#authKicker').textContent = kicker; $('#authTitle').textContent = title; $('#authSubtitle').textContent = subtitle;
  $$('.auth-form').forEach(form => form.classList.toggle('auth-form-active', form.id === `${view === 'signup' ? 'signUp' : 'signIn'}Form`));
  setAuthMessage('');
  const focusId = view === 'signup' ? 'signUpName' : 'signInEmail';
  setTimeout(() => $('#'+focusId)?.focus(), 50);
}
function showAuthGate(view='signin') {
  document.body.classList.add('auth-active');
  document.body.classList.remove('app-ready');
  closeProfileMenu();
  setAuthView(view);
}
function enterWorkspace(user, notify=true) {
  AUTH.currentUser = user;
  document.body.classList.remove('auth-active');
  document.body.classList.add('app-ready');
  updateProfileUI();
  init();
  requestAnimationFrame(() => { resizeCanvases(); });
  if (notify) setTimeout(() => toast('Workspace ready', `Welcome, ${user.name}. You have full simulator access.`, 'success'), 250);
}
function updateProfileUI() {
  const user = AUTH.currentUser || { name:'Aegis Analyst', email:'analyst@aegis.local', role:'SOC Analyst' };
  const initials = userInitials(user.name);
  $('#userAvatar').textContent = initials; $('#menuAvatar').textContent = initials;
  $('#profileName').textContent = String(user.name).split(/\s+/)[0].toUpperCase();
  $('#menuName').textContent = user.name; $('#menuEmail').textContent = user.email;
  $('#menuRole').textContent = `${String(user.role || 'SOC Analyst').toUpperCase()} · FULL TRAINING ACCESS`;
}
function setBusy(button, busy, text) {
  if (!button) return;
  if (!button.dataset.originalText) button.dataset.originalText = button.textContent;
  button.disabled = busy;
  button.textContent = busy ? text : button.dataset.originalText;
}
function setupAuthentication() {
  $$('[data-auth-view]').forEach(button => button.addEventListener('click', () => setAuthView(button.dataset.authView)));
  $$('[data-password-toggle]').forEach(button => button.addEventListener('click', () => {
    const input = $('#'+button.dataset.passwordToggle); if (!input) return;
    input.type = input.type === 'password' ? 'text' : 'password';
    button.textContent = input.type === 'password' ? '◉' : '◌';
    button.setAttribute('aria-label', input.type === 'password' ? 'Show password' : 'Hide password');
  }));
  $('#demoSignIn').addEventListener('click', async () => {
    const button = $('#demoSignIn');
    setBusy(button, true, 'Opening demo workspace…');
    try {
      const result = await requestJSON('/api/auth/demo-login', { method:'POST', body:'{}' });
      enterWorkspace(result.user);
    } catch (error) { setAuthMessage(error.message); }
    finally { setBusy(button, false); }
  });
  $('#signInForm').addEventListener('submit', async event => {
    event.preventDefault();
    const button = $('button[type="submit"]', $('#signInForm'));
    const email = normaliseEmail($('#signInEmail').value);
    const password = $('#signInPassword').value;
    if (!email || !password) { setAuthMessage('Enter both your email address and password.'); return; }
    setBusy(button, true, 'Signing in…');
    try {
      const result = await requestJSON('/api/auth/login', { method:'POST', body:JSON.stringify({ email, password }) });
      enterWorkspace(result.user);
    } catch (error) { setAuthMessage(error.message); }
    finally { setBusy(button, false); }
  });
  $('#signUpForm').addEventListener('submit', async event => {
    event.preventDefault();
    const button = $('button[type="submit"]', $('#signUpForm'));
    const name = $('#signUpName').value.trim();
    const email = normaliseEmail($('#signUpEmail').value);
    const role = $('#signUpRole').value;
    const password = $('#signUpPassword').value;
    const confirm = $('#signUpConfirm').value;
    if (name.length < 2) { setAuthMessage('Enter your full name to create the account.'); return; }
    if (!/^\S+@\S+\.\S+$/.test(email)) { setAuthMessage('Enter a valid email address.'); return; }
    if (password.length < 8) { setAuthMessage('Your password must contain at least 8 characters.'); return; }
    if (password !== confirm) { setAuthMessage('Your passwords do not match.'); return; }
    if (!$('#signUpConsent').checked) { setAuthMessage('Please confirm that you understand this is a simulated training platform.'); return; }
    setBusy(button, true, 'Creating account…');
    try {
      const result = await requestJSON('/api/auth/register', { method:'POST', body:JSON.stringify({ name, email, role, password }) });
      enterWorkspace(result.user);
    } catch (error) { setAuthMessage(error.message); }
    finally { setBusy(button, false); }
  });
}
function setupProfileMenu() {
  $('#profileButton').addEventListener('click', event => { event.stopPropagation(); toggleProfileMenu(); });
  $('#profileMenu').addEventListener('click', event => event.stopPropagation());
  document.addEventListener('click', closeProfileMenu);
  $('#logoutButton').addEventListener('click', async () => {
    try { await requestJSON('/api/auth/logout', { method:'POST', body:'{}' }); } catch { /* Session will still be cleared client-side. */ }
    if (APP.eventSource) { APP.eventSource.close(); APP.eventSource = null; }
    AUTH.currentUser = null;
    showAuthGate('signin');
    setAuthMessage('You have been signed out securely.', 'success');
  });
  $('#workspaceGuide').addEventListener('click', openWorkspaceGuide);
}
function toggleProfileMenu() { const menu=$('#profileMenu'); const open=!menu.classList.contains('open'); menu.classList.toggle('open', open); menu.setAttribute('aria-hidden', String(!open)); $('#profileButton').setAttribute('aria-expanded', String(open)); }
function closeProfileMenu() { const menu=$('#profileMenu'); if (!menu) return; menu.classList.remove('open'); menu.setAttribute('aria-hidden', 'true'); $('#profileButton')?.setAttribute('aria-expanded', 'false'); }
function openWorkspaceGuide() {
  closeProfileMenu();
  $('#modalContent').innerHTML = `<div class="modal-content"><p class="panel-kicker">START HERE</p><h2>Workspace guide</h2><p>Every alert is simulated, while your account, messages, session, and real-time browser updates are handled by this server.</p><div class="evidence-list" style="margin-top:18px"><div class="evidence-row"><span>1 · Overview</span><span>Watch live server-sent telemetry and open a priority case.</span></div><div class="evidence-row"><span>2 · Incidents</span><span>Review evidence, assign cases, and simulate a response.</span></div><div class="evidence-row"><span>3 · Detection Lab</span><span>Test an analytic and inspect data-source health.</span></div><div class="evidence-row"><span>4 · Contact</span><span>Use the built-in message form or LinkedIn link.</span></div></div><button class="button primary" style="margin-top:18px" id="guideClose">Start exploring →</button></div>`;
  $('#modalLayer').classList.add('open'); $('#modalLayer').setAttribute('aria-hidden','false');
  $('#guideClose').addEventListener('click', closeModal);
}

function applyTelemetry(metrics) {
  if (!metrics) return;
  APP.threats = metrics.threatsDisrupted ?? APP.threats;
  if ($('#metricEvents')) $('#metricEvents').textContent = `${((metrics.eventsProcessed || APP.eventCount) / 1_000_000_000).toFixed(2)}B`;
  if ($('#metricIncidents')) $('#metricIncidents').textContent = metrics.activeIncidents ?? incidents.length;
  if ($('#metricThreats')) $('#metricThreats').textContent = formatNumber(APP.threats);
  if ($('#metricAssets')) $('#metricAssets').textContent = metrics.protectedAssets ?? 243;
  if ($('#metricExposure')) $('#metricExposure').textContent = metrics.exposureScore ?? 34;
  if ($('#mapAttackCount')) $('#mapAttackCount').textContent = formatNumber(metrics.blockedFlows ?? 4821);
  if ($('#trafficRate')) $('#trafficRate').textContent = `${Number(metrics.ingestRate || 128400).toLocaleString('en-US')} /s`;
  const risk = metrics.riskScore || 72;
  if ($('#riskScore')) $('#riskScore').textContent = risk;
  if ($('#gaugeProgress')) $('#gaugeProgress').style.strokeDashoffset = String(188.5 - (188.5 * risk / 100));
}
function connectRealtime() {
  if (APP.eventSource) return;
  const source = new EventSource('/api/telemetry/stream', { withCredentials:true });
  APP.eventSource = source;
  source.addEventListener('open', () => {
    const node = $('#realtimeStatus');
    if (node) {
      node.classList.remove('realtime-offline');
      node.classList.add('realtime-online');
      node.innerHTML = '<span class="pulse"></span> LIVE TELEMETRY CONNECTED';
    }
  });
  source.addEventListener('error', () => {
    const node = $('#realtimeStatus');
    if (node) {
      node.classList.remove('realtime-online');
      node.classList.add('realtime-offline');
      node.innerHTML = '<span class="pulse"></span> TELEMETRY RECONNECTING';
    }
  });
  source.addEventListener('telemetry:bootstrap', event => {
    const payload = JSON.parse(event.data);
    applyTelemetry(payload.metrics);
    if (Array.isArray(payload.events)) {
      payload.events.slice().reverse().forEach(entry => liveEvents.unshift(entry));
      liveEvents.splice(8);
      renderEvents();
    }
  });
  source.addEventListener('telemetry:metrics', event => applyTelemetry(JSON.parse(event.data)));
  source.addEventListener('telemetry:event', event => {
    const entry = JSON.parse(event.data);
    liveEvents.unshift(entry);
    liveEvents.splice(8);
    renderEvents();
    if ($('#latestCorrelation')) $('#latestCorrelation').textContent = entry.detection;
    appendTerminal('', `[LIVE] ${escapeHTML(entry.severity.toUpperCase())} telemetry: <span class="cmd">${escapeHTML(entry.detection)}</span> → ${escapeHTML(entry.entity)}`);
  });
  source.addEventListener('simulation:action', event => {
    const entry = JSON.parse(event.data);
    appendTerminal('good', `[ACTION] ${escapeHTML(entry.actor)} ran ${escapeHTML(entry.type)} in the safe simulator.`);
  });
}

async function logSimulation(type, details={}) {
  try { await requestJSON('/api/simulations/action', { method:'POST', body:JSON.stringify({ type, details }) }); } catch { /* Local UI remains usable if audit logging is temporarily unavailable. */ }
}
async function setupContact() {
  const form = $('#contactForm');
  if (!form) return;
  try {
    const config = await requestJSON('/api/public/config');
    $('#contactOwner').textContent = config.ownerName || 'Project owner';
    $('#contactEmailText').textContent = config.contactEmail || 'owner@example.com';
    $('#contactEmailLink').href = `mailto:${config.contactEmail || 'owner@example.com'}`;
    const phoneOne = config.contactPhonePrimary || '';
    const phoneTwo = config.contactPhoneSecondary || '';
    $('#contactPhonePrimaryText').textContent = phoneOne || 'Phone not configured';
    $('#contactPhonePrimaryLink').href = phoneOne ? `tel:${phoneOne.replace(/\s+/g,'')}` : '#';
    $('#contactPhoneSecondaryText').textContent = phoneTwo || 'Alternate phone not configured';
    $('#contactPhoneSecondaryLink').href = phoneTwo ? `tel:${phoneTwo.replace(/\s+/g,'')}` : '#';
    const linkedin = config.linkedinUrl || 'https://www.linkedin.com/';
    $('#contactLinkedinLink').href = linkedin; $('#linkedinButton').href = linkedin;
    $('#contactLinkedinText').textContent = config.linkedinLabel || 'Open professional profile';
    $('#contactDeliveryStatus').textContent = config.emailDeliveryConfigured
      ? 'Gmail delivery is configured. A submitted message is saved in the project database and a copy is sent to the owner inbox.'
      : 'Messages are saved in the project database. Add a Gmail App Password in .env to receive a copy in the owner inbox.';
  } catch { $('#contactFormNote').textContent = 'Contact configuration will appear when the server connection is available.'; }
  $('#contactName').value = AUTH.currentUser?.name || '';
  $('#contactEmail').value = AUTH.currentUser?.email || '';
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const button = $('#contactSubmit');
    const name = $('#contactName').value.trim(); const email = normaliseEmail($('#contactEmail').value);
    const subject = $('#contactSubject').value.trim(); const message = $('#contactMessage').value.trim();
    if (!name || !email || !subject || !message) { toast('Message incomplete', 'Please complete all contact fields.', 'warning'); return; }
    setBusy(button, true, 'Sending message…');
    try {
      const result = await requestJSON('/api/contact', { method:'POST', body:JSON.stringify({ name, email, subject, message }) });
      $('#contactSubject').value = ''; $('#contactMessage').value = '';
      const delivered = Boolean(result.emailDelivery?.delivered);
      $('#contactFormNote').textContent = delivered
        ? 'Message saved and delivered to the owner Gmail inbox.'
        : 'Message saved in the project database. Gmail delivery is not configured or could not be completed.';
      toast('Message received', delivered ? 'Your message was delivered to the owner inbox.' : 'Your message was saved for the project owner.', 'success');
    } catch (error) { toast('Message not sent', error.message, 'warning'); }
    finally { setBusy(button, false); }
  });
}

function localAgentHeaders() {
  return DEVICE.token ? { Authorization:`Bearer ${DEVICE.token}` } : {};
}
async function agentRequest(path, options = {}) {
  const response = await fetch(`${DEVICE.base}${path}`, {
    method: options.method || 'GET',
    headers: { 'Content-Type':'application/json', ...localAgentHeaders(), ...(options.headers || {}) },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || 'Local agent request failed.');
  return payload;
}
function updateAgentUI(online, detail='') {
  DEVICE.connected = online;
  const chip = $('#agentStatusChip'); const label = $('#agentConnectionLabel');
  chip.classList.toggle('online', online); chip.textContent = online ? '● AGENT CONNECTED' : '● AGENT OFFLINE';
  label.classList.toggle('green', online); label.innerHTML = `<i></i> ${online ? 'CONNECTED' : 'NOT CONNECTED'}`;
  if (!online && detail) $('#deviceStatusBody').innerHTML = `<div class="device-empty"><div>◌</div><strong>Agent unavailable</strong><p>${escapeHTML(detail)}</p></div>`;
}
function safeDate(value) {
  if (!value) return 'Not available';
  const date = new Date(value); return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}
function renderDeviceStatus(payload) {
  const status = payload?.defender || {};
  const field = (value, yes='Enabled', no='Disabled') => value ? `<strong class="good">${yes}</strong>` : `<strong class="warn">${no}</strong>`;
  $('#deviceStatusBody').innerHTML = `<div class="device-state-grid">
    <div class="device-state"><span>ANTIVIRUS</span>${field(status.antivirusEnabled)}</div>
    <div class="device-state"><span>REAL-TIME PROTECTION</span>${field(status.realTimeProtectionEnabled)}</div>
    <div class="device-state"><span>AGENT PERMISSION</span><strong class="${payload.elevated ? 'good' : 'warn'}">${payload.elevated ? 'Administrator' : 'Standard user'}</strong></div>
    <div class="device-state"><span>DEFINITIONS</span><strong>${escapeHTML(status.signatureVersion || 'Unknown')}</strong></div>
    <div class="device-state"><span>LAST QUICK SCAN</span><strong>${escapeHTML(safeDate(status.quickScanEndTime))}</strong></div>
    <div class="device-state"><span>LAST FULL SCAN</span><strong>${escapeHTML(safeDate(status.fullScanEndTime))}</strong></div>
  </div><div class="device-detection-summary"><b>DEFENDER DETECTIONS</b><br>${payload.detections?.length ? `${payload.detections.length} recent detection record(s) available in Windows Defender.` : 'No recent detection records returned by the local agent.'}</div>`;
  $('#firewallLabel').classList.toggle('green', Boolean(payload.elevated));
  $('#firewallLabel').innerHTML = `<i></i> ${payload.elevated ? 'ADMIN READY' : 'ADMIN REQUIRED'}`;
  renderBlocks(payload.blocks || []);
}
function renderBlocks(blocks) {
  const list = $('#blockList');
  const ips = [...new Set((blocks || []).map(item => String(item.DisplayName || '').match(/Block IP (.+?) \(/)?.[1]).filter(Boolean))];
  list.innerHTML = ips.length ? ips.map(ip => `<div class="block-row"><strong>${escapeHTML(ip)}</strong><button type="button" data-unblock-ip="${escapeHTML(ip)}">Remove block</button></div>`).join('') : '<p>No Aegis Sentinel firewall block rules are currently loaded.</p>';
  $$('[data-unblock-ip]').forEach(button => button.addEventListener('click', async () => {
    try {
      const result = await agentRequest('/firewall/unblock', { method:'POST', body:{ ip:button.dataset.unblockIp } });
      renderBlocks(result.blocks || []); toast('Firewall rule removed', `${button.dataset.unblockIp} is no longer blocked by Aegis Sentinel.`, 'success');
    } catch (error) { toast('Could not remove block', error.message, 'warning'); }
  }));
}
async function refreshDeviceStatus(showMessage=true) {
  if (!DEVICE.token) { updateAgentUI(false, 'Paste the local token from agent-config.json, then connect this PC.'); return; }
  try {
    const payload = await agentRequest('/status'); DEVICE.status = payload; updateAgentUI(true); renderDeviceStatus(payload);
    if (showMessage) toast('Device status refreshed', 'Microsoft Defender and Aegis firewall status were read from this PC.', 'success');
  } catch (error) { updateAgentUI(false, error.message); if (showMessage) toast('Local agent unavailable', error.message, 'warning'); }
}
async function setupDeviceProtection() {
  const tokenInput = $('#agentTokenInput'); if (!tokenInput) return;
  tokenInput.value = DEVICE.token;
  $('#connectAgent').addEventListener('click', async () => {
    const token = tokenInput.value.trim();
    if (token.length < 20) { toast('Token required', 'Copy the complete token value from agent-config.json.', 'warning'); return; }
    DEVICE.token = token; sessionStorage.setItem('aegis_device_agent_token', token);
    try {
      const health = await agentRequest('/health');
      toast('Local agent connected', `Agent online on this PC. Administrator: ${health.elevated ? 'yes' : 'no'}.`, 'success');
      await refreshDeviceStatus(false);
    } catch (error) { updateAgentUI(false, error.message); toast('Could not connect', error.message, 'warning'); }
  });
  $('#forgetAgent').addEventListener('click', () => { DEVICE.token=''; DEVICE.status=null; sessionStorage.removeItem('aegis_device_agent_token'); tokenInput.value=''; updateAgentUI(false, 'Token removed from this browser session.'); toast('Local token removed', 'Reconnect by pasting the token again.', 'success'); });
  $('#refreshDevice').addEventListener('click', () => refreshDeviceStatus(true));
  const startScan = (kind, title) => async () => {
    try { const result = await agentRequest(`/scan/${kind}`, { method:'POST', body:{} }); toast(title, result.message, 'success'); setTimeout(() => refreshDeviceStatus(false), 2500); }
    catch (error) { toast('Scan was not launched', error.message, 'warning'); }
  };
  $('#quickScan').addEventListener('click', startScan('quick', 'Quick scan launched'));
  $('#fullScan').addEventListener('click', startScan('full', 'Full scan launched'));
  $('#blockIp').addEventListener('click', async () => {
    const input = $('#blockIpInput'); const ip = input.value.trim();
    if (!ip) { toast('IP address required', 'Enter a confirmed malicious IPv4 or IPv6 address from your own authorized logs.', 'warning'); return; }
    try { const result = await agentRequest('/firewall/block', { method:'POST', body:{ ip } }); renderBlocks(result.blocks || []); input.value=''; toast('Firewall block created', `${result.ip} was blocked inbound and outbound on this PC.`, 'danger'); }
    catch (error) { toast('Block was not created', error.message, 'warning'); }
  });
  $('#deviceGuide').addEventListener('click', () => {
    $('#modalContent').innerHTML = `<div class="modal-content"><p class="panel-kicker">DEVICE PROTECTION GUIDE</p><h2>How the local agent works</h2><p>The browser cannot directly scan or firewall-control a laptop. The optional local agent runs only on your own Windows PC at <code>127.0.0.1</code>.</p><div class="evidence-list" style="margin-top:18px"><div class="evidence-row"><span>1 · Start agent</span><span>Run <code>node .\\aegis-device-agent.js</code> from the project agent folder.</span></div><div class="evidence-row"><span>2 · Copy token</span><span>Copy the generated token from <code>agent-config.json</code and paste it in this page.</span></div><div class="evidence-row"><span>3 · Defender scans</span><span>Use Quick scan or Full scan to launch Microsoft Defender locally.</span></div><div class="evidence-row"><span>4 · Firewall IP rule</span><span>Run the agent as Administrator, then block only an IP confirmed from your own authorized security logs.</span></div></div><button class="button primary" style="margin-top:18px" id="deviceGuideClose">Understood →</button></div>`;
    $('#modalLayer').classList.add('open'); $('#modalLayer').setAttribute('aria-hidden','false'); $('#deviceGuideClose').addEventListener('click', closeModal);
  });
}

function updateClock() {
  const date = new Date();
  const output = date.toLocaleTimeString('en-GB', { timeZone:'UTC', hour12:false });
  $('#utcClock').textContent = output;
}

function renderRisk() {
  $('#riskList').innerHTML = riskData.map(([name,value,level]) => `<div class="risk-row"><span>${name}</span><strong>${value}%</strong><div class="risk-bar"><i style="width:${value}%; background:${level === 'critical' ? 'linear-gradient(90deg,#ff8b4b,#ff5470)' : level === 'high' ? 'linear-gradient(90deg,#ffd166,#ff8b4b)' : 'linear-gradient(90deg,#25d4ff,#5b8cff)'}"></i></div></div>`).join('');
}

function renderEvents() {
  const rows = APP.eventSeverity === 'all' ? liveEvents : liveEvents.filter(e => e.severity === APP.eventSeverity);
  $('#eventTable').innerHTML = rows.map(e => `<tr><td><span class="severity ${e.severity}">${e.severity.toUpperCase()}</span></td><td><a href="#incidents" class="event-link event-open" data-incident="${e.incident}">${e.detection}</a></td><td><span class="event-entity">${e.entity}</span></td><td><span class="mitre-tag">${e.mitre}</span></td><td><span class="time-cell">${e.time}</span></td><td><button class="row-action event-open" data-incident="${e.incident}" aria-label="Open incident">→</button></td></tr>`).join('');
  $$('.event-open').forEach(el => el.addEventListener('click', () => openIncident(el.dataset.incident, true)));
}

function renderControls() {
  const controls = [['Endpoint coverage',94],['Identity telemetry',100],['Cloud visibility',86],['Network analytics',78]];
  $('#controlBars').innerHTML = controls.map(([name, val]) => `<div class="control-row"><span>${name}</span><div class="control-track"><i style="width:${val}%; background:${val < 80 ? 'var(--yellow)' : val < 90 ? 'var(--cyan)' : 'var(--green)'}"></i></div><b>${val}%</b></div>`).join('');
}

function renderMitre() {
  const active = new Set([3, 7, 12, 16, 23, 29]); const observed = new Set([2, 4, 9, 17, 22, 28, 32]);
  $('#mitreMatrix').innerHTML = Array.from({ length:35 }, (_, i) => `<div class="matrix-node ${active.has(i) ? 'hot' : observed.has(i) ? 'warm' : i % 3 !== 0 ? 'cool' : ''}" title="ATT&CK coverage node ${i+1}"></div>`).join('');
}

function renderEndpoints() {
  const nodes = Array.from({ length:63 }, (_, index) => {
    const state = index === 12 || index === 51 ? 'isolated' : index === 23 || index === 44 ? 'watch' : 'healthy';
    return `<div class="endpoint ${state}" data-label="EDR-${String(index+1).padStart(3,'0')} · ${state.toUpperCase()}"></div>`;
  });
  $('#endpointGrid').innerHTML = nodes.join('');
}

function renderCases() {
  $('#caseList').innerHTML = incidents.slice(0, 5).map(item => `<article class="case-row" data-incident="${item.id}"><i class="case-severity ${item.severity}"></i><div><strong>${item.title}</strong><p>${item.id} · ${item.entity} · ${item.status}</p></div><time>${item.time}</time></article>`).join('');
  $$('.case-row').forEach(el => el.addEventListener('click', () => openIncident(el.dataset.incident, true)));
}

function renderBrief() {
  $('#intelBrief').innerHTML = intelligence.slice(0,3).map(item => `<article class="brief-item"><div class="brief-meta"><span>${item.source}</span><time>${item.time}</time></div><strong>${item.title}</strong><p>${item.description}</p></article>`).join('');
}

function renderIncidents(filter='open') {
  const query = ($('#incidentSearch')?.value || '').trim().toLowerCase();
  const source = filter === 'closed' ? [] : incidents;
  const list = source.filter(item => `${item.id} ${item.title} ${item.entity} ${item.technique}`.toLowerCase().includes(query));
  $('#incidentList').innerHTML = list.length ? list.map(item => `<article class="incident-card ${item.severity} ${APP.selectedIncident === item.id ? 'selected' : ''}" data-incident="${item.id}"><i class="incident-band"></i><div><h3>${item.title}</h3><p>${item.id} · ${item.entity} · ${item.status}</p><div class="incident-tags"><span class="tag">${item.technique}</span><span class="tag">Confidence ${item.score}%</span><span class="tag">${item.owner}</span></div></div><div class="incident-side"><span>${item.severity.toUpperCase()}</span>${item.time}</div></article>`).join('') : `<div class="empty-state" style="min-height:250px"><div class="empty-graphic">✓</div><h2>No cases found</h2><p>Your selected queue has no matching cases.</p></div>`;
  $$('.incident-card').forEach(el => el.addEventListener('click', () => selectIncident(el.dataset.incident)));
}

function selectIncident(id) {
  const item = incidents.find(x => x.id === id); if (!item) return;
  APP.selectedIncident = id; renderIncidents(currentIncidentTab());
  $('#incidentDetail').innerHTML = `<div class="detail-content"><div class="detail-top"><span class="severity ${item.severity}">${item.severity.toUpperCase()}</span><h2>${item.title}</h2><p>${item.summary}</p><div class="detail-meta"><span>CASE <b>${item.id}</b></span><span>OWNER <b>${item.owner}</b></span><span>STATUS <b>${item.status}</b></span></div></div><section class="detail-section"><h3>OBSERVED EVIDENCE</h3><div class="evidence-list">${item.evidence.map(([key,value]) => `<div class="evidence-row"><span>${key}</span><span>${value}</span></div>`).join('')}</div></section><section class="detail-section"><h3>RECOMMENDED RESPONSE</h3><div class="response-actions">${item.actions.map(([title, text]) => `<button class="response-action" data-response="${title}"><b>${title}</b><span>${text}</span></button>`).join('')}</div></section><section class="detail-section"><h3>CASE TIMELINE</h3><div class="evidence-list"><div class="evidence-row"><span>Initial detection</span><span>${item.time}</span></div><div class="evidence-row"><span>Correlation confidence</span><span>${item.score}%</span></div><div class="evidence-row"><span>Automatic enrichment</span><span>Completed</span></div></div></section><div class="detail-footer"><button class="button alert action-contain">Contain entity</button><button class="button ghost action-assign">Assign to me</button></div></div>`;
  $$('.response-action').forEach(btn => btn.addEventListener('click', () => { logSimulation('response_action', {incident:item.id, action:btn.dataset.response}); toast('Response action queued', `${btn.dataset.response} was simulated successfully.`, 'warning'); }));
  $('.action-contain').addEventListener('click', () => { logSimulation('contain_entity', {incident:item.id, entity:item.entity}); toast('Containment simulation started', `${item.entity} was moved to a protected containment state.`, 'danger'); });
  $('.action-assign').addEventListener('click', () => { item.owner = AUTH.currentUser?.name || 'You'; item.status = 'Investigating'; logSimulation('assign_case', {incident:item.id}); selectIncident(id); toast('Case assigned', `${item.id} is now in your analyst queue.`); });
}

function currentIncidentTab() { return $('#incidentTabs .active')?.dataset.tab || 'open'; }
function openIncident(id, jump) { if (jump) changeView('incidents'); setTimeout(() => selectIncident(id), 30); }

function renderDetectionLab() {
  const code = `<span class="comment"># Simulated detection analytic — portfolio demo</span>\n<span class="key">title:</span> <span class="string">Impossible travel with privileged role</span>\n<span class="key">status:</span> <span class="string">enabled</span>\n<span class="key">severity:</span> <span class="string">high</span>\n<span class="key">logsource:</span>\n  <span class="key">product:</span> <span class="string">identity_provider</span>\n<span class="key">detection:</span>\n  <span class="key">selection:</span>\n    <span class="key">role:</span> <span class="string">[\"Global Administrator\", \"Privileged Role Admin\"]</span>\n    <span class="key">geo_velocity_kmh:</span> <span class="string">&gt; 800</span>\n  <span class="key">condition:</span> <span class="string">selection and not trusted_corporate_egress</span>\n<span class="key">falsepositives:</span>\n  - <span class="string">Corporate travel with approved secure egress</span>\n<span class="key">tags:</span>\n  - <span class="string">attack.t1078</span>\n  - <span class="string">attack.t1098</span>`;
  $('#codeEditor').innerHTML = code;
  const sources = [['Identity Provider','Microsoft Entra / Okta normalized telemetry','HEALTHY'],['Cloud Audit','AWS CloudTrail and IAM events','HEALTHY'],['Endpoint Telemetry','EDR process and network signals','HEALTHY'],['VPN Gateway','Authentication and session trails','DEGRADED']];
  $('#sourceList').innerHTML = sources.map(([name,desc,status]) => `<div class="source-row"><div><strong>${name}</strong><p>${desc}</p></div><span style="color:${status === 'DEGRADED' ? 'var(--yellow)' : 'var(--green)'}">● ${status}</span></div>`).join('');
}

function renderIntel() {
  $('#intelFeed').innerHTML = intelligence.map(item => `<article class="intel-feed-item"><div class="brief-meta" style="color:${item.color === 'red' ? 'var(--red)' : item.color === 'purple' ? 'var(--purple)' : item.color === 'green' ? 'var(--green)' : 'var(--orange)'}"><span>${item.source}</span><span>${item.label}</span></div><h3>${item.title}</h3><p>${item.description}</p><footer><span>${item.time}</span><button class="text-button intel-open">Open brief →</button></footer></article>`).join('');
  $('.ioc-node-view').innerHTML = nodeGraph();
  const watch = [['198.51.100.0/24','Credential phishing infrastructure','High'],['hash: 92ad…7c31','Ransomware family sample cluster','Critical'],['sync-auth[.]cloud','Session replay callback domain','High'],['ASN 64513','Newly observed proxy network','Medium'],['svc-finance-archive','Sensitive service account','Watch']];
  $('#watchlist').innerHTML = watch.map(([ioc,desc,level]) => `<article class="watch-item"><strong>${ioc}</strong><p>${desc}</p><footer><span>${level.toUpperCase()}</span><span>Tracked now</span></footer></article>`).join('');
}

function nodeGraph() {
  const nodes = [ ['idp-prod-02','hot',44,44], ['auth-session','',238,77], ['198.51.100.14','purple',96,210], ['aws-prod','',305,242], ['mail-sec-01','',184,352], ['ioc-cluster','hot',345,378] ];
  const links = [[84,66,266,96],[84,66,134,230],[134,230,343,262],[343,262,384,394],[205,366,384,394]];
  return links.map(([x,y,x2,y2]) => { const dx=x2-x,dy=y2-y; const len=Math.hypot(dx,dy); const deg=Math.atan2(dy,dx)*180/Math.PI; return `<i class="ioc-link" style="left:${x}px;top:${y}px;width:${len}px;transform:rotate(${deg}deg)"></i>`; }).join('') + nodes.map(([label,cls,x,y]) => `<span class="ioc-node ${cls}" style="left:${x}px;top:${y}px">${label}</span>`).join('');
}

function renderAssets() {
  const render = (filter='') => {
    const source = assets.filter(a => a.join(' ').toLowerCase().includes(filter.toLowerCase()));
    $('#assetTable').innerHTML = source.map(([name,owner,tier,exposure,last,status]) => `<tr><td><a href="#" class="event-link asset-link">${name}</a></td><td>${owner}</td><td><span class="criticality ${tier === 'Tier 1' ? 'tier-1' : tier === 'Tier 2' ? 'tier-2' : 'tier-3'}">${tier.toUpperCase()}</span></td><td><span class="exposure-tag ${exposure.toLowerCase()}">${exposure.toUpperCase()}</span></td><td><span class="time-cell">${last}</span></td><td><span class="asset-status ${status === 'Watch' ? 'watch' : ''}"><i></i>${status.toUpperCase()}</span></td><td><button class="row-action asset-link">→</button></td></tr>`).join('');
    $$('.asset-link').forEach(el => el.addEventListener('click', (ev) => { ev.preventDefault(); toast('Asset context opened', 'Asset details would open in a full integrated environment.'); }));
  };
  render();
  $('#assetSearch').addEventListener('input', e => render(e.target.value));
  const domains = [['Identity',76],['Cloud configuration',34],['Endpoint hygiene',42],['Public exposure',51],['Data protection',22]];
  $('#domainBars').innerHTML = domains.map(([name,value]) => `<div class="domain-row"><span>${name}</span><b>${value}</b><div class="control-track"><i style="width:${value}%;background:${value > 65 ? 'var(--red)' : value > 45 ? 'var(--orange)' : 'var(--green)'}"></i></div></div>`).join('');
}

function renderPlaybooks() {
  $('#playbookCards').innerHTML = playbooks.map(([name,desc,icon], index) => `<article class="playbook-card ${index === 0 ? 'active' : ''}" data-playbook="${index}"><span class="playbook-icon">${icon}</span><div><h3>${name}</h3><p>${desc}</p></div><span>● READY</span></article>`).join('');
  $$('.playbook-card').forEach(el => el.addEventListener('click', () => {
    $$('.playbook-card').forEach(card => card.classList.remove('active')); el.classList.add('active');
    const [name] = playbooks[Number(el.dataset.playbook)]; $('#flowTitle').textContent = name; renderFlow(Number(el.dataset.playbook));
  }));
  renderFlow(0);
}
function renderFlow(index) {
  const flows = [
    [['Signal received','Identity risk score exceeds threshold',''],['Enrich context','Collect related logins and host context',''],['Contain sessions','Revoke active tokens and enforce MFA','danger'],['Hunt related activity','Pivot across privileged identities',''],['Close or escalate','Record decision and preserve evidence','success']],
    [['Detect encryption burst','High-rate file modification behavior',''],['Isolate endpoint','Restrict network access immediately','danger'],['Preserve evidence','Capture memory and process telemetry',''],['Block IOCs','Update endpoint and firewall controls',''],['Recover securely','Validate backups and restore operations','success']],
  ];
  const steps = flows[index === 1 ? 1 : 0];
  $('#flowCanvas').innerHTML = steps.map(([title,sub,cls]) => `<div class="flow-step ${cls}"><b>${title}</b><span>${sub}</span></div>`).join('');
}

function setupNavigation() {
  $$('.nav-item').forEach(btn => btn.addEventListener('click', () => changeView(btn.dataset.view)));
  $$('[data-view-jump]').forEach(btn => btn.addEventListener('click', () => changeView(btn.dataset.viewJump)));
}
function changeView(view) {
  APP.activeView = view;
  $$('.view').forEach(section => section.classList.toggle('active', section.id === view));
  $$('.nav-item').forEach(btn => btn.classList.toggle('active', btn.dataset.view === view));
  window.scrollTo({ top:0, behavior:'smooth' });
  if (view === 'overview') requestAnimationFrame(resizeCanvases);
  if (view === 'detections') requestAnimationFrame(resizeQualityChart);
  if (view === 'device' && DEVICE.token) refreshDeviceStatus(false);
}

function setupButtons() {
  $('#dismissBanner').addEventListener('click', () => { $('#priorityBanner').style.display = 'none'; toast('Priority banner dismissed', 'The case remains in your active analyst queue.'); });
  $('#investigatePriority').addEventListener('click', () => openIncident('INC-2048', true));
  $('#openIncidentCreator').addEventListener('click', openIncidentModal);
  $('#createIncidentButton').addEventListener('click', openIncidentModal);
  $('#exportSnapshot').addEventListener('click', exportSnapshot);
  $('#downloadCaseReport').addEventListener('click', exportCaseReport);
  $('#refreshEvents').addEventListener('click', () => { addRandomEvent(); toast('Detection queue refreshed', 'A new telemetry correlation was added to the live queue.'); });
  $('#severityFilter').addEventListener('click', cycleSeverity);
  $('#incidentSearch').addEventListener('input', () => renderIncidents(currentIncidentTab()));
  $('#incidentSort').addEventListener('click', () => { incidents.reverse(); renderIncidents(currentIncidentTab()); toast('Queue reordered', 'Cases are now sorted in reverse priority order.'); });
  $$('#incidentTabs button').forEach(btn => btn.addEventListener('click', () => { $$('#incidentTabs button').forEach(x => x.classList.remove('active')); btn.classList.add('active'); renderIncidents(btn.dataset.tab); }));
  $('#runDetectionTest').addEventListener('click', () => toast('Test suite completed', '14 test events evaluated. 14 passed.', 'warning'));
  $('#newRuleButton').addEventListener('click', () => toast('New analytic editor opened', 'Use this design as a template for a new detection rule.'));
  $('#saveRule').addEventListener('click', () => toast('Detection version saved', 'Analytic saved as version 13.'));
  $('#applyTuning').addEventListener('click', () => toast('Tuning recommendation applied', 'Corporate egress exception added to the simulated rule.'));
  $('#syncIntel').addEventListener('click', () => toast('Feeds synchronized', '4 feeds refreshed and 16 simulated indicators added.'));
  $('#createHunt').addEventListener('click', () => toast('Hunt created', 'A new investigation canvas is ready for your IOCs.'));
  $('#runHunt').addEventListener('click', () => toast('Hunt complete', '7 matched entities found across simulated telemetry.', 'warning'));
  $('#assetScan').addEventListener('click', () => toast('Asset scan complete', 'Inventory updated: 243 protected assets.'));
  $('#addAsset').addEventListener('click', () => toast('Asset form opened', 'Add-asset workflow is simulated in this demo.'));
  $('#viewRemediation').addEventListener('click', () => toast('Remediation plan prepared', 'Two high-exposure services were prioritized.'));
  $('#testPlaybook').addEventListener('click', () => toast('Test completed safely', 'No live controls were changed. Simulation output: success.', 'warning'));
  $('#newPlaybook').addEventListener('click', () => toast('New playbook initialized', 'Start with a trigger and response action.'));
  $('#simulatePlaybook').addEventListener('click', () => toast('Playbook simulation complete', 'Containment actions executed in a safe simulated environment.', 'danger'));
  $('#closeModal').addEventListener('click', closeModal);
  $('#modalLayer').addEventListener('click', e => { if (e.target === $('#modalLayer')) closeModal(); });
}

function cycleSeverity() {
  const choices = ['all','critical','high','medium','low']; const idx=choices.indexOf(APP.eventSeverity); APP.eventSeverity = choices[(idx+1)%choices.length];
  $('#severityFilter').textContent = `Severity: ${APP.eventSeverity} ⌄`; renderEvents();
}

function openIncidentModal() {
  $('#modalContent').innerHTML = `<div class="modal-content"><h2>Open a new incident</h2><p>Create a simulated case for your SOC workflow. This portfolio build does not submit data to any external system.</p><form class="modal-form" id="incidentForm"><label>Case title<input required placeholder="e.g., Suspicious OAuth consent" /></label><label>Severity<select><option>High</option><option>Critical</option><option>Medium</option><option>Low</option></select></label><label>Primary entity<input required placeholder="e.g., user@company.example" /></label><label>Analyst note<textarea placeholder="Add observed evidence or initial scope..."></textarea></label><button class="button primary" type="submit">Create simulated case</button></form></div>`;
  $('#modalLayer').classList.add('open'); $('#modalLayer').setAttribute('aria-hidden','false');
  $('#incidentForm').addEventListener('submit', e => { e.preventDefault(); closeModal(); toast('Incident created', 'Your simulated case was added to the analyst workspace.'); changeView('incidents'); });
}
function closeModal() { $('#modalLayer').classList.remove('open'); $('#modalLayer').setAttribute('aria-hidden','true'); }

function setupTerminal() {
  const entries = [
    ['good','[OK] Correlation engine online · 38 sources connected'],
    ['','[INFO] Tracking privileged identity session baseline'],
    ['warn','[WARN] Elevated authentication anomaly score: idp-prod-02'],
    ['good','[OK] Enrichment complete · 12 context objects attached'],
  ];
  entries.forEach(([type,text]) => appendTerminal(type,text));
  $('#terminalForm').addEventListener('submit', e => { e.preventDefault(); const input=$('#terminalCommand'); const command=input.value.trim(); if (!command) return; appendTerminal('', `<span class="prompt">operator@aegis:~$</span> <span class="cmd">${escapeHTML(command)}</span>`); safeTerminalCommand(command); input.value=''; });
}
function appendTerminal(type, text) { const el = document.createElement('div'); el.className = `term-line ${type}`; el.innerHTML = text; $('#terminal').appendChild(el); $('#terminal').scrollTop = $('#terminal').scrollHeight; }
function safeTerminalCommand(command) {
  const normalized = command.toLowerCase();
  const responses = {
    help:'Available simulated commands: <span class="cmd">status</span>, <span class="cmd">hunt</span>, <span class="cmd">isolate &lt;entity&gt;</span>, <span class="cmd">clear</span>.',
    status:'<span class="good">[OK] SOC nominal. 12 active cases, 3 require immediate attention.</span>',
    hunt:'<span class="good">[OK] Hunt job started against simulated telemetry. Candidate results: 7.</span>',
  };
  if (normalized === 'clear') { $('#terminal').innerHTML=''; return; }
  logSimulation('terminal_command', {command: normalized});
  if (normalized.startsWith('isolate')) { logSimulation('terminal_isolate', {command: normalized}); appendTerminal('warn','[SIMULATION] Isolation request accepted. No actual endpoint or network control was contacted.'); return; }
  appendTerminal('', responses[normalized] || '[INFO] Unknown simulation command. Type <span class="cmd">help</span> to view available safe commands.');
}
function escapeHTML(value) { return value.replace(/[&<>'"]/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#039;','"':'&quot;'}[ch])); }

function setupCommandPalette() {
  const actions = [
    ['Overview','Open live security posture','◈',()=>changeView('overview')],
    ['Incidents','Open incident response workspace','!',()=>changeView('incidents')],
    ['Detection Lab','Open analytics engineering','⌬',()=>changeView('detections')],
    ['Threat Intel','Open intelligence fusion','◉',()=>changeView('intel')],
    ['Asset Exposure','Open attack surface management','▦',()=>changeView('assets')],
    ['Device Protection','Connect local Microsoft Defender and firewall agent','⌁',()=>changeView('device')],
    ['Playbooks','Open automated response library','↯',()=>changeView('playbooks')],
    ['Open priority incident','Investigate INC-2048','!',()=>openIncident('INC-2048', true)],
    ['Export snapshot','Download current simulated dashboard summary','⇩',exportSnapshot],
  ];
  const renderCommands = filter => {
    const matching = actions.filter(a => `${a[0]} ${a[1]}`.toLowerCase().includes(filter.toLowerCase()));
    APP.commandIndex = clamp(APP.commandIndex,0,Math.max(matching.length-1,0));
    $('#commandResults').innerHTML = matching.map((a,index) => `<button class="command-result ${index === APP.commandIndex ? 'selected' : ''}" data-index="${index}"><i>${a[2]}</i><div>${a[0]}<span>${a[1]}</span></div><kbd>↵</kbd></button>`).join('') || `<div class="empty-state" style="min-height:150px"><h2>No actions found</h2><p>Try another phrase.</p></div>`;
    $$('.command-result').forEach(btn => btn.addEventListener('click', () => { const action=matching[Number(btn.dataset.index)]; closeCommand(); action[3](); }));
    return matching;
  };
  let current = renderCommands('');
  const open = () => { $('#commandModal').classList.add('open'); $('#commandModal').setAttribute('aria-hidden','false'); $('#commandSearch').value=''; current=renderCommands(''); setTimeout(() => $('#commandSearch').focus(),20); };
  const close = () => { $('#commandModal').classList.remove('open'); $('#commandModal').setAttribute('aria-hidden','true'); };
  window.closeCommand = close;
  $('#openCommand').addEventListener('click', open);
  $('#commandSearch').addEventListener('input', e => { APP.commandIndex=0; current=renderCommands(e.target.value); });
  document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase()==='k') { e.preventDefault(); open(); }
    if (!$('#commandModal').classList.contains('open')) return;
    if (e.key==='Escape') close();
    if (e.key==='ArrowDown') { e.preventDefault(); APP.commandIndex=clamp(APP.commandIndex+1,0,current.length-1); renderCommands($('#commandSearch').value); }
    if (e.key==='ArrowUp') { e.preventDefault(); APP.commandIndex=clamp(APP.commandIndex-1,0,current.length-1); renderCommands($('#commandSearch').value); }
    if (e.key==='Enter' && current.length) { e.preventDefault(); const action=current[APP.commandIndex]; close(); action[3](); }
  });
  $('#commandModal').addEventListener('click', e => { if(e.target===$('#commandModal')) close(); });
}

function toast(title, text, type='') {
  const el = document.createElement('article'); el.className = `toast ${type}`;
  el.innerHTML = `<div><strong>${title}</strong><p>${text}</p></div><button aria-label="Dismiss">×</button>`;
  $('#toastStack').appendChild(el); $('button',el).addEventListener('click',()=>el.remove()); setTimeout(()=>el.remove(), 5000);
}

function exportSnapshot() {
  const content = `AEGIS SENTINEL — SIMULATED SOC SNAPSHOT\nGenerated: ${new Date().toISOString()}\nWorkspace user: ${AUTH.currentUser?.name || 'Aegis Analyst'}\n\nEvents processed: 2.84B\nActive incidents: ${incidents.length}\nThreats disrupted: ${formatNumber(APP.threats)}\nProtected assets: 243\nExposure score: 34/100\n\nPriority case: INC-2048 — Potential credential abuse against identity infrastructure\n\nThis report contains local simulated portfolio data only.`;
  downloadFile('aegis-sentinel-snapshot.txt', content); toast('Snapshot exported', 'Your simulated SOC snapshot was downloaded.');
}
function exportCaseReport() { const item = APP.selectedIncident ? incidents.find(i=>i.id===APP.selectedIncident) : incidents[0]; const content = `AEGIS SENTINEL — CASE REPORT\nCase: ${item.id}\nTitle: ${item.title}\nSeverity: ${item.severity}\nOwner: ${item.owner}\nEntity: ${item.entity}\n\nSummary:\n${item.summary}\n\nEvidence:\n${item.evidence.map(([a,b])=>`- ${a}: ${b}`).join('\n')}\n\nThis is simulated portfolio data.`; downloadFile(`${item.id}-report.txt`, content); toast('Case report exported', `${item.id} report downloaded.`); }
function downloadFile(name, content) { const blob = new Blob([content], {type:'text/plain'}); const url = URL.createObjectURL(blob); const a=document.createElement('a'); a.href=url; a.download=name; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url); }

function animateCounters() {
  const nodes=[['metricEvents',2.84,'B'],['metricIncidents',12,''],['metricThreats',48291,''],['metricAssets',243,''],['metricExposure',34,'']];
  nodes.forEach(([id,target,suffix]) => { const node=$('#'+id); const started=performance.now(); const dur=900; const run=(now)=>{ const t=clamp((now-started)/dur,0,1); const value=target*(1-Math.pow(1-t,3)); node.textContent=(suffix === 'B' ? value.toFixed(2) : Math.round(value).toLocaleString())+suffix; if(t<1) requestAnimationFrame(run); }; requestAnimationFrame(run); });
}

function simulateTelemetry() {
  APP.threats += random(1,9); $('#metricThreats').textContent=formatNumber(APP.threats); $('#mapAttackCount').textContent=formatNumber(4821 + random(-33,46));
  const choices = [
    {severity:'high', detection:'Abnormal outbound authentication flow', entity:'idp-edge-01', mitre:'T1071 · App Layer Protocol', time:'just now', incident:'INC-2048'},
    {severity:'medium', detection:'Unusual archive creation pattern', entity:'files-prod-01', mitre:'T1074 · Data Staged', time:'just now', incident:'INC-2022'},
    {severity:'low', detection:'New device enrollment observed', entity:'mktg-tenant', mitre:'T1098 · Account Manipulation', time:'just now', incident:'INC-2022'},
  ];
  if (Math.random() > .48) { liveEvents.unshift(pick(choices)); liveEvents.splice(8); renderEvents(); }
  appendTerminal('', `[INFO] Ingest checkpoint: <span class="cmd">${random(118,135)}K events/sec</span> · correlation latency ${random(20,44)}ms`);
  if (Math.random() > .9 && Date.now() - APP.lastCorrelationToast > 45000) { APP.lastCorrelationToast = Date.now(); toast('New telemetry correlation', 'Anomaly confidence increased for an active simulated case.', 'warning'); }
}

function updateRisk() {
  const score=random(66,78); $('#riskScore').textContent=score; $('#gaugeProgress').style.strokeDashoffset=String(188.5-(188.5*score/100));
  $('#metricExposure').textContent=random(31,38);
}

/* Canvas maps and charts */
function setupCanvas() {
  for (let i=0; i<62; i++) { APP.traffic.ingest.push(random(78,137)); APP.traffic.anomaly.push(random(10,35)); APP.traffic.contained.push(random(4,18)); }
  seedMapFlows(); resizeCanvases(); window.addEventListener('resize', resizeCanvases);
  requestAnimationFrame(drawLoop); setInterval(updateTrafficData, 800);
}
function resizeCanvases() { resizeCanvas($('#threatMap')); resizeCanvas($('#trafficChart')); resizeQualityChart(); }
function resizeCanvas(canvas) { if (!canvas) return; const rect=canvas.getBoundingClientRect(); const dpr=window.devicePixelRatio||1; canvas.width=Math.max(1,Math.floor(rect.width*dpr)); canvas.height=Math.max(1,Math.floor(rect.height*dpr)); canvas.getContext('2d').setTransform(dpr,0,0,dpr,0,0); }
function resizeQualityChart() { const canvas=$('#qualityChart'); if(!canvas)return; resizeCanvas(canvas); drawQualityChart(); }
function updateTrafficData() { APP.traffic.ingest.push(random(82,145)); APP.traffic.anomaly.push(random(8,48)); APP.traffic.contained.push(random(4,28)); ['ingest','anomaly','contained'].forEach(k=>APP.traffic[k].shift()); $('#trafficRate').textContent=`${(random(1210,1370)/10).toFixed(1)}K/s`; }
function seedMapFlows() { APP.mapFlows = Array.from({length:10}, (_,i)=>({from:i%9,to:(i*3+4)%10,t:Math.random(),speed:.0016+Math.random()*.003,color:pick(['#ff5470','#ff8b4b','#ffd166'])})); }
function drawLoop() { drawThreatMap(); drawTrafficChart(); drawQualityChart(); requestAnimationFrame(drawLoop); }
function drawThreatMap() {
  const canvas=$('#threatMap'); if(!canvas) return; const ctx=canvas.getContext('2d'); const w=canvas.clientWidth,h=canvas.clientHeight; if(!w||!h)return; ctx.clearRect(0,0,w,h);
  const bg=ctx.createRadialGradient(w*.5,h*.45,0,w*.5,h*.45,w*.7); bg.addColorStop(0,'rgba(7,49,75,.28)'); bg.addColorStop(1,'rgba(2,9,15,.03)'); ctx.fillStyle=bg; ctx.fillRect(0,0,w,h);
  ctx.strokeStyle='rgba(54,178,223,.08)';ctx.lineWidth=.7; for(let x=0;x<w;x+=w/10){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,h);ctx.stroke();} for(let y=0;y<h;y+=h/5){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(w,y);ctx.stroke();}
  const continents=[[.09,.18,.18,.22],[.16,.48,.11,.28],[.43,.18,.15,.14],[.44,.33,.13,.34],[.58,.16,.25,.27],[.72,.58,.13,.15]];
  continents.forEach(([x,y,cw,ch])=>{ctx.beginPath();ctx.roundRect(x*w,y*h,cw*w,ch*h,8);ctx.fillStyle='rgba(15,95,127,.17)';ctx.fill();ctx.strokeStyle='rgba(37,212,255,.16)';ctx.stroke();});
  const nodes=[[.13,.32,'US-EAST'],[.25,.25,'TORONTO'],[.47,.28,'LONDON'],[.52,.34,'BERLIN'],[.60,.42,'NAIROBI'],[.68,.24,'DELHI'],[.78,.28,'SINGAPORE'],[.86,.65,'SYDNEY'],[.56,.2,'REYKJAVIK'],[.38,.58,'SAO PAULO']].map(([x,y,label],i)=>({x:x*w,y:y*h,label,color:i===0||i===3?'#ff5470':i===5||i===6?'#ff8b4b':'#25d4ff'}));
  APP.mapFlows.forEach(flow=>{ const a=nodes[flow.from],b=nodes[flow.to]; flow.t+=flow.speed; if(flow.t>1){flow.t=0; flow.from=random(0,nodes.length-1);flow.to=random(0,nodes.length-1);flow.color=pick(['#ff5470','#ff8b4b','#ffd166']);} const cx=(a.x+b.x)/2,cy=Math.min(a.y,b.y)-h*.18; ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.quadraticCurveTo(cx,cy,b.x,b.y);ctx.strokeStyle=flow.color+'44';ctx.lineWidth=1;ctx.stroke();const t=flow.t;const px=(1-t)*(1-t)*a.x+2*(1-t)*t*cx+t*t*b.x,py=(1-t)*(1-t)*a.y+2*(1-t)*t*cy+t*t*b.y;ctx.beginPath();ctx.arc(px,py,2.5,0,Math.PI*2);ctx.fillStyle=flow.color;ctx.shadowBlur=10;ctx.shadowColor=flow.color;ctx.fill();ctx.shadowBlur=0;});
  nodes.forEach(node=>{const p=.6+Math.sin(Date.now()/600+node.x)*.35;ctx.beginPath();ctx.arc(node.x,node.y,9*p,0,Math.PI*2);ctx.strokeStyle=node.color+'55';ctx.stroke();ctx.beginPath();ctx.arc(node.x,node.y,3.4,0,Math.PI*2);ctx.fillStyle=node.color;ctx.shadowBlur=9;ctx.shadowColor=node.color;ctx.fill();ctx.shadowBlur=0;ctx.fillStyle='rgba(192,228,242,.72)';ctx.font='8px DM Mono';ctx.fillText(node.label,node.x+6,node.y-6);});
}
function drawTrafficChart() { const canvas=$('#trafficChart'); if(!canvas)return; const ctx=canvas.getContext('2d');const w=canvas.clientWidth,h=canvas.clientHeight;if(!w||!h)return;ctx.clearRect(0,0,w,h);ctx.strokeStyle='rgba(71,155,191,.12)';ctx.lineWidth=.6;for(let i=1;i<5;i++){const y=(h/5)*i;ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(w,y);ctx.stroke();} const draw=(data,color,fill,max)=>{ const step=w/(data.length-1);ctx.beginPath();data.forEach((v,i)=>{const x=i*step,y=h-((v/max)*(h-16))-8;i?ctx.lineTo(x,y):ctx.moveTo(x,y);});ctx.lineTo(w,h);ctx.lineTo(0,h);ctx.closePath();ctx.fillStyle=fill;ctx.fill();ctx.beginPath();data.forEach((v,i)=>{const x=i*step,y=h-((v/max)*(h-16))-8;i?ctx.lineTo(x,y):ctx.moveTo(x,y);});ctx.strokeStyle=color;ctx.lineWidth=1.4;ctx.stroke();};draw(APP.traffic.ingest,'#25d4ff','rgba(37,212,255,.055)',160);draw(APP.traffic.anomaly,'#ff5470','rgba(255,84,112,.05)',160);draw(APP.traffic.contained,'#4df2aa','rgba(77,242,170,.045)',160);ctx.font='8px DM Mono';ctx.fillStyle='rgba(138,183,203,.6)';ctx.fillText('160K',4,13);ctx.fillText('80K',4,h/2);ctx.fillText('0',4,h-6); }
function drawQualityChart() { const canvas=$('#qualityChart'); if(!canvas)return;const ctx=canvas.getContext('2d');const w=canvas.clientWidth,h=canvas.clientHeight;if(!w||!h)return;ctx.clearRect(0,0,w,h);ctx.strokeStyle='rgba(71,155,191,.12)';ctx.lineWidth=.6;for(let i=1;i<4;i++){ctx.beginPath();ctx.moveTo(0,(h/4)*i);ctx.lineTo(w,(h/4)*i);ctx.stroke();} const points=Array.from({length:18},(_,i)=>62+Math.sin(i*.85)*8+i*1.45);const step=w/(points.length-1);ctx.beginPath();points.forEach((v,i)=>{const x=i*step,y=h-(v/100)*(h-18)-8;i?ctx.lineTo(x,y):ctx.moveTo(x,y);});ctx.strokeStyle='#b68cff';ctx.lineWidth=1.5;ctx.stroke();ctx.lineTo(w,h);ctx.lineTo(0,h);ctx.closePath();ctx.fillStyle='rgba(182,140,255,.09)';ctx.fill();ctx.fillStyle='rgba(148,190,208,.7)';ctx.font='8px DM Mono';ctx.fillText('Precision trend',8,13); }

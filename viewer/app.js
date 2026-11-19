// Jarvis Galaxy HUD. Everything goes to POST /chat; the server decides what it is and returns a "kind" to draw.
// No inline scripts (the page's Content-Security-Policy forbids them), and all text goes in via textContent.
(function () {
  'use strict';
  const $ = id => document.getElementById(id);
  const mk = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
  const pad2 = n => String(n).padStart(2, '0');
  const session = (() => {
    try { return sessionStorage.getItem('jg-session') || (sessionStorage.setItem('jg-session', crypto.randomUUID()), sessionStorage.getItem('jg-session')); }
    catch (e) { return crypto.randomUUID(); }
  })();

  // A 401 means the session ended (idle, locked, restarted): back to the login page.
  async function api(path, body) {
    const res = await fetch(path, body === undefined ? { cache: 'no-store' }
      : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (res.status === 401) { location.replace('/login'); throw new Error('Locked.'); }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Server error (${res.status})`);
    return data;
  }

  // ---------- Voice out ----------
  let mode = {};
  function speak(text) {
    if (!('speechSynthesis' in window) || !text) return;
    speechSynthesis.cancel();
    const u = new SpeechSynthesisUtterance(text.replace(/\(Answered by the private brain[^)]*\)/, ''));
    const voices = speechSynthesis.getVoices();
    const wanted = (mode.voice || '').toLowerCase();
    u.voice = voices.find(v => wanted && v.name.toLowerCase().startsWith(wanted))
           || voices.find(v => /en-GB/i.test(v.lang) && /male|george|ryan|daniel/i.test(v.name))
           || voices.find(v => /en-GB/i.test(v.lang)) || null;
    speechSynthesis.speak(u);
  }

  // ---------- Answers ----------
  function show(question, content, isError) {
    const box = $('answer');
    box.replaceChildren();
    if (question) box.append(mk('div', 'q', question));
    box.append(typeof content === 'string' ? mk('div', isError ? 'err' : '', content) : content);
  }

  // ---------- Drawer ----------
  function drawer(title, nodes) {
    $('drawer-title').textContent = title;
    $('drawer-body').replaceChildren(...nodes);
    $('drawer').classList.add('open');
    $('drawer').setAttribute('aria-hidden', 'false');
  }
  $('drawer-close').addEventListener('click', () => { $('drawer').classList.remove('open'); $('drawer').setAttribute('aria-hidden', 'true'); });
  function sourcesDrawer(data) {
    drawer(`Sources · ${data.query}`, data.sources.length ? data.sources.map(s => {
      const a = mk('a', 'src' + (s.used ? ' used' : ''));
      a.href = s.url; a.target = '_blank'; a.rel = 'noopener noreferrer';
      a.append(mk('div', 't', s.title || s.domain), mk('div', 'd', s.domain + (s.used ? ' · cited' : '')), mk('div', 's', s.snippet));
      return a;
    }) : [mk('p', 'd', 'No sources came back.')]);
  }

  // ---------- The galaxy ----------
  let graph = null, data = { nodes: [], links: [] }, version = null;
  const COLORS = ['#5ee7ff', '#ffb36b', '#3dffa8', '#c49bff', '#ff8fb1', '#ffe08a', '#7fb3ff'];
  const groupColor = (() => { const m = {}; return g => m[g] || (m[g] = COLORS[Object.keys(m).length % COLORS.length]); })();
  let lit = new Set();
  // Each note is a glowing star: an additive sprite (unaffected by scene lighting), coloured by its folder.
  let glowTexture = null;
  function glow() {
    if (glowTexture) return glowTexture;
    const c = document.createElement('canvas');
    c.width = c.height = 128;
    const g = c.getContext('2d'), grad = g.createRadialGradient(64, 64, 0, 64, 64, 64);
    grad.addColorStop(0, 'rgba(255,255,255,1)');
    grad.addColorStop(0.18, 'rgba(255,255,255,0.95)');
    grad.addColorStop(0.42, 'rgba(255,255,255,0.35)');
    grad.addColorStop(1, 'rgba(255,255,255,0)');
    g.fillStyle = grad;
    g.fillRect(0, 0, 128, 128);
    return (glowTexture = new THREE.CanvasTexture(c));
  }
  function star(n) {
    const dim = lit.size && !lit.has(n.id);
    const sprite = new THREE.Sprite(new THREE.SpriteMaterial({
      map: glow(), color: dim ? '#3a5260' : groupColor(n.group), transparent: true,
      blending: THREE.AdditiveBlending, depthWrite: false, opacity: dim ? 0.5 : 1 }));
    const size = 10 + Math.sqrt(n.degree + 1) * 7 + (lit.has(n.id) ? 10 : 0);
    sprite.scale.set(size, size, 1);
    return sprite;
  }
  function initGraph() {
    if (typeof ForceGraph3D === 'undefined') {
      $('error').hidden = false;
      $('error').textContent = 'The 3D libraries didn’t load (no internet, or the CDN file didn’t match its pinned hash).';
      return;
    }
    graph = ForceGraph3D()($('galaxy'))
      .backgroundColor('#02070d')
      .showNavInfo(false)
      .nodeLabel(n => n.label)
      .nodeThreeObject(star)
      .linkColor(l => l.kind === 'link' ? 'rgba(94,231,255,0.55)' : 'rgba(94,231,255,0.15)')
      .linkWidth(l => l.kind === 'link' ? 0.8 : 0.2)
      .onNodeClick(openNote);
    addEventListener('resize', () => graph.width(innerWidth).height(innerHeight));
  }
  function openNote(n) {
    drawer(n.label, [mk('div', 'note-text', n.excerpt || '(empty note)')]);
    if (graph) flyTo(n);
  }
  function flyTo(n) {
    const d = 90, r = 1 + d / Math.hypot(n.x || 1, n.y || 1, n.z || 1);
    graph.cameraPosition({ x: (n.x || 0) * r, y: (n.y || 0) * r, z: (n.z || 0) * r }, n, 1200);
  }
  async function loadGraph() {
    try {
      const g = await api('/api/graph');
      if (g.version === version) return;
      version = g.version;
      data = { nodes: g.nodes, links: g.links };
      if (graph) {
        const first = !graph.graphData().nodes.length;
        graph.graphData(data);
        if (first) setTimeout(() => graph.zoomToFit(800, 140), 1200);   // fill the screen once it has settled
      }
    } catch (e) { /* offline or locked */ }
  }
  function light(ids) {
    lit = new Set(ids || []);
    if (graph) graph.nodeThreeObject(star);                          // redraw: cited notes bright, the rest dimmed
    const first = data.nodes.find(n => n.id === (ids || [])[0]);
    if (first && graph) setTimeout(() => flyTo(first), 300);
  }

  // ---------- Activity ----------
  function dayLabel(date) {
    const d = new Date(`${date}T12:00:00`), today = new Date(); today.setHours(12, 0, 0, 0);
    const days = Math.round((today - d) / 86400000);
    if (days === 0) return 'Today';
    if (days === 1) return 'Yesterday';
    if (days > 1 && days < 7) return d.toLocaleDateString('en-GB', { weekday: 'long' });
    return d.toLocaleDateString('en-GB', { weekday: 'short', day: 'numeric', month: 'short' });
  }
  async function loadActivity() {
    try {
      const { entries } = await api('/api/activity');
      const list = $('activity');
      list.replaceChildren();
      if (!entries.length) list.append(mk('li', 'empty', 'Quiet so far.'));
      let day = null;
      entries.slice(0, 14).forEach(e => {
        if (e.date !== day) { day = e.date; list.append(mk('li', 'day', dayLabel(day))); }
        const li = mk('li');
        li.append(mk('time', '', e.at), mk('span', '', e.text));
        li.title = `${e.date} ${e.at}\n${e.text}`;
        list.append(li);
      });
    } catch (e) { /* offline */ }
  }

  // ---------- Modes ----------
  async function loadMode() {
    try {
      mode = await api('/api/mode');
      $('name').textContent = (mode.name || 'Jarvis').toUpperCase();
      document.title = `${mode.name || 'Jarvis'} Galaxy`;
      $('chip-demo').hidden = !mode.demo;
      $('chip-expert').hidden = !mode.expert || mode.lab;
      $('chip-lab').hidden = !mode.lab;
      $('chip-private').hidden = !mode.private;
      $('chip-expert').title = `Expert mode until ${mode.until}`;
      $('chip-lab').title = `Lab mode until ${mode.until}`;
      $('lock').hidden = !mode.locked;
    } catch (e) { /* offline */ }
  }

  // ---------- Asking ----------
  const LOCK_RE = /^\s*(?:(?:please|jarvis)[\s,]+)?(?:lock(?:\s+(?:jarvis|yourself|now))?|log\s*out|sign\s*out)[\s.!]*$/i;
  let busy = false;
  async function lock() {
    try { await fetch('/auth/logout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }); } catch (e) {}
    location.replace('/login');
  }
  $('lock').addEventListener('click', lock);

  async function ask(question) {
    question = question.trim();
    if (!question || busy) return;
    if (LOCK_RE.test(question)) return lock();
    busy = true;
    $('send').disabled = true;
    $('q').value = '';
    show(question, '…');
    try {
      const d = await api('/chat', { text: question, session });
      show(question, d.answer);
      speak(d.answer);
      if (d.kind === 'answer') light(d.nodes);
      if (d.kind === 'research') sourcesDrawer(d);
      if (d.kind === 'capture') setTimeout(loadGraph, 400);
      if (d.kind === 'mode') loadMode();
      loadActivity();
    } catch (err) {
      show(question, err.message === 'Failed to fetch' ? 'Can’t reach the server. Is it running?' : err.message, true);
    } finally {
      busy = false;
      $('send').disabled = false;
      $('q').focus();
    }
  }
  $('ask').addEventListener('submit', e => { e.preventDefault(); ask($('q').value); });

  // ---------- Voice in (Chrome's Web Speech API: audio goes to Google while the mic is on) ----------
  const Rec = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!Rec) $('mic').hidden = true;
  $('mic').addEventListener('click', () => {
    const r = new Rec();
    r.lang = navigator.language || 'en-GB';
    r.interimResults = false;
    $('mic').classList.add('on');
    r.onresult = e => ask(e.results[0][0].transcript);
    r.onend = () => $('mic').classList.remove('on');
    r.onerror = () => $('mic').classList.remove('on');
    if (window.speechSynthesis) speechSynthesis.cancel();
    r.start();
  });

  // ---------- Reminders (spoken here; the server shows a Windows notification if no tab is open) ----------
  async function checkReminders() {
    if (busy) return;
    try {
      const { due } = await api('/api/reminders/due');
      if (!due.length) return;
      const { delivered } = await api('/reminders/ack', { ids: due.map(r => r.id) });
      if (!delivered.length) return;
      const line = (delivered.length === 1 ? 'A reminder: ' : `${delivered.length} reminders: `) + delivered.map(r => r.text).join('; ') + '.';
      show('Reminder', line);
      speak(line);
    } catch (e) {}
  }

  // ---------- Clock ----------
  function tick() {
    const d = new Date();
    $('clock').textContent = `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
    $('date').textContent = d.toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'long' });
  }

  // ---------- Start ----------
  try {
    const notice = sessionStorage.getItem('auth-notice');
    if (notice) { sessionStorage.removeItem('auth-notice'); show('Security', notice, true); }
  } catch (e) {}
  tick();
  setInterval(tick, 1000 * 15);
  initGraph();
  loadMode().then(loadGraph);
  loadActivity();
  setInterval(loadGraph, 20 * 1000);
  setInterval(loadMode, 60 * 1000);
  setInterval(checkReminders, 15 * 1000);
  $('q').focus();
})();

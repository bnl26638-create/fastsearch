const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'fastsearch_dev_secret';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 },
}));

// ===== Utilisateurs en mémoire =====
const users = [];

// ===== Middleware auth =====
const requireAuth = (req, res, next) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Non connecté' });
  next();
};

// ===== API AUTH =====
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Champs manquants' });
  if (password.length < 4) return res.status(400).json({ error: 'Mot de passe trop court (min 4)' });
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ error: 'Nom d\'utilisateur déjà pris' });
  }
  const hash = await bcrypt.hash(password, 10);
  users.push({ id: users.length + 1, username, password: hash });
  res.json({ success: true });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: 'Identifiants incorrects' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Identifiants incorrects' });
  req.session.userId = user.id;
  req.session.username = user.username;
  res.json({ success: true });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/me', (req, res) => {
  if (req.session.userId) return res.json({ username: req.session.username });
  res.status(401).json({ error: 'Non connecté' });
});

// ===== API RECHERCHE (placeholder) =====
app.get('/api/search', requireAuth, (req, res) => {
  res.json([]);
});

app.get('/api/stats', (req, res) => {
  res.json({ personnes: 0 });
});

// ===== PAGE UNIQUE (HTML + CSS + JS) =====
app.get('*', (req, res) => {
  res.send(HTML);
});

// ===== HTML COMPLET =====
const HTML = `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FastSearch — Trouve tout, vite</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0a0b10;--bg-2:#12141c;--bg-3:#1a1d29;--border:#232635;
  --text:#e8eaf0;--text-dim:#8b8fa3;--accent:#5865f2;--accent-2:#7c3aed;
  --accent-glow:rgba(88,101,242,.35);--danger:#ed4245;--success:#3ba55d;
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:'Inter',-apple-system,system-ui,sans-serif;
  background:var(--bg);color:var(--text);min-height:100vh;
  overflow-x:hidden;-webkit-font-smoothing:antialiased;
}
body::before{
  content:'';position:fixed;inset:0;pointer-events:none;z-index:-1;
  background:
    radial-gradient(circle at 20% 20%, rgba(88,101,242,.15), transparent 50%),
    radial-gradient(circle at 80% 80%, rgba(124,58,237,.12), transparent 50%);
  animation:bgFloat 20s ease-in-out infinite;
}
@keyframes bgFloat{
  0%,100%{transform:translate(0,0) scale(1)}
  50%{transform:translate(-30px,-20px) scale(1.05)}
}
.container{max-width:1200px;margin:0 auto;padding:40px 24px}

/* NAVBAR */
.navbar{
  display:flex;justify-content:space-between;align-items:center;
  padding:20px 32px;background:rgba(18,20,28,.8);backdrop-filter:blur(20px);
  border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100;
}
.logo{
  display:flex;align-items:center;gap:10px;font-size:20px;font-weight:800;
  letter-spacing:-.5px;
  background:linear-gradient(135deg,var(--accent),var(--accent-2));
  -webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;
}
.logo-icon{font-size:24px;filter:drop-shadow(0 0 12px var(--accent-glow))}
.nav-actions{display:flex;gap:12px;align-items:center}

/* BOUTONS */
button,.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:12px 22px;border-radius:10px;border:none;
  background:linear-gradient(135deg,var(--accent),var(--accent-2));
  color:#fff;font-size:14px;font-weight:600;cursor:pointer;text-decoration:none;
  transition:all .25s cubic-bezier(.4,0,.2,1);font-family:inherit;
}
button:hover,.btn:hover{transform:translateY(-2px);box-shadow:0 12px 30px var(--accent-glow)}
button:active,.btn:active{transform:translateY(0)}
.btn-ghost{background:transparent;border:1px solid var(--border);color:var(--text)}
.btn-ghost:hover{background:var(--bg-3);border-color:var(--accent);box-shadow:none}
.btn-small{padding:8px 14px;font-size:13px}

/* HERO */
.hero{text-align:center;padding:100px 20px 60px;animation:fadeUp .8s ease-out}
.hero h1{
  font-size:clamp(40px,7vw,72px);font-weight:900;letter-spacing:-2px;line-height:1.05;
  margin-bottom:24px;background:linear-gradient(135deg,#fff 0%,#8b8fa3 100%);
  -webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;
}
.hero h1 .accent{
  background:linear-gradient(135deg,var(--accent),var(--accent-2));
  -webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;
}
.hero p{font-size:18px;color:var(--text-dim);max-width:600px;margin:0 auto 40px;line-height:1.6}
.hero-actions{display:flex;gap:14px;justify-content:center;flex-wrap:wrap}

/* STATS */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin-top:80px}
.stat{
  background:var(--bg-2);border:1px solid var(--border);border-radius:16px;
  padding:28px;text-align:center;transition:all .3s ease;
  animation:fadeUp .8s ease-out backwards;
}
.stat:nth-child(1){animation-delay:.1s}
.stat:nth-child(2){animation-delay:.2s}
.stat:nth-child(3){animation-delay:.3s}
.stat:hover{border-color:var(--accent);transform:translateY(-4px);box-shadow:0 20px 40px rgba(0,0,0,.3)}
.stat .num{
  font-size:42px;font-weight:800;line-height:1;
  background:linear-gradient(135deg,var(--accent),var(--accent-2));
  -webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;
}
.stat .label{
  font-size:13px;color:var(--text-dim);margin-top:10px;
  text-transform:uppercase;letter-spacing:1px;font-weight:600;
}

/* AUTH */
.auth-wrapper{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.auth-card{
  width:100%;max-width:420px;background:var(--bg-2);border:1px solid var(--border);
  border-radius:20px;padding:40px;box-shadow:0 30px 80px rgba(0,0,0,.5);
  animation:fadeUp .6s ease-out;
}
.auth-card h1{font-size:28px;font-weight:800;margin-bottom:8px;letter-spacing:-.5px}
.auth-card .subtitle{color:var(--text-dim);font-size:14px;margin-bottom:28px}

/* INPUTS */
input{
  width:100%;padding:14px 18px;margin-bottom:14px;border-radius:10px;
  border:1px solid var(--border);background:var(--bg);color:var(--text);
  font-size:15px;font-family:inherit;transition:all .2s ease;
}
input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow)}
input::placeholder{color:var(--text-dim)}

/* RECHERCHE */
.search-page{max-width:1000px;margin:0 auto;padding:40px 24px}
.search-bar{position:relative;margin-bottom:32px}
.search-bar input{
  font-size:18px;padding:20px 24px 20px 56px;margin:0;border-radius:16px;background:var(--bg-2);
}
.search-bar input:focus{
  border-color:var(--accent);
  box-shadow:0 0 0 4px var(--accent-glow),0 20px 40px rgba(0,0,0,.3);
}
.search-icon{
  position:absolute;left:22px;top:50%;transform:translateY(-50%);
  font-size:20px;color:var(--text-dim);pointer-events:none;
}

/* FICHES */
.fiche{
  background:var(--bg-2);border:1px solid var(--border);border-radius:16px;
  padding:28px;margin-bottom:16px;animation:fadeUp .5s ease-out backwards;
  transition:all .3s ease;
}
.fiche:hover{border-color:var(--accent);box-shadow:0 20px 40px rgba(0,0,0,.3)}
.fiche-header{
  display:flex;justify-content:space-between;align-items:flex-start;
  margin-bottom:22px;padding-bottom:20px;border-bottom:1px solid var(--border);
  gap:20px;flex-wrap:wrap;
}
.fiche-name{font-size:22px;font-weight:800;letter-spacing:-.5px}
.fiche-sub{color:var(--text-dim);font-size:14px;margin-top:4px}
.avatar{
  width:52px;height:52px;border-radius:50%;
  background:linear-gradient(135deg,var(--accent),var(--accent-2));
  display:flex;align-items:center;justify-content:center;
  font-weight:800;font-size:20px;color:#fff;flex-shrink:0;
}
.fiche-top{display:flex;gap:16px;align-items:center}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:14px}
.field{
  background:var(--bg);border:1px solid var(--border);border-radius:10px;
  padding:12px 14px;transition:all .2s ease;
}
.field:hover{border-color:var(--accent)}
.field .label{
  font-size:10px;color:var(--text-dim);text-transform:uppercase;
  letter-spacing:1px;font-weight:700;margin-bottom:6px;
}
.field .value{font-size:14px;word-break:break-all;font-weight:500}
.field .value.empty{color:var(--text-dim);font-style:italic}
.field .value.mono{font-family:'JetBrains Mono',monospace;font-size:13px}

/* EMPTY */
.empty{text-align:center;padding:80px 20px;color:var(--text-dim);animation:fadeUp .5s ease-out}
.empty-icon{font-size:64px;margin-bottom:16px;opacity:.5}
.empty-text{font-size:16px}

/* LOADER */
.loader{
  display:inline-block;width:20px;height:20px;border:2px solid var(--border);
  border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite;
}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes fadeUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}

/* MSG */
#msg{margin:12px 0;font-size:14px;min-height:20px}
#msg.error{color:var(--danger)}
#msg.success{color:var(--success)}
.auth-footer{margin-top:20px;text-align:center;font-size:14px;color:var(--text-dim)}
.auth-footer a{color:var(--accent);text-decoration:none;font-weight:600}
.auth-footer a:hover{text-decoration:underline}
a{color:var(--accent);text-decoration:none}

::-webkit-scrollbar{width:10px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:5px}
::-webkit-scrollbar-thumb:hover{background:var(--accent)}
</style>
</head>
<body>

<!-- Vue : Accueil -->
<div id="view-home" style="display:none">
  <nav class="navbar">
    <div class="logo"><span class="logo-icon">⚡</span> FastSearch</div>
    <div class="nav-actions">
      <a href="#login" class="btn btn-ghost btn-small" data-nav="login">Connexion</a>
      <a href="#register" class="btn btn-small" data-nav="register">S'inscrire</a>
    </div>
  </nav>
  <div class="container">
    <section class="hero">
      <h1>Trouve tout,<br><span class="accent">instantanément.</span></h1>
      <p>FastSearch indexe, croise et retrouve n'importe quelle information en quelques millisecondes.</p>
      <div class="hero-actions">
        <a href="#register" class="btn" data-nav="register">Commencer gratuitement →</a>
        <a href="#login" class="btn btn-ghost" data-nav="login">J'ai déjà un compte</a>
      </div>
    </section>
    <section class="stats">
      <div class="stat">
        <div class="num" id="nbPersonnes">0</div>
        <div class="label">Fiches indexées</div>
      </div>
      <div class="stat">
        <div class="num">&lt;10ms</div>
        <div class="label">Temps de recherche</div>
      </div>
      <div class="stat">
        <div class="num">100%</div>
        <div class="label">Local & privé</div>
      </div>
    </section>
  </div>
</div>

<!-- Vue : Inscription -->
<div id="view-register" style="display:none">
  <div class="auth-wrapper">
    <div class="auth-card">
      <div class="logo" style="margin-bottom:24px"><span class="logo-icon">⚡</span> FastSearch</div>
      <h1>Créer un compte</h1>
      <p class="subtitle">Rejoins FastSearch en quelques secondes.</p>
      <form id="form-register">
        <input type="text" id="reg-username" placeholder="Nom d'utilisateur" required autofocus>
        <input type="password" id="reg-password" placeholder="Mot de passe (min 4 caractères)" required minlength="4">
        <button type="submit" style="width:100%">Créer mon compte</button>
      </form>
      <p id="msg"></p>
      <div class="auth-footer">
        Déjà un compte ? <a href="#login" data-nav="login">Se connecter</a>
      </div>
    </div>
  </div>
</div>

<!-- Vue : Connexion -->
<div id="view-login" style="display:none">
  <div class="auth-wrapper">
    <div class="auth-card">
      <div class="logo" style="margin-bottom:24px"><span class="logo-icon">⚡</span> FastSearch</div>
      <h1>Bon retour 👋</h1>
      <p class="subtitle">Connecte-toi pour accéder à la recherche.</p>
      <form id="form-login">
        <input type="text" id="log-username" placeholder="Nom d'utilisateur" required autofocus>
        <input type="password" id="log-password" placeholder="Mot de passe" required>
        <button type="submit" style="width:100%">Se connecter</button>
      </form>
      <p id="msg"></p>
      <div class="auth-footer">
        Pas de compte ? <a href="#register" data-nav="register">S'inscrire</a>
      </div>
    </div>
  </div>
</div>

<!-- Vue : Recherche -->
<div id="view-search" style="display:none">
  <nav class="navbar">
    <div class="logo"><span class="logo-icon">⚡</span> FastSearch</div>
    <div class="nav-actions">
      <span id="current-user" style="color:var(--text-dim);font-size:14px"></span>
      <button id="btn-logout" class="btn btn-ghost btn-small">Déconnexion</button>
    </div>
  </nav>
  <div class="search-page">
    <div class="search-bar">
      <span class="search-icon">🔍</span>
      <input type="text" id="q" placeholder="Rechercher par nom, prénom, email, ville..." autocomplete="off">
    </div>
    <div id="results">
      <div class="empty">
        <div class="empty-icon">⚡</div>
        <div class="empty-text">Tape une recherche pour commencer</div>
      </div>
    </div>
  </div>
</div>

<script>
// ===== ROUTEUR SPA =====
const VIEWS = ['home', 'register', 'login', 'search'];

function show(view) {
  VIEWS.forEach(v => {
    document.getElementById('view-' + v).style.display = (v === view ? 'block' : 'none');
  });
  // MAJ URL sans recharger
  if (location.hash !== '#' + view) history.replaceState(null, '', '#' + view);
  // Focus auto
  if (view === 'login') setTimeout(() => document.getElementById('log-username')?.focus(), 50);
  if (view === 'register') setTimeout(() => document.getElementById('reg-username')?.focus(), 50);
  if (view === 'search') setTimeout(() => document.getElementById('q')?.focus(), 50);
}

function navigate() {
  const hash = location.hash.replace('#', '') || 'home';
  if (!VIEWS.includes(hash)) return show('home');
  // Vérif auth pour search
  if (hash === 'search') {
    fetch('/api/me').then(r => {
      if (!r.ok) return show('login');
      return r.json().then(d => {
        document.getElementById('current-user').textContent = d.username;
        show('search');
      });
    });
    return;
  }
  show(hash);
}

window.addEventListener('hashchange', navigate);
window.addEventListener('DOMContentLoaded', () => {
  // Navigation par data-nav
  document.querySelectorAll('[data-nav]').forEach(el => {
    el.addEventListener('click', (e) => {
      e.preventDefault();
      location.hash = el.dataset.nav;
    });
  });

  // Inscription
  document.getElementById('form-register').addEventListener('submit', async (e) => {
    e.preventDefault();
    const msg = document.getElementById('msg');
    msg.textContent = ''; msg.className = '';
    const r = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: document.getElementById('reg-username').value,
        password: document.getElementById('reg-password').value,
      }),
    });
    const d = await r.json();
    if (d.success) {
      msg.textContent = '✅ Compte créé, redirection...';
      msg.className = 'success';
      setTimeout(() => location.hash = 'login', 800);
    } else {
      msg.textContent = '❌ ' + d.error;
      msg.className = 'error';
    }
  });

  // Connexion
  document.getElementById('form-login').addEventListener('submit', async (e) => {
    e.preventDefault();
    const msg = document.getElementById('msg');
    msg.textContent = ''; msg.className = '';
    const r = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: document.getElementById('log-username').value,
        password: document.getElementById('log-password').value,
      }),
    });
    const d = await r.json();
    if (d.success) {
      location.hash = 'search';
    } else {
      msg.textContent = '❌ ' + d.error;
      msg.className = 'error';
    }
  });

  // Déconnexion
  document.getElementById('btn-logout').addEventListener('click', async () => {
    await fetch('/api/logout', { method: 'POST' });
    location.hash = 'login';
  });

  // Recherche live (debounce 250ms)
  let timer = null;
  document.getElementById('q').addEventListener('input', (e) => {
    clearTimeout(timer);
    timer = setTimeout(() => search(e.target.value.trim()), 250);
  });

  // Stats accueil
  fetch('/api/stats').then(r => r.json()).then(d => {
    document.getElementById('nbPersonnes').textContent = d.personnes.toLocaleString('fr-FR');
  });

  navigate();
});

// ===== RECHERCHE =====
async function search(q) {
  const results = document.getElementById('results');
  if (!q) {
    results.innerHTML = '<div class="empty"><div class="empty-icon">⚡</div><div class="empty-text">Tape une recherche pour commencer</div></div>';
    return;
  }
  results.innerHTML = '<div class="empty"><div class="loader"></div></div>';
  try {
    const r = await fetch('/api/search?q=' + encodeURIComponent(q));
    const data = await r.json();
    if (data.length === 0) {
      results.innerHTML = '<div class="empty"><div class="empty-icon">🔎</div><div class="empty-text">Aucun résultat pour « ' + escape(q) + ' »</div></div>';
      return;
    }
    results.innerHTML = data.map((p, i) => renderFiche(p, i)).join('');
  } catch {
    results.innerHTML = '<div class="empty"><div class="empty-icon">⚠️</div><div class="empty-text">Erreur lors de la recherche</div></div>';
  }
}

function renderFiche(p, i) {
  const initiales = ((p.prenom?.[0] || '') + (p.nom?.[0] || '')).toUpperCase() || '?';
  const titre = [p.prenom, p.nom].filter(Boolean).join(' ') || 'Sans nom';
  return '<div class="fiche" style="animation-delay:' + Math.min(i * 40, 400) + 'ms">' +
    '<div class="fiche-header"><div class="fiche-top">' +
      '<div class="avatar">' + escape(initiales) + '</div>' +
      '<div><div class="fiche-name">' + escape(titre) + '</div>' +
      '<div class="fiche-sub">' + escape(p.ville || '') + (p.ville && p.code_postal ? ' · ' : '') + escape(p.code_postal || '') + '</div></div>' +
    '</div></div>' +
    '<div class="grid">' +
      field('Nom', p.nom) +
      field('Prénom', p.prenom) +
      field('Date de naissance', p.date_naissance) +
      field('Sexe', p.sexe) +
      field('Email', p.email) +
      field('Téléphone', p.telephone) +
      field('Adresse', p.adresse) +
      field('Ville', p.ville) +
      field('Code postal', p.code_postal) +
      field('Pays', p.pays) +
      field('IBAN', p.iban, 'mono') +
      field('BIC', p.bic, 'mono') +
      field('NIR', p.nir, 'mono') +
    '</div></div>';
}

function field(label, value, cls) {
  cls = cls || '';
  const v = value ? escape(value) : '<span class="empty">—</span>';
  return '<div class="field"><div class="label">' + label + '</div>' +
    '<div class="value ' + cls + (value ? '' : ' empty') + '">' + v + '</div></div>';
}

function escape(s) {
  if (s == null) return '';
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
</script>
</body>
</html>`;

app.listen(PORT, () => console.log('⚡ FastSearch → http://localhost:' + PORT));

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

const users = [];

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

app.get('/api/search', requireAuth, (req, res) => res.json([]));
app.get('/api/stats', (req, res) => res.json({ personnes: 0 }));

// ===== PAGE UNIQUE (HTML + CSS + JS) =====
const HTML = \`<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FastSearch — Search The Unsearchable</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#05060a;--bg-2:#0a0c14;--panel:rgba(15,18,28,.6);
  --border:rgba(120,180,255,.12);--border-hover:rgba(120,180,255,.35);
  --text:#e6f0ff;--text-dim:#6b7a99;
  --cyan:#00e5ff;--magenta:#ff2bd6;--green:#00ff9d;--danger:#ff3355;
  --glow-cyan:0 0 20px rgba(0,229,255,.5);
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:'Space Grotesk',system-ui,sans-serif;
  background:var(--bg);color:var(--text);min-height:100vh;
  overflow-x:hidden;-webkit-font-smoothing:antialiased;
}
.bg-layer{position:fixed;inset:0;pointer-events:none;z-index:-1}
.bg-grid{
  position:absolute;inset:0;
  background-image:
    linear-gradient(rgba(0,229,255,.06) 1px,transparent 1px),
    linear-gradient(90deg,rgba(0,229,255,.06) 1px,transparent 1px);
  background-size:50px 50px;
  mask-image:radial-gradient(ellipse 80% 60% at 50% 50%,#000 30%,transparent 100%);
  -webkit-mask-image:radial-gradient(ellipse 80% 60% at 50% 50%,#000 30%,transparent 100%);
  animation:gridMove 30s linear infinite;
}
@keyframes gridMove{from{background-position:0 0}to{background-position:50px 50px}}
.bg-halo{position:absolute;border-radius:50%;filter:blur(120px);opacity:.4}
.halo-1{width:600px;height:600px;background:var(--cyan);top:-200px;left:-200px;animation:float1 15s ease-in-out infinite}
.halo-2{width:500px;height:500px;background:var(--magenta);bottom:-150px;right:-150px;animation:float2 18s ease-in-out infinite}
.halo-3{width:400px;height:400px;background:#7c3aed;top:40%;left:50%;transform:translate(-50%,-50%);opacity:.2;animation:float3 20s ease-in-out infinite}
@keyframes float1{0%,100%{transform:translate(0,0)}50%{transform:translate(80px,60px)}}
@keyframes float2{0%,100%{transform:translate(0,0)}50%{transform:translate(-60px,-80px)}}
@keyframes float3{0%,100%{transform:translate(-50%,-50%) scale(1)}50%{transform:translate(-45%,-55%) scale(1.2)}}
.bg-scanline{
  position:absolute;left:0;right:0;height:200px;
  background:linear-gradient(to bottom,transparent 0%,rgba(0,229,255,.03) 50%,transparent 100%);
  animation:scan 8s linear infinite;
}
@keyframes scan{from{transform:translateY(-200px)}to{transform:translateY(100vh)}}
.bg-noise{
  position:absolute;inset:0;opacity:.04;
  background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
}
.navbar{
  display:flex;justify-content:space-between;align-items:center;
  padding:18px 40px;background:rgba(5,6,10,.6);
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  border-bottom:1px solid var(--border);
  position:sticky;top:0;z-index:100;
}
.logo{
  display:flex;align-items:center;gap:12px;
  font-family:'JetBrains Mono',monospace;
  font-size:16px;font-weight:700;letter-spacing:2px;
  color:var(--cyan);text-shadow:var(--glow-cyan);
}
.logo::before{
  content:'';width:10px;height:10px;border-radius:50%;
  background:var(--cyan);box-shadow:0 0 12px var(--cyan);
  animation:pulse 2s ease-in-out infinite;
}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(.8)}}
.logo-text{
  background:linear-gradient(90deg,var(--cyan),var(--magenta));
  -webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;
  background-size:200% auto;animation:shine 4s linear infinite;
}
@keyframes shine{to{background-position:200% center}}
.nav-actions{display:flex;gap:10px;align-items:center}
button,.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:12px 22px;border-radius:6px;
  border:1px solid var(--border);background:rgba(0,229,255,.05);
  color:var(--cyan);font-family:'JetBrains Mono',monospace;
  font-size:12px;font-weight:500;letter-spacing:1.5px;text-transform:uppercase;
  cursor:pointer;text-decoration:none;
  transition:all .25s cubic-bezier(.4,0,.2,1);
  position:relative;overflow:hidden;
}
button::before,.btn::before{
  content:'';position:absolute;inset:0;
  background:linear-gradient(90deg,transparent,rgba(0,229,255,.2),transparent);
  transform:translateX(-100%);transition:transform .6s ease;
}
button:hover::before,.btn:hover::before{transform:translateX(100%)}
button:hover,.btn:hover{
  border-color:var(--cyan);background:rgba(0,229,255,.1);
  box-shadow:0 0 25px rgba(0,229,255,.35);
  transform:translateY(-2px);color:#fff;
}
.btn-magenta{border-color:rgba(255,43,214,.3);background:rgba(255,43,214,.05);color:var(--magenta)}
.btn-magenta:hover{border-color:var(--magenta);background:rgba(255,43,214,.1);box-shadow:0 0 25px rgba(255,43,214,.35);color:#fff}
.btn-small{padding:9px 16px;font-size:11px}
.btn-block{width:100%}
.container{max-width:1200px;margin:0 auto;padding:0 40px}
.hero{text-align:center;padding:120px 20px 80px}
.hero-tag{
  display:inline-flex;align-items:center;gap:8px;
  padding:8px 16px;border-radius:100px;
  border:1px solid var(--border);background:rgba(0,229,255,.03);
  font-family:'JetBrains Mono',monospace;
  font-size:11px;letter-spacing:1.5px;text-transform:uppercase;
  color:var(--cyan);margin-bottom:32px;
  animation:fadeUp .6s ease-out;
}
.hero-tag::before{
  content:'';width:6px;height:6px;border-radius:50%;
  background:var(--green);box-shadow:0 0 8px var(--green);
  animation:pulse 2s ease-in-out infinite;
}
.hero h1{
  font-size:clamp(44px,8vw,96px);font-weight:700;
  letter-spacing:-3px;line-height:.95;margin-bottom:28px;
  animation:fadeUp .8s ease-out .1s backwards;
}
.hero h1 .line{display:block}
.hero h1 .grad{
  background:linear-gradient(90deg,var(--cyan) 0%,var(--magenta) 100%);
  -webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;
  background-size:200% auto;animation:shine 6s linear infinite;
}
.hero p{
  font-size:17px;color:var(--text-dim);max-width:560px;
  margin:0 auto 44px;line-height:1.7;
  animation:fadeUp .8s ease-out .2s backwards;
}
.hero p code{
  font-family:'JetBrains Mono',monospace;color:var(--cyan);font-size:14px;
  background:rgba(0,229,255,.08);padding:2px 8px;border-radius:4px;
  border:1px solid rgba(0,229,255,.15);
}
.hero-actions{display:flex;gap:14px;justify-content:center;flex-wrap:wrap;animation:fadeUp .8s ease-out .3s backwards}
.terminal{
  max-width:720px;margin:80px auto 0;
  background:var(--bg-2);border:1px solid var(--border);border-radius:12px;
  overflow:hidden;box-shadow:0 30px 80px rgba(0,0,0,.6),0 0 60px rgba(0,229,255,.05);
  animation:fadeUp .8s ease-out .4s backwards;text-align:left;
}
.terminal-bar{
  display:flex;align-items:center;gap:8px;
  padding:12px 16px;background:rgba(0,0,0,.4);border-bottom:1px solid var(--border);
}
.dot{width:12px;height:12px;border-radius:50%}
.dot-r{background:#ff5f56}.dot-y{background:#ffbd2e}.dot-g{background:#27c93f}
.terminal-title{margin-left:auto;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);letter-spacing:1px}
.terminal-body{padding:20px 24px;font-family:'JetBrains Mono',monospace;font-size:13px;line-height:2;color:var(--text-dim)}
.terminal-body .prompt{color:var(--cyan)}
.terminal-body .cmd{color:var(--text)}
.terminal-body .out{color:var(--green)}
.terminal-body .warn{color:#ffbd2e}
.cursor{
  display:inline-block;width:8px;height:14px;background:var(--cyan);
  vertical-align:middle;margin-left:2px;
  animation:blink 1s step-end infinite;box-shadow:0 0 8px var(--cyan);
}
@keyframes blink{50%{opacity:0}}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-top:60px;padding-bottom:80px}
.stat{
  position:relative;background:var(--panel);
  backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);
  border:1px solid var(--border);border-radius:10px;
  padding:28px 24px;transition:all .35s cubic-bezier(.4,0,.2,1);
  overflow:hidden;animation:fadeUp .8s ease-out backwards;
}
.stat::before{
  content:'';position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,var(--cyan),transparent);
  opacity:0;transition:opacity .3s;
}
.stat:hover::before{opacity:1}
.stat:hover{border-color:var(--border-hover);transform:translateY(-4px);box-shadow:0 20px 40px rgba(0,0,0,.4),0 0 40px rgba(0,229,255,.1)}
.stat-num{font-family:'JetBrains Mono',monospace;font-size:38px;font-weight:700;line-height:1;margin-bottom:10px;color:var(--cyan);text-shadow:var(--glow-cyan)}
.stat-label{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:2px}
.auth-wrapper{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.auth-card{
  width:100%;max-width:440px;background:var(--panel);
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  border:1px solid var(--border);border-radius:14px;
  padding:44px 40px;box-shadow:0 30px 80px rgba(0,0,0,.6),0 0 80px rgba(0,229,255,.05);
  position:relative;animation:fadeUp .6s ease-out;overflow:hidden;
}
.auth-card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),var(--magenta),transparent)}
.auth-card::after{content:'';position:absolute;bottom:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--magenta),var(--cyan),transparent)}
.auth-logo{display:flex;align-items:center;gap:10px;font-family:'JetBrains Mono',monospace;font-size:14px;font-weight:700;letter-spacing:2px;color:var(--cyan);margin-bottom:32px;text-shadow:var(--glow-cyan)}
.auth-card h1{font-size:28px;font-weight:600;letter-spacing:-.5px;margin-bottom:8px}
.auth-card .subtitle{color:var(--text-dim);font-size:14px;margin-bottom:30px;font-family:'JetBrains Mono',monospace}
.input-group{margin-bottom:16px}
.input-group label{display:block;font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:2px;margin-bottom:8px}
input{
  width:100%;padding:14px 16px;border-radius:8px;
  border:1px solid var(--border);background:rgba(0,0,0,.3);
  color:var(--text);font-size:14px;font-family:'JetBrains Mono',monospace;
  transition:all .25s ease;
}
input:focus{outline:none;border-color:var(--cyan);background:rgba(0,229,255,.03);box-shadow:0 0 0 3px rgba(0,229,255,.1),0 0 20px rgba(0,229,255,.15)}
input::placeholder{color:var(--text-dim);opacity:.5}
.search-page{max-width:1000px;margin:0 auto;padding:40px}
.search-bar{position:relative;margin-bottom:36px}
.search-bar input{font-size:16px;padding:22px 24px 22px 60px;border-radius:12px;background:rgba(0,0,0,.4);letter-spacing:.5px}
.search-bar input:focus{border-color:var(--cyan);box-shadow:0 0 0 4px rgba(0,229,255,.08),0 0 40px rgba(0,229,255,.15)}
.search-icon{position:absolute;left:24px;top:50%;transform:translateY(-50%);font-size:18px;color:var(--cyan);pointer-events:none;text-shadow:var(--glow-cyan)}
.fiche{
  background:var(--panel);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);
  border:1px solid var(--border);border-radius:12px;padding:26px;margin-bottom:14px;
  animation:fadeUp .5s ease-out backwards;transition:all .3s ease;
  position:relative;overflow:hidden;
}
.fiche::before{content:'';position:absolute;top:0;left:0;bottom:0;width:3px;background:linear-gradient(180deg,var(--cyan),var(--magenta));opacity:.6;transition:opacity .3s}
.fiche:hover{border-color:var(--border-hover);box-shadow:0 20px 50px rgba(0,0,0,.5),0 0 40px rgba(0,229,255,.08);transform:translateX(4px)}
.fiche:hover::before{opacity:1}
.fiche-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:22px;padding-bottom:20px;border-bottom:1px solid var(--border);gap:20px;flex-wrap:wrap}
.fiche-top{display:flex;gap:16px;align-items:center}
.avatar{
  width:54px;height:54px;border-radius:10px;
  background:linear-gradient(135deg,rgba(0,229,255,.15),rgba(255,43,214,.15));
  border:1px solid var(--border-hover);
  display:flex;align-items:center;justify-content:center;
  font-family:'JetBrains Mono',monospace;font-weight:700;font-size:18px;
  color:var(--cyan);flex-shrink:0;text-shadow:var(--glow-cyan);
}
.fiche-name{font-size:20px;font-weight:600;letter-spacing:-.3px}
.fiche-sub{font-family:'JetBrains Mono',monospace;color:var(--text-dim);font-size:12px;margin-top:4px;letter-spacing:.5px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}
.field{background:rgba(0,0,0,.25);border:1px solid var(--border);border-radius:8px;padding:12px 14px;transition:all .2s ease}
.field:hover{border-color:var(--border-hover);background:rgba(0,229,255,.02)}
.field .label{font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--text-dim);text-transform:uppercase;letter-spacing:1.5px;font-weight:500;margin-bottom:6px}
.field .value{font-size:13px;word-break:break-all;font-weight:500}
.field .value.empty{color:var(--text-dim);font-style:italic;opacity:.5}
.field .value.mono{font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--cyan)}
.empty{text-align:center;padding:100px 20px;color:var(--text-dim);animation:fadeUp .5s ease-out}
.empty-icon{font-size:56px;margin-bottom:20px;opacity:.4;filter:drop-shadow(0 0 20px var(--cyan))}
.empty-text{font-family:'JetBrains Mono',monospace;font-size:13px;letter-spacing:1px}
.loader{display:inline-block;width:24px;height:24px;border:2px solid var(--border);border-top-color:var(--cyan);border-radius:50%;animation:spin .8s linear infinite;box-shadow:0 0 15px rgba(0,229,255,.3)}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes fadeUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
#msg{margin:16px 0;font-size:13px;min-height:20px;font-family:'JetBrains Mono',monospace;letter-spacing:.5px}
#msg.error{color:var(--danger);text-shadow:0 0 12px rgba(255,51,85,.5)}
#msg.success{color:var(--green);text-shadow:0 0 12px rgba(0,255,157,.5)}
.auth-footer{margin-top:24px;text-align:center;font-size:13px;color:var(--text-dim);font-family:'JetBrains Mono',monospace}
.auth-footer a{color:var(--cyan);text-decoration:none;font-weight:500;transition:all .2s}
.auth-footer a:hover{text-shadow:var(--glow-cyan)}
a{color:var(--cyan);text-decoration:none}
::-webkit-scrollbar{width:10px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:linear-gradient(var(--cyan),var(--magenta));border-radius:5px}
</style>
</head>
<body>

<div class="bg-layer">
  <div class="bg-grid"></div>
  <div class="bg-halo halo-1"></div>
  <div class="bg-halo halo-2"></div>
  <div class="bg-halo halo-3"></div>
  <div class="bg-scanline"></div>
  <div class="bg-noise"></div>
</div>

<div id="view-home" style="display:none">
  <nav class="navbar">
    <div class="logo"><span class="logo-text">FASTSEARCH</span></div>
    <div class="nav-actions">
      <a href="#login" class="btn btn-small" data-nav="login">Connexion</a>
      <a href="#register" class="btn btn-magenta btn-small" data-nav="register">S'inscrire</a>
    </div>
  </nav>
  <div class="container">
    <section class="hero">
      <div class="hero-tag">System Online · v1.0</div>
      <h1>
        <span class="line">Search The</span>
        <span class="line grad">Unsearchable.</span>
      </h1>
      <p>Moteur de recherche nouvelle génération. Indexation instantanée, résultats en <code>&lt;10ms</code>, précision absolue.</p>
      <div class="hero-actions">
        <a href="#register" class="btn btn-magenta" data-nav="register">Initialiser →</a>
        <a href="#login" class="btn" data-nav="login">Accéder au système</a>
      </div>
      <div class="terminal">
        <div class="terminal-bar">
          <span class="dot dot-r"></span>
          <span class="dot dot-y"></span>
          <span class="dot dot-g"></span>
          <span class="terminal-title">fastsearch — zsh</span>
        </div>
        <div class="terminal-body">
          <div><span class="prompt">→</span> <span class="cmd">fastsearch init --mode=aggressive</span></div>
          <div><span class="out">✓</span> Index chargé · <span class="warn">0 entrées</span></div>
          <div><span class="out">✓</span> Moteur de recherche prêt</div>
          <div><span class="out">✓</span> Latence moyenne : 4.2ms</div>
          <div><span class="prompt">→</span> <span class="cmd">_</span><span class="cursor"></span></div>
        </div>
      </div>
    </section>
    <section class="stats">
      <div class="stat">
        <div class="stat-num" id="nbPersonnes">0</div>
        <div class="stat-label">Fiches indexées</div>
      </div>
      <div class="stat">
        <div class="stat-num">4.2ms</div>
        <div class="stat-label">Latence moyenne</div>
      </div>
      <div class="stat">
        <div class="stat-num">100%</div>
        <div class="stat-label">Local & privé</div>
      </div>
    </section>
  </div>
</div>

<div id="view-register" style="display:none">
  <div class="auth-wrapper">
    <div class="auth-card">
      <div class="auth-logo">⚡ FASTSEARCH</div>
      <h1>Initialisation</h1>
      <p class="subtitle">// créer un nouvel accès</p>
      <form id="form-register">
        <div class="input-group">
          <label>Identifiant</label>
          <input type="text" id="reg-username" placeholder="votre_pseudo" required autofocus>
        </div>
        <div class="input-group">
          <label>Mot de passe</label>
          <input type="password" id="reg-password" placeholder="min. 4 caractères" required minlength="4">
        </div>
        <button type="submit" class="btn-magenta btn-block" style="margin-top:8px">Créer l'accès</button>
      </form>
      <p id="msg"></p>
      <div class="auth-footer">
        Déjà enregistré ? <a href="#login" data-nav="login">Connexion →</a>
      </div>
    </div>
  </div>
</div>

<div id="view-login" style="display:none">
  <div class="auth-wrapper">
    <div class="auth-card">
      <div class="auth-logo">⚡ FASTSEARCH</div>
      <h1>Authentification</h1>
      <p class="subtitle">// accéder au système</p>
      <form id="form-login">
        <div class="input-group">
          <label>Identifiant</label>
          <input type="text" id="log-username" placeholder="votre_pseudo" required autofocus>
        </div>
        <div class="input-group">
          <label>Mot de passe</label>
          <input type="password" id="log-password" placeholder="••••••••" required>
        </div>
        <button type="submit" class="btn-block" style="margin-top:8px">Connexion</button>
      </form>
      <p id="msg"></p>
      <div class="auth-footer">
        Pas d'accès ? <a href="#register" data-nav="register">S'enregistrer →</a>
      </div>
    </div>
  </div>
</div>

<div id="view-search" style="display:none">
  <nav class="navbar">
    <div class="logo"><span class="logo-text">FASTSEARCH</span></div>
    <div class="nav-actions">
      <span id="current-user" style="color:var(--text-dim);font-size:12px;font-family:'JetBrains Mono',monospace"></span>
      <button id="btn-logout" class="btn-small">Déconnexion</button>
    </div>
  </nav>
  <div class="search-page">
    <div class="search-bar">
      <span class="search-icon">⌕</span>
      <input type="text" id="q" placeholder="Rechercher : nom, prénom, email, ville..." autocomplete="off">
    </div>
    <div id="results">
      <div class="empty">
        <div class="empty-icon">⌕</div>
        <div class="empty-text">EN ATTENTE D'UNE REQUÊTE_</div>
      </div>
    </div>
  </div>
</div>

<script>
var VIEWS = ['home','register','login','search'];

function show(view){
  VIEWS.forEach(function(v){
    document.getElementById('view-'+v).style.display = (v===view?'block':'none');
  });
  if(location.hash !== '#'+view) history.replaceState(null,'','#'+view);
  if(view==='login') setTimeout(function(){ var e=document.getElementById('log-username'); if(e) e.focus(); },50);
  if(view==='register') setTimeout(function(){ var e=document.getElementById('reg-username'); if(e) e.focus(); },50);
  if(view==='search') setTimeout(function(){ var e=document.getElementById('q'); if(e) e.focus(); },50);
}

function navigate(){
  var hash = location.hash.replace('#','') || 'home';
  if(VIEWS.indexOf(hash) === -1) return show('home');
  if(hash==='search'){
    fetch('/api/me').then(function(r){
      if(!r.ok){ show('login'); return; }
      return r.json().then(function(d){
        document.getElementById('current-user').textContent = '→ ' + d.username;
        show('search');
      });
    });
    return;
  }
  show(hash);
}

window.addEventListener('hashchange', navigate);

window.addEventListener('DOMContentLoaded', function(){
  document.querySelectorAll('[data-nav]').forEach(function(el){
    el.addEventListener('click', function(e){
      e.preventDefault();
      location.hash = el.dataset.nav;
    });
  });

  document.getElementById('form-register').addEventListener('submit', async function(e){
    e.preventDefault();
    var msg = document.getElementById('msg');
    msg.textContent=''; msg.className='';
    var r = await fetch('/api/register',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        username: document.getElementById('reg-username').value,
        password: document.getElementById('reg-password').value
      })
    });
    var d = await r.json();
    if(d.success){
      msg.textContent = '✅ Accès créé, redirection...';
      msg.className = 'success';
      setTimeout(function(){ location.hash='login'; },800);
    } else {
      msg.textContent = '❌ ' + d.error;
      msg.className = 'error';
    }
  });

  document.getElementById('form-login').addEventListener('submit', async function(e){
    e.preventDefault();
    var msg = document.getElementById('msg');
    msg.textContent=''; msg.className='';
    var r = await fetch('/api/login',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        username: document.getElementById('log-username').value,
        password: document.getElementById('log-password').value
      })
    });
    var d = await r.json();
    if(d.success){
      location.hash = 'search';
    } else {
      msg.textContent = '❌ ' + d.error;
      msg.className = 'error';
    }
  });

  document.getElementById('btn-logout').addEventListener('click', async function(){
    await fetch('/api/logout', { method: 'POST' });
    location.hash = 'login';
  });

  var timer = null;
  document.getElementById('q').addEventListener('input', function(e){
    clearTimeout(timer);
    timer = setTimeout(function(){ search(e.target.value.trim()); }, 250);
  });

  fetch('/api/stats').then(function(r){ return r.json(); }).then(function(d){
    document.getElementById('nbPersonnes').textContent = d.personnes.toLocaleString('fr-FR');
  });

  navigate();
});

async function search(q){
  var results = document.getElementById('results');
  if(!q){
    results.innerHTML = '<div class="empty"><div class="empty-icon">⌕</div><div class="empty-text">EN ATTENTE D\\'UNE REQUÊTE_</div></div>';
    return;
  }
  results.innerHTML = '<div class="empty"><div class="loader"></div></div>';
  try {
    var r = await fetch('/api/search?q=' + encodeURIComponent(q));
    var data = await r.json();
    if(data.length === 0){
      results.innerHTML = '<div class="empty"><div class="empty-icon">⌕</div><div class="empty-text">AUCUN RÉSULTAT : ' + escape(q) + '_</div></div>';
      return;
    }
    results.innerHTML = data.map(function(p,i){ return renderFiche(p,i); }).join('');
  } catch(err){
    results.innerHTML = '<div class="empty"><div class="empty-icon">⚠</div><div class="empty-text">ERREUR DE RECHERCHE_</div></div>';
  }
}

function renderFiche(p, i){
  var initiales = ((p.prenom&&p.prenom[0]||'') + (p.nom&&p.nom[0]||'')).toUpperCase() || '?';
  var titre = [p.prenom, p.nom].filter(Boolean).join(' ') || 'Sans nom';
  var delay = Math.min(i*40, 400);
  return '<div class="fiche" style="animation-delay:'+delay+'ms">' +
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

function field(label, value, cls){
  cls = cls || '';
  var v = value ? escape(value) : '<span class="empty">—</span>';
  return '<div class="field"><div class="label">' + label + '</div>' +
    '<div class="value ' + cls + (value ? '' : ' empty') + '">' + v + '</div></div>';
}

function escape(s){
  if(s == null) return '';
  return String(s).replace(/[&<>"']/g, function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}
</script>
</body>
</html>\`;

app.listen(PORT, () => console.log('⚡ FastSearch → http://localhost:' + PORT));

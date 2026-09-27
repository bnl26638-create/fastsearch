const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'fastsearch_secret_change_me';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 7, httpOnly: true },
}));

// ===== Stockage utilisateurs en mémoire =====
// (Pour un vrai projet : remplace par SQLite/Postgres)
const users = [];

const requireAuth = (req, res, next) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Non connecté' });
  next();
};

// ===== INSCRIPTION =====
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Champs manquants' });
    }
    if (username.length < 3) {
      return res.status(400).json({ error: 'Nom d\'utilisateur trop court (min 3)' });
    }
    if (password.length < 4) {
      return res.status(400).json({ error: 'Mot de passe trop court (min 4)' });
    }
    if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
      return res.status(400).json({ error: 'Nom d\'utilisateur déjà pris' });
    }

    const hash = await bcrypt.hash(password, 10);
    const user = { id: users.length + 1, username, password: hash };
    users.push(user);

    // Connexion auto après inscription
    req.session.userId = user.id;
    req.session.username = user.username;

    res.json({ success: true, username: user.username });
  } catch (err) {
    console.error('Erreur register:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ===== CONNEXION =====
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Champs manquants' });
    }

    const user = users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (!user) {
      return res.status(401).json({ error: 'Identifiants incorrects' });
    }

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      return res.status(401).json({ error: 'Identifiants incorrects' });
    }

    req.session.userId = user.id;
    req.session.username = user.username;

    res.json({ success: true, username: user.username });
  } catch (err) {
    console.error('Erreur login:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ===== DÉCONNEXION =====
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// ===== QUI SUIS-JE =====
app.get('/api/me', (req, res) => {
  if (req.session.userId) {
    return res.json({ userId: req.session.userId, username: req.session.username });
  }
  res.status(401).json({ error: 'Non connecté' });
});

// ===== RECHERCHE =====
// Pas de données pour l'instant → retourne toujours un tableau vide
// Plus tard : tu brancheras ici ta vraie BDD
app.get('/api/search', requireAuth, (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q) return res.json({ results: [], total: 0 });

  // TODO : remplacer par une vraie requête SQL
  const results = [];

  res.json({ results, total: results.length, query: q });
});

// ===== STATS =====
app.get('/api/stats', (req, res) => {
  res.json({ personnes: 0, users: users.length });
});

// ===== PAGE UNIQUE =====
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`⚡ FastSearch → http://localhost:${PORT}`);
  console.log(`   ${users.length} utilisateur(s) en mémoire`);
});

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');

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

// Sert index.html pour toutes les routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => console.log('⚡ FastSearch → http://localhost:' + PORT));

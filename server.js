const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const pool = require('./db');

const app = express();

const PORT = process.env.PORT || 3000;
const SESSION_SECRET =
  process.env.SESSION_SECRET || 'fastsearch_secret_change_me';

// ============================================================
// ADMIN
// ============================================================
const ADMIN_USERNAME = 'zk';
const isAdmin = (username) => username === ADMIN_USERNAME;

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 7,
      httpOnly: true
    }
  })
);

// ============================================================
// STOCKAGE EN MÉMOIRE
// ============================================================

const users = [];
const messages = [];
const searchHistory = [];
const sseClients = new Set();
const presenceClients = new Set();

const MESSAGE_TTL = 24 * 60 * 60 * 1000;
const MAX_MESSAGE_LENGTH = 500;
const MAX_MESSAGES = 500;
const MAX_SEARCH_HISTORY = 1000;

const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Non connecté' });
  }
  next();
};

const requireAdmin = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Non connecté' });
  }
  const user = users.find((u) => u.id === req.session.userId);
  if (!user || !isAdmin(user.username)) {
    return res.status(403).json({ error: 'Accès refusé' });
  }
  next();
};

// ============================================================
// AUTHENTIFICATION
// ============================================================

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Champs manquants' });
    }
    if (username.length < 3 && username !== ADMIN_USERNAME) {
      return res.status(400).json({ error: 'Nom trop court (min 3), sauf pour zk' });
    }
    if (password.length < 4) {
      return res.status(400).json({ error: 'Mot de passe trop court (min 4)' });
    }

    const existingUser = users.find(
      (u) => u.username.toLowerCase() === username.toLowerCase()
    );
    if (existingUser) {
      return res.status(400).json({ error: "Nom d'utilisateur déjà pris" });
    }

    const hash = await bcrypt.hash(password, 10);

    const user = {
      id: users.length + 1,
      username: username,
      password: hash,
      avatar: null,
      banned: false,
      isAdmin: isAdmin(username),
      createdAt: Date.now()
    };

    users.push(user);

    req.session.userId = user.id;
    req.session.username = user.username;

    res.json({
      success: true,
      username: user.username,
      admin: isAdmin(user.username),
      isAdmin: isAdmin(user.username)
    });
  } catch (err) {
    console.error('Erreur register:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Champs manquants' });
    }

    const user = users.find(
      (u) => u.username.toLowerCase() === username.toLowerCase()
    );

    if (!user) {
      return res.status(401).json({ error: 'Identifiants incorrects' });
    }

    if (user.banned) {
      return res.status(403).json({ error: 'Ce compte est banni' });
    }

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      return res.status(401).json({ error: 'Identifiants incorrects' });
    }

    req.session.userId = user.id;
    req.session.username = user.username;

    res.json({
      success: true,
      username: user.username,
      admin: isAdmin(user.username),
      isAdmin: isAdmin(user.username)
    });
  } catch (err) {
    console.error('Erreur login:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.get('/api/me', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Non connecté' });
  }

  const user = users.find((u) => u.id === req.session.userId);

  res.json({
    userId: req.session.userId,
    username: req.session.username,
    avatar: user ? user.avatar : null,
    admin: isAdmin(req.session.username),
    isAdmin: isAdmin(req.session.username)
  });
});

// ============================================================
// CHANGER LE MOT DE PASSE
// ============================================================

app.post('/api/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Champs manquants' });
    }
    if (newPassword.length < 4) {
      return res.status(400).json({ error: 'Nouveau mot de passe trop court (min 4)' });
    }

    const user = users.find((u) => u.id === req.session.userId);
    if (!user) {
      return res.status(404).json({ error: 'Utilisateur introuvable' });
    }

    const ok = await bcrypt.compare(currentPassword, user.password);
    if (!ok) {
      return res.status(401).json({ error: 'Mot de passe actuel incorrect' });
    }

    const hash = await bcrypt.hash(newPassword, 10);
    user.password = hash;

    res.json({ success: true });
  } catch (err) {
    console.error('Erreur change-password:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ============================================================
// AVATAR
// ============================================================

app.post('/api/avatar', requireAuth, (req, res) => {
  const { dataUrl } = req.body;

  if (!dataUrl || typeof dataUrl !== 'string') {
    return res.status(400).json({ error: 'Image manquante' });
  }
  if (!dataUrl.startsWith('data:image/')) {
    return res.status(400).json({ error: 'Format invalide' });
  }
  if (dataUrl.length > 2 * 1024 * 1024) {
    return res.status(400).json({ error: 'Image trop lourde (max ~1.5 Mo)' });
  }

  const user = users.find((u) => u.id === req.session.userId);
  if (!user) {
    return res.status(404).json({ error: 'Utilisateur introuvable' });
  }

  user.avatar = dataUrl;

  // Met à jour tous les messages existants de cet utilisateur
  messages.forEach((m) => {
    if (m.userId === user.id) m.avatar = dataUrl;
  });

  res.json({ success: true });
});

app.delete('/api/avatar', requireAuth, (req, res) => {
  const user = users.find((u) => u.id === req.session.userId);
  if (!user) {
    return res.status(404).json({ error: 'Utilisateur introuvable' });
  }
  user.avatar = null;
  messages.forEach((m) => {
    if (m.userId === user.id) m.avatar = null;
  });
  res.json({ success: true });
});

// ============================================================
// RECHERCHE POSTGRESQL
// ============================================================

app.get('/api/search', requireAuth, async (req, res) => {
  try {
    const q = (req.query.q || '').trim();

    if (!q) {
      return res.json({ results: [], total: 0, query: q });
    }

    const search = '%' + q + '%';

    const sql =
      'SELECT ' +
      'id, last_name, first_name, email, address, postal_code, city, ' +
      'birth_date, department, phone ' +
      'FROM people ' +
      'WHERE ' +
      'last_name ILIKE $1 OR first_name ILIKE $1 OR email ILIKE $1 ' +
      'OR address ILIKE $1 OR postal_code ILIKE $1 OR city ILIKE $1 ' +
      'OR birth_date ILIKE $1 OR department ILIKE $1 OR phone ILIKE $1 ' +
      'ORDER BY id LIMIT 50';

    const result = await pool.query(sql, [search]);

    // Enregistrer la recherche dans l'historique
    searchHistory.push({
      username: req.session.username,
      query: q,
      resultsCount: result.rows.length,
      timestamp: Date.now()
    });

    // Limiter la taille de l'historique
    if (searchHistory.length > MAX_SEARCH_HISTORY) {
      searchHistory.shift();
    }

    res.json({
      results: result.rows,
      total: result.rows.length,
      query: q
    });
  } catch (err) {
    console.error('Erreur recherche:', err);
    res.status(500).json({ error: 'Erreur lors de la recherche' });
  }
});

// ============================================================
// STATS
// ============================================================

app.get('/api/stats', (req, res) => {
  res.json({
    personnes: 8587,
    users: users.length,
    online: presenceClients.size
  });
});

// ============================================================
// PRÉSENCE
// ============================================================

function broadcastPresence() {
  const payload =
    'data: ' +
    JSON.stringify({ type: 'presence', count: presenceClients.size }) +
    '\n\n';

  for (const client of presenceClients) {
    try { client.res.write(payload); } catch (e) {}
  }
}

app.get('/api/presence/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const client = { res: res };
  presenceClients.add(client);

  try {
    res.write('data: ' + JSON.stringify({ type: 'presence', count: presenceClients.size }) + '\n\n');
  } catch (e) {}

  broadcastPresence();

  const hb = setInterval(() => {
    try { res.write(': ping\n\n'); } catch (e) {}
  }, 25000);

  req.on('close', () => {
    clearInterval(hb);
    presenceClients.delete(client);
    broadcastPresence();
  });
});

// ============================================================
// CHAT — NETTOYAGE
// ============================================================

function cleanupMessages() {
  const now = Date.now();
  const before = messages.length;

  for (let i = messages.length - 1; i >= 0; i--) {
    if (now - messages[i].createdAt > MESSAGE_TTL) {
      messages.splice(i, 1);
    }
  }

  if (before !== messages.length) {
    broadcastChat({ type: 'cleanup', removed: before - messages.length });
  }
}

setInterval(cleanupMessages, 60 * 1000);

// ============================================================
// CHAT — SSE
// ============================================================

function broadcastChat(event) {
  const payload = 'data: ' + JSON.stringify(event) + '\n\n';
  for (const client of sseClients) {
    try { client.res.write(payload); } catch (e) {}
  }
}

app.get('/api/chat/stream', requireAuth, (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const client = { res: res, username: req.session.username };
  sseClients.add(client);

  const hb = setInterval(() => {
    try { res.write(': ping\n\n'); } catch (e) {}
  }, 25000);

  req.on('close', () => {
    clearInterval(hb);
    sseClients.delete(client);
  });
});

// ============================================================
// CHAT — TYPING
// ============================================================

function broadcastTyping(username, isTyping) {
  const payload =
    'data: ' +
    JSON.stringify({ type: 'typing', username: username, isTyping: isTyping }) +
    '\n\n';

  for (const client of sseClients) {
    if (client.username === username) continue;
    try { client.res.write(payload); } catch (e) {}
  }
}

app.post('/api/chat/typing', requireAuth, (req, res) => {
  broadcastTyping(req.session.username, true);
  res.json({ success: true });
});

// ============================================================
// CHAT — MESSAGES
// ============================================================

app.get('/api/chat/messages', requireAuth, (req, res) => {
  cleanupMessages();

  res.json({
    messages: messages.map((m) => {
      const u = users.find((x) => x.id === m.userId);
      return {
        id: m.id,
        username: m.username,
        text: m.text,
        createdAt: m.createdAt,
        admin: isAdmin(m.username),
        avatar: u ? u.avatar : null
      };
    }),
    online: sseClients.size
  });
});

app.post('/api/chat/messages', requireAuth, (req, res) => {
  const text = (req.body.text || '').trim();

  if (!text) {
    return res.status(400).json({ error: 'Message vide' });
  }
  if (text.length > MAX_MESSAGE_LENGTH) {
    return res.status(400).json({ error: 'Message trop long (max ' + MAX_MESSAGE_LENGTH + ')' });
  }

  const me = users.find((u) => u.id === req.session.userId);

  const message = {
    id: Date.now() + '-' + Math.random().toString(36).slice(2, 8),
    userId: req.session.userId,
    username: req.session.username,
    text: text,
    createdAt: Date.now(),
    admin: isAdmin(req.session.username),
    avatar: me ? me.avatar : null
  };

  messages.push(message);
  if (messages.length > MAX_MESSAGES) messages.shift();

  broadcastChat({ type: 'message', message: message });
  broadcastTyping(req.session.username, false);

  res.json({ success: true, message: message });
});

// ============================================================
// ADMIN — STATS
// ============================================================

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const totalSearches = searchHistory.length;
  const totalUsers = users.length;
  const totalMessages = messages.length;
  const bannedUsers = users.filter((u) => u.banned).length;

  // Recherche la plus fréquente
  const compteur = {};
  searchHistory.forEach((h) => {
    const key = h.query.toLowerCase();
    compteur[key] = (compteur[key] || 0) + 1;
  });
  let topQuery = '-';
  let topCount = 0;
  for (const k in compteur) {
    if (compteur[k] > topCount) {
      topCount = compteur[k];
      topQuery = k;
    }
  }

  res.json({
    totalUsers,
    totalSearches,
    totalMessages,
    bannedUsers,
    online: presenceClients.size,
    topQuery,
    topCount
  });
});

// ============================================================
// ADMIN — LISTE DES UTILISATEURS
// ============================================================

app.get('/api/admin/users', requireAdmin, (req, res) => {
  res.json({
    users: users.map((u) => ({
      id: u.id,
      username: u.username,
      banned: u.banned || false,
      hasAvatar: !!u.avatar,
      createdAt: u.createdAt,
      admin: isAdmin(u.username),
      isAdmin: isAdmin(u.username)
    }))
  });
});

// ============================================================
// ADMIN — BANNIR / DÉBANNIR
// ============================================================

app.post('/api/admin/users/:id/ban', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const user = users.find((u) => u.id === id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  if (isAdmin(user.username)) return res.status(400).json({ error: 'Impossible de bannir le créateur' });

  user.banned = !user.banned;
  res.json({ success: true, banned: user.banned });
});

// ============================================================
// ADMIN — SUPPRIMER UN UTILISATEUR
// ============================================================

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const index = users.findIndex((u) => u.id === id);
  if (index === -1) return res.status(404).json({ error: 'Utilisateur introuvable' });
  if (isAdmin(users[index].username)) return res.status(400).json({ error: 'Impossible de supprimer le créateur' });

  users.splice(index, 1);
  res.json({ success: true });
});

// ============================================================
// ADMIN — RENOMMER UN UTILISATEUR
// ============================================================

app.post('/api/admin/users/:id/rename', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const newName = (req.body.newName || req.body.newUsername || '').trim();
  if (!newName || newName.length < 3) {
    return res.status(400).json({ error: 'Nom trop court' });
  }

  const user = users.find((u) => u.id === id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  if (isAdmin(user.username)) return res.status(400).json({ error: 'Impossible de renommer le créateur' });

  const taken = users.find(
    (u) => u.id !== id && u.username.toLowerCase() === newName.toLowerCase()
  );
  if (taken) return res.status(400).json({ error: 'Nom déjà pris' });

  user.username = newName;
  res.json({ success: true });
});

// ============================================================
// ADMIN — RESET AVATAR
// ============================================================

app.post('/api/admin/users/:id/reset-avatar', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const user = users.find((u) => u.id === id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });

  user.avatar = null;

  // Met à jour les messages en mémoire
  messages.forEach((m) => {
    if (m.userId === user.id) m.avatar = null;
  });

  res.json({ success: true });
});

// ============================================================
// ADMIN — HISTORIQUE DES RECHERCHES
// ============================================================

app.get('/api/admin/search-history', requireAdmin, (req, res) => {
  const history = searchHistory.slice().reverse();
  res.json({ history });
});

// ============================================================
// ADMIN — SUPPRIMER UN MESSAGE DU CHAT
// ============================================================

app.delete('/api/admin/chat/messages/:id', requireAdmin, (req, res) => {
  const id = req.params.id;
  const index = messages.findIndex((m) => m.id === id);
  if (index === -1) return res.status(404).json({ error: 'Message introuvable' });

  messages.splice(index, 1);
  broadcastChat({ type: 'delete', messageId: id });
  res.json({ success: true });
});

// ============================================================
// ADMIN — VIDER LE CHAT
// ============================================================

app.post('/api/admin/chat/clear', requireAdmin, (req, res) => {
  messages.length = 0;
  broadcastChat({ type: 'clear' });
  res.json({ success: true });
});

// ============================================================
// PAGE UNIQUE
// ============================================================

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ============================================================
// SERVEUR
// ============================================================

app.listen(PORT, () => {
  console.log('⚡ FastSearch → http://localhost:' + PORT);
});

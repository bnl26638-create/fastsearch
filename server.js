```js
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const pool = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'fastsearch_secret_change_me';

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 * 7,
    httpOnly: true
  },
}));

// ============================================================
// STOCKAGE EN MÉMOIRE
// ============================================================

const users = [];
const messages = [];
const sseClients = new Set();
const presenceClients = new Set();

const MESSAGE_TTL = 24 * 60 * 60 * 1000;
const MAX_MESSAGE_LENGTH = 500;
const MAX_MESSAGES = 500;

const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Non connecté' });
  }
  next();
};

// ============================================================
// AUTH
// ============================================================

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Champs manquants' });
    }

    if (username.length < 3) {
      return res.status(400).json({ error: 'Nom trop court (min 3)' });
    }

    if (password.length < 4) {
      return res.status(400).json({ error: 'Mot de passe trop court (min 4)' });
    }

    if (users.find(u =>
      u.username.toLowerCase() === username.toLowerCase()
    )) {
      return res.status(400).json({
        error: 'Nom d\'utilisateur déjà pris'
      });
    }

    const hash = await bcrypt.hash(password, 10);

    const user = {
      id: users.length + 1,
      username,
      password: hash,
      avatar: null
    };

    users.push(user);

    req.session.userId = user.id;
    req.session.username = user.username;

    res.json({
      success: true,
      username: user.username
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

    const user = users.find(u =>
      u.username.toLowerCase() === username.toLowerCase()
    );

    if (!user) {
      return res.status(401).json({
        error: 'Identifiants incorrects'
      });
    }

    const ok = await bcrypt.compare(password, user.password);

    if (!ok) {
      return res.status(401).json({
        error: 'Identifiants incorrects'
      });
    }

    req.session.userId = user.id;
    req.session.username = user.username;

    res.json({
      success: true,
      username: user.username
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
  if (req.session.userId) {
    const user = users.find(u => u.id === req.session.userId);

    return res.json({
      userId: req.session.userId,
      username: req.session.username,
      avatar: user ? user.avatar : null,
    });
  }

  res.status(401).json({
    error: 'Non connecté'
  });
});

// ============================================================
// CHANGER LE MOT DE PASSE
// ============================================================

app.post('/api/change-password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        error: 'Champs manquants'
      });
    }

    if (newPassword.length < 4) {
      return res.status(400).json({
        error: 'Nouveau mot de passe trop court (min 4)'
      });
    }

    const user = users.find(u =>
      u.id === req.session.userId
    );

    if (!user) {
      return res.status(404).json({
        error: 'Utilisateur introuvable'
      });
    }

    const ok = await bcrypt.compare(
      currentPassword,
      user.password
    );

    if (!ok) {
      return res.status(401).json({
        error: 'Mot de passe actuel incorrect'
      });
    }

    const hash = await bcrypt.hash(newPassword, 10);

    user.password = hash;

    res.json({
      success: true
    });

  } catch (err) {
    console.error('Erreur change-password:', err);
    res.status(500).json({
      error: 'Erreur serveur'
    });
  }
});

// ============================================================
// AVATAR
// ============================================================

app.post('/api/avatar', requireAuth, (req, res) => {
  const { dataUrl } = req.body;

  if (!dataUrl || typeof dataUrl !== 'string') {
    return res.status(400).json({
      error: 'Image manquante'
    });
  }

  if (!dataUrl.startsWith('data:image/')) {
    return res.status(400).json({
      error: 'Format invalide'
    });
  }

  if (dataUrl.length > 2 * 1024 * 1024) {
    return res.status(400).json({
      error: 'Image trop lourde (max ~1.5 Mo)'
    });
  }

  const user = users.find(u =>
    u.id === req.session.userId
  );

  if (!user) {
    return res.status(404).json({
      error: 'Utilisateur introuvable'
    });
  }

  user.avatar = dataUrl;

  res.json({
    success: true
  });
});

app.delete('/api/avatar', requireAuth, (req, res) => {
  const user = users.find(u =>
    u.id === req.session.userId
  );

  if (!user) {
    return res.status(404).json({
      error: 'Utilisateur introuvable'
    });
  }

  user.avatar = null;

  res.json({
    success: true
  });
});

// ============================================================
// RECHERCHE POSTGRESQL
// ============================================================

app.get('/api/search', requireAuth, async (req, res) => {
  try {
    const q = (req.query.q || '').trim();

    if (!q) {
      return res.json({
        results: [],
        total: 0,
        query: q
      });
    }

    const search = `%${q}%`;

    const result = await pool.query(
      `
      SELECT
        id,
        last_name,
        first_name,
        email,
        address,
        postal_code,
        city,
        birth_date,
        department,
        phone
      FROM people
      WHERE
        last_name ILIKE $1
        OR first_name ILIKE $1
        OR email ILIKE $1
        OR address ILIKE $1
        OR postal_code ILIKE $1
        OR city ILIKE $1
        OR birth_date ILIKE $1
        OR department ILIKE $1
        OR phone ILIKE $1
      ORDER BY id
      LIMIT 50
      `,
      [search]
    );

    res.json({
      results: result.rows,
      total: result.rows.length,
      query: q
    });

  } catch (err) {
    console.error('Erreur recherche:', err);

    res.status(500).json({
      error: 'Erreur lors de la recherche'
    });
  }
});

// ============================================================
// STATS
// ============================================================

app.get('/api/stats', (req, res) => {
  res.json({
    personnes: 8587,
    users: users.length,
    online: presenceClients.size,
  });
});

// ============================================================
// PRÉSENCE
// ============================================================

function broadcastPresence() {
  const payload =
    `data: ${JSON.stringify({
      type: 'presence',
      count: presenceClients.size
    })}\n\n`;

  for (const client of presenceClients) {
    try {
      client.res.write(payload);
    } catch (e) {}
  }
}

app.get('/api/presence/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const client = { res };

  presenceClients.add(client);

  try {
    res.write(
      `data: ${JSON.stringify({
        type: 'presence',
        count: presenceClients.size
      })}\n\n`
    );
  } catch (e) {}

  broadcastPresence();

  const hb = setInterval(() => {
    try {
      res.write(': ping\n\n');
    } catch (e) {}
  }, 25000);

  req.on('close', () => {
    clearInterval(hb);
    presenceClients.delete(client);
    broadcastPresence();
  });
});

// ============================================================
// CHAT — nettoyage
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
    broadcastChat({
      type: 'cleanup',
      removed: before - messages.length
    });
  }
}

setInterval(cleanupMessages, 60 * 1000);

// ============================================================
// CHAT — SSE
// ============================================================

function broadcastChat(event) {
  const payload =
    `data: ${JSON.stringify(event)}\n\n`;

  for (const client of sseClients) {
    try {
      client.res.write(payload);
    } catch (e) {}
  }
}

app.get('/api/chat/stream', requireAuth, (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const client = {
    res,
    username: req.session.username
  };

  sseClients.add(client);

  const hb = setInterval(() => {
    try {
      res.write(': ping\n\n');
    } catch (e) {}
  }, 25000);

  req.on('close', () => {
    clearInterval(hb);
    sseClients.delete(client);
  });
});

// ============================================================
// CHAT — typing
// ============================================================

function broadcastTyping(username, isTyping) {
  const payload =
    `data: ${JSON.stringify({
      type: 'typing',
      username,
      isTyping
    })}\n\n`;

  for (const client of sseClients) {
    if (client.username === username) continue;

    try {
      client.res.write(payload);
    } catch (e) {}
  }
}

app.post('/api/chat/typing', requireAuth, (req, res) => {
  broadcastTyping(req.session.username, true);

  res.json({
    success: true
  });
});

// ============================================================
// CHAT — messages
// ============================================================

app.get('/api/chat/messages', requireAuth, (req, res) => {
  cleanupMessages();

  res.json({
    messages: messages.map(m => ({
      id: m.id,
      username: m.username,
      text: m.text,
      createdAt: m.createdAt,
    })),
    online: sseClients.size,
  });
});

app.post('/api/chat/messages', requireAuth, (req, res) => {
  const text = (req.body.text || '').trim();

  if (!text) {
    return res.status(400).json({
      error: 'Message vide'
    });
  }

  if (text.length > MAX_MESSAGE_LENGTH) {
    return res.status(400).json({
      error: `Message trop long (max ${MAX_MESSAGE_LENGTH})`
    });
  }

  const message = {
    id:
      Date.now() +
      '-' +
      Math.random().toString(36).slice(2, 8),

    userId: req.session.userId,
    username: req.session.username,
    text,
    createdAt: Date.now(),
  };

  messages.push(message);

  if (messages.length > MAX_MESSAGES) {
    messages.shift();
  }

  broadcastChat({
    type: 'message',
    message
  });

  broadcastTyping(
    req.session.username,
    false
  );

  res.json({
    success: true,
    message
  });
});

// ============================================================
// PAGE UNIQUE
// ============================================================

app.get('*', (req, res) => {
  res.sendFile(
    path.join(__dirname, 'index.html')
  );
});

// ============================================================
// SERVEUR
// ============================================================

app.listen(PORT, () => {
  console.log(
    `⚡ FastSearch → http://localhost:${PORT}`
  );
});
```

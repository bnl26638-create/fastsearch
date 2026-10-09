const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const pool = require('./db');
const Groq = require('groq-sdk');

const app = express();

const PORT = process.env.PORT || 3000;
const SESSION_SECRET =
  process.env.SESSION_SECRET || 'fastsearch_secret_change_me';
const GROQ_API_KEY = process.env.GROQ_API_KEY || '';

// Init Groq
const groq = GROQ_API_KEY ? new Groq({ apiKey: GROQ_API_KEY }) : null;

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
const aiRateLimits = new Map(); // userId -> [timestamps]

const MESSAGE_TTL = 24 * 60 * 60 * 1000;
const MAX_MESSAGE_LENGTH = 500;
const MAX_MESSAGES = 500;
const MAX_SEARCH_HISTORY = 1000;
const MAX_SEARCH_HISTORY_PER_USER = 30;
const AI_MAX_PER_HOUR = 30;
const AI_MAX_HISTORY_TURNS = 12;
const AI_MAX_RESULTS_TO_LLM = 10;

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

// Un user est PRO si : admin (zk) OU isPro manuel
const isUserPro = (user) => {
  if (!user) return false;
  if (isAdmin(user.username)) return true;
  return user.isPro === true;
};

const requirePro = (req, res, next) => {
  const user = users.find((u) => u.id === req.session.userId);
  if (!user) {
    return res.status(401).json({ error: 'Non connecté' });
  }
  if (!isUserPro(user)) {
    return res.status(403).json({ error: 'Réservé aux abonnés PRO' });
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
    if (username.length < 3 && username.toLowerCase() !== ADMIN_USERNAME) {
      return res.status(400).json({ error: 'Nom trop court (min 3)' });
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
      isPro: isAdmin(username), // zk est PRO d'office
      createdAt: Date.now()
    };

    users.push(user);

    req.session.userId = user.id;
    req.session.username = user.username;

    res.json({
      success: true,
      username: user.username,
      admin: isAdmin(user.username),
      isAdmin: isAdmin(user.username),
      isPro: isUserPro(user)
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
      isAdmin: isAdmin(user.username),
      isPro: isUserPro(user)
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
    isAdmin: isAdmin(req.session.username),
    isPro: isUserPro(user)
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
// CHANGER LE NOM D'UTILISATEUR
// ============================================================

app.post('/api/change-username', requireAuth, (req, res) => {
  try {
    const newUsername = (req.body.newUsername || '').trim();

    if (!newUsername) {
      return res.status(400).json({ error: 'Nouveau pseudo manquant' });
    }
    if (newUsername.length < 3 && newUsername.toLowerCase() !== ADMIN_USERNAME) {
      return res.status(400).json({ error: 'Nom trop court (min 3)' });
    }
    if (newUsername.length > 24) {
      return res.status(400).json({ error: 'Nom trop long (max 24)' });
    }
    if (!/^[a-zA-Z0-9_.-]+$/.test(newUsername)) {
      return res.status(400).json({ error: 'Caractères autorisés : lettres, chiffres, _ . -' });
    }

    const user = users.find((u) => u.id === req.session.userId);
    if (!user) {
      return res.status(404).json({ error: 'Utilisateur introuvable' });
    }

    // Le créateur ne peut pas être renommé
    if (isAdmin(user.username)) {
      return res.status(400).json({ error: 'Le créateur ne peut pas être renommé' });
    }

    // Le nouveau nom est-il déjà pris (par un autre) ?
    const taken = users.find(
      (u) => u.id !== user.id && u.username.toLowerCase() === newUsername.toLowerCase()
    );
    if (taken) {
      return res.status(400).json({ error: 'Ce pseudo est déjà pris' });
    }

    if (newUsername === user.username) {
      return res.status(400).json({ error: 'C\'est déjà ton pseudo actuel' });
    }

    const oldUsername = user.username;
    user.username = newUsername;

    // Met à jour partout
    messages.forEach((m) => {
      if (m.username === oldUsername) m.username = newUsername;
    });
    searchHistory.forEach((h) => {
      if (h.username === oldUsername) h.username = newUsername;
    });
    for (const client of sseClients) {
      if (client.username === oldUsername) client.username = newUsername;
    }

    // Met à jour la session
    req.session.username = newUsername;

    res.json({ success: true, username: newUsername });
  } catch (err) {
    console.error('Erreur change-username:', err);
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
// RECHERCHE — BRIXHUB
// ============================================================

app.get('/api/search', requireAuth, async (req, res) => {
  try {
    // 1. Récupération des critères envoyés par le formulaire
    const allowedFields = {
      nom: 'nom_famille',
      prenom: 'prenom',
      ville: 'ville',
      code_postal: 'code_postal'
    };

    const criteria = {};

    for (const [formField, apiField] of Object.entries(allowedFields)) {
      const value = String(req.query[formField] || '').trim();

      if (value) {
        criteria[apiField] = value;
      }
    }

    // 2. Vérifier qu'au moins un critère a été saisi
    if (Object.keys(criteria).length === 0) {
      return res.status(400).json({
        error: 'Saisis au moins un critère de recherche.'
      });
    }

    // 3. Paramètres de pagination
    criteria.page = 1;
    criteria.per_page = 20;
    criteria.flexible = false;

    // 4. Appel de l'API BrixHub
    const response = await fetch(
      'https://api.brixhub.ru/api/v1/search',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify(criteria),
        signal: AbortSignal.timeout(15000)
      }
    );

    // 5. Lire la réponse de l'API
    const payload = await response.json().catch(() => null);
    console.log('BrixHub HTTP :', response.status);
    console.log('BrixHub réponse :', JSON.stringify(payload, null, 2));
    if (!response.ok) {
      console.error('Erreur BrixHub :', {
        status: response.status,
        message: payload?.message
      });

      return res.status(502).json({
        error: 'La recherche distante a échoué.',
        upstreamStatus: response.status,
        message: payload?.message || null
      });
    }

    // 6. Gérer la maintenance annoncée par l'API
    if (payload?.meta?.maintenance === true) {
      return res.status(503).json({
        error: 'Le service de recherche est en maintenance.',
        maintenance: true
      });
    }

    // 7. Extraire les résultats selon la structure documentée
    const results = payload?.data?.results;

    if (!Array.isArray(results)) {
      console.error('Réponse BrixHub inattendue.');

      return res.status(502).json({
        error: 'Le format de réponse du service distant est inattendu.'
      });
    }

    // 8. Enregistrer l'historique de recherche
    const query = Object.values(allowedFields)
      .map(apiField => criteria[apiField])
      .filter(Boolean)
      .join(' ');

    searchHistory.push({
      username: req.session.username,
      query,
      resultsCount: results.length,
      timestamp: Date.now()
    });

    if (searchHistory.length > MAX_SEARCH_HISTORY) {
      searchHistory.shift();
    }

    trimUserHistory(req.session.username);

    // 9. Renvoyer les résultats au formulaire
    return res.json({
      results,
      total: payload?.meta?.total ?? results.length,
      page: payload?.meta?.page ?? 1,
      pages: payload?.meta?.pages ?? 1,
      query
    });

  } catch (err) {
    console.error('Erreur /api/search :', err.message);

    if (err.name === 'TimeoutError' || err.name === 'AbortError') {
      return res.status(504).json({
        error: 'Le service distant met trop de temps à répondre.'
      });
    }

    return res.status(502).json({
      error: 'Impossible de contacter le service distant.'
    });
  }
});

function trimUserHistory(username) {
  const userIndexes = [];
  for (let i = 0; i < searchHistory.length; i++) {
    if (searchHistory[i].username === username) userIndexes.push(i);
  }
  if (userIndexes.length <= MAX_SEARCH_HISTORY_PER_USER) return;

  const toRemove = userIndexes.length - MAX_SEARCH_HISTORY_PER_USER;
  const indexesToRemove = userIndexes.slice(0, toRemove);

  for (let i = indexesToRemove.length - 1; i >= 0; i--) {
    searchHistory.splice(indexesToRemove[i], 1);
  }
}

// ============================================================
// MES RECHERCHES
// ============================================================

app.get('/api/my-searches', requireAuth, (req, res) => {
  const mine = searchHistory
    .filter((h) => h.username === req.session.username)
    .slice()
    .reverse();

  res.json({ searches: mine });
});

app.delete('/api/my-searches', requireAuth, (req, res) => {
  for (let i = searchHistory.length - 1; i >= 0; i--) {
    if (searchHistory[i].username === req.session.username) {
      searchHistory.splice(i, 1);
    }
  }
  res.json({ success: true });
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
// PRÉSENCE — compteur "en ligne" temps réel
// ============================================================

app.get('/api/presence', (req, res) => {
  res.json({ online: presenceClients.size });
});

function broadcastOnlineCount() {
  const payload =
    'data: ' +
    JSON.stringify({ type: 'online', count: presenceClients.size }) +
    '\n\n';

  for (const client of presenceClients) {
    try { client.res.write(payload); } catch (e) {}
  }
}

function broadcastPresence() {
  broadcastOnlineCount();
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
    res.write('data: ' + JSON.stringify({ type: 'online', count: presenceClients.size }) + '\n\n');
  } catch (e) {}

  broadcastOnlineCount();

  const hb = setInterval(() => {
    try { res.write(': ping\n\n'); } catch (e) {}
  }, 25000);

  req.on('close', () => {
    clearInterval(hb);
    presenceClients.delete(client);
    broadcastOnlineCount();
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
// ASSISTANT IA — GROQ (recherche réelle)
// ============================================================

const AI_SYSTEM_PROMPT = `Tu es l'Assistant IA de FastSearch, une plateforme OSINT française.

Ton rôle : aider l'utilisateur à chercher des personnes dans la base de données.
L'utilisateur te parle en français (ou anglais). Tu utilises la fonction "search_people"
pour interroger la base et tu lui réponds avec les résultats.

Champs disponibles dans la base (table "people") :
- "last_name" : nom de famille
- "first_name" : prénom
- "email" : adresse email
- "address" : adresse postale
- "postal_code" : code postal
- "city" : ville
- "birth_date" : date de naissance (format YYYY/MM/DD)
- "department" : département
- "phone" : numéro de téléphone

Règles :
1. Tu réponds TOUJOURS en français, de manière concise et professionnelle.
2. Tu ne donnes JAMAIS de conseils illégaux, tu restes dans un cadre légal (OSINT légitime).
3. Quand l'utilisateur donne des critères, tu appelles "search_people" avec UNIQUEMENT
   les champs pertinents (ex: {last_name: "Dupont", city: "Lyon"}).
4. Tu ne remplis PAS tous les champs si l'utilisateur n'en a donné que 2-3.
5. Après l'appel, tu reçois les résultats et tu les présentes à l'utilisateur sous forme
   de LISTE numérotée avec les infos clés (nom, prénom, date de naissance, ville, email, téléphone).
6. Utilise des emojis pour la lisibilité : 👤 nom, 🎂 naissance, 📍 ville, 📧 email, 📱 téléphone, 🏠 adresse.
7. Si 0 résultat, dis-le clairement et propose de reformuler.
8. Si beaucoup de résultats (>5), montre les 5 premiers et dis combien tu en as en tout.
9. Si l'utilisateur est vague (ex: "trouve Jean"), demande une précision (nom de famille ? ville ?).
10. Si la demande n'a rien à voir avec une recherche, refuse poliment.
11. Ne montre JAMAIS de données internes (id, department, etc.) sauf si l'utilisateur demande explicitement.

Exemples :

User: "trouve Jean Dupont né en 1985 à Lyon"
→ appelle search_people({first_name:"Jean", last_name:"Dupont", city:"Lyon"})
→ réponds avec la liste des résultats formatée.

User: "cherche test@test.com"
→ appelle search_people({email:"test@test.com"})
→ réponds avec les infos du profil trouvé.

User: "salut ça va"
→ réponds : "Salut ! Que cherches-tu ? Décris-moi la personne (nom, ville, email...)"

User: "trouve tous les Dupont"
→ si tu n'as pas assez d'infos, demande "Quel prénom, ville ou autre info pour préciser ?"
`;

const AI_TOOLS = [
  {
    type: 'function',
    function: {
      name: 'search_people',
      description: 'Recherche des personnes dans la base de données FastSearch. Renvoie une liste de profils correspondants.',
      parameters: {
        type: 'object',
        properties: {
          last_name: { type: 'string', description: 'Nom de famille' },
          first_name: { type: 'string', description: 'Prénom' },
          email: { type: 'string', description: 'Email' },
          address: { type: 'string', description: 'Adresse postale' },
          postal_code: { type: 'string', description: 'Code postal' },
          city: { type: 'string', description: 'Ville' },
          birth_date: { type: 'string', description: 'Date de naissance' },
          department: { type: 'string', description: 'Département' },
          phone: { type: 'string', description: 'Téléphone' }
        },
        additionalProperties: false
      }
    }
  }
];

// Exécute la recherche réelle en Postgres pour l'IA
async function runAiSearch(filters) {
  if (!filters || typeof filters !== 'object') return { rows: [], total: 0 };

  const allowed = ['last_name', 'first_name', 'email', 'address', 'postal_code', 'city', 'birth_date', 'department', 'phone'];
  const whereParts = [];
  const params = [];

  for (const key of allowed) {
    const raw = filters[key];
    if (!raw) continue;
    const value = String(raw).trim();
    if (!value) continue;
    params.push('%' + value + '%');
    whereParts.push(key + ' ILIKE $' + params.length);
  }

  if (whereParts.length === 0) {
    return { rows: [], total: 0 };
  }

  const sql =
    'SELECT id, last_name, first_name, email, address, postal_code, city, ' +
    'birth_date, department, phone ' +
    'FROM people WHERE ' + whereParts.join(' AND ') +
    ' ORDER BY id LIMIT 50';

  const result = await pool.query(sql, params);
  return { rows: result.rows, total: result.rows.length };
}

// Formate les résultats pour l'IA (payload compact)
function resultsForLlm(rows) {
  return rows.slice(0, AI_MAX_RESULTS_TO_LLM).map((r) => ({
    last_name: r.last_name || '',
    first_name: r.first_name || '',
    email: r.email || '',
    address: r.address || '',
    postal_code: r.postal_code || '',
    city: r.city || '',
    birth_date: r.birth_date || '',
    department: r.department || '',
    phone: r.phone || ''
  }));
}

function checkAiRateLimit(userId) {
  const now = Date.now();
  const oneHourAgo = now - 60 * 60 * 1000;

  let arr = aiRateLimits.get(userId) || [];
  arr = arr.filter((t) => t > oneHourAgo);

  if (arr.length >= AI_MAX_PER_HOUR) {
    aiRateLimits.set(userId, arr);
    return { ok: false, remaining: 0 };
  }

  arr.push(now);
  aiRateLimits.set(userId, arr);
  return { ok: true, remaining: AI_MAX_PER_HOUR - arr.length };
}

app.post('/api/ai/search', requireAuth, requirePro, async (req, res) => {
  try {
    if (!groq) {
      return res.status(500).json({ error: 'Assistant IA non configuré (GROQ_API_KEY manquante)' });
    }

    const history = Array.isArray(req.body.history) ? req.body.history : [];
    const message = (req.body.message || '').trim();

    if (!message) {
      return res.status(400).json({ error: 'Message vide' });
    }
    if (message.length > 2000) {
      return res.status(400).json({ error: 'Message trop long (max 2000)' });
    }

    const rl = checkAiRateLimit(req.session.userId);
    if (!rl.ok) {
      return res.status(429).json({ error: 'Limite atteinte : 30 messages / heure. Réessaie plus tard.' });
    }

    // Construction de l'historique
    const messagesForGroq = [
      { role: 'system', content: AI_SYSTEM_PROMPT }
    ];

    const trimmedHistory = history.slice(-AI_MAX_HISTORY_TURNS);
    for (const turn of trimmedHistory) {
      if (!turn || !turn.role || !turn.content) continue;
      if (turn.role !== 'user' && turn.role !== 'assistant') continue;
      messagesForGroq.push({
        role: turn.role,
        content: String(turn.content).slice(0, 2000)
      });
    }

    messagesForGroq.push({ role: 'user', content: message });

    // Première passe : l'IA décide d'appeler search_people ou pas
    const completion1 = await groq.chat.completions.create({
      model: 'openai/gpt-oss-120b',
      messages: messagesForGroq,
      tools: AI_TOOLS,
      tool_choice: 'auto',
      temperature: 0.3,
      max_tokens: 800
    });

    const choice1 = completion1.choices && completion1.choices[0];
    const msg1 = choice1 && choice1.message;

    if (!msg1) {
      return res.status(500).json({ error: 'Réponse IA invalide' });
    }

    // Si pas de tool_call → réponse directe (question de précision, refus, etc.)
    const toolCalls = Array.isArray(msg1.tool_calls) ? msg1.tool_calls : [];
    if (toolCalls.length === 0) {
      return res.json({
        success: true,
        reply: msg1.content || '',
        results: null,
        remaining: rl.remaining
      });
    }

    // Sinon, on exécute chaque search_people demandé
    const executed = [];
    for (const call of toolCalls) {
      if (!call.function) continue;
      if (call.function.name !== 'search_people') continue;
      let fargs = {};
      try { fargs = JSON.parse(call.function.arguments || '{}'); } catch (e) { fargs = {}; }

      const { rows, total } = await runAiSearch(fargs);
      executed.push({
        toolCallId: call.id,
        filters: fargs,
        rows: rows,
        total: total
      });
    }

    if (executed.length === 0) {
      // L'IA a appelé un tool inconnu → on lui dit
      return res.json({
        success: true,
        reply: msg1.content || 'Je n\'ai pas pu traiter cette demande.',
        results: null,
        remaining: rl.remaining
      });
    }

    // Enregistrement dans l'historique des recherches
    for (const exec of executed) {
      const q = Object.values(exec.filters).filter(Boolean).join(' ');
      if (!q) continue;
      searchHistory.push({
        username: req.session.username,
        query: q,
        resultsCount: exec.total,
        timestamp: Date.now()
      });
      if (searchHistory.length > MAX_SEARCH_HISTORY) searchHistory.shift();
      trimUserHistory(req.session.username);
    }

    // Construit les messages pour la 2e passe
    const messages2 = messagesForGroq.slice();
    messages2.push({
      role: 'assistant',
      content: msg1.content || '',
      tool_calls: toolCalls
    });

    let totalResults = 0;
    for (const exec of executed) {
      totalResults += exec.total;
      const payload = {
        total: exec.total,
        filters: exec.filters,
        results: resultsForLlm(exec.rows)
      };
      messages2.push({
        role: 'tool',
        tool_call_id: exec.toolCallId,
        content: JSON.stringify(payload)
      });
    }

    // Deuxième passe : l'IA rédige la réponse finale avec les résultats
    const completion2 = await groq.chat.completions.create({
      model: 'openai/gpt-oss-120b',
      messages: messages2,
      temperature: 0.4,
      max_tokens: 1200
    });

    const choice2 = completion2.choices && completion2.choices[0];
    const msg2 = choice2 && choice2.message;
    const reply = (msg2 && msg2.content) || 'Voici ce que j\'ai trouvé.';

    res.json({
      success: true,
      reply: reply,
      results: {
        total: totalResults,
        filters: executed[0].filters,
        raw: executed[0].rows
      },
      remaining: rl.remaining
    });
  } catch (err) {
    console.error('Erreur IA:', err);
    res.status(500).json({ error: 'Erreur assistant IA : ' + (err.message || 'inconnue') });
  }
});

// ============================================================
// ADMIN — STATS
// ============================================================

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const totalSearches = searchHistory.length;
  const totalUsers = users.length;
  const totalMessages = messages.length;
  const bannedUsers = users.filter((u) => u.banned).length;
  const proUsers = users.filter((u) => isUserPro(u)).length;

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
    proUsers,
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
      isAdmin: isAdmin(u.username),
      isPro: isUserPro(u)
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

  const oldName = user.username;
  user.username = newName;
  messages.forEach((m) => { if (m.username === oldName) m.username = newName; });
  searchHistory.forEach((h) => { if (h.username === oldName) h.username = newName; });

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
  messages.forEach((m) => {
    if (m.userId === user.id) m.avatar = null;
  });

  res.json({ success: true });
});

// ============================================================
// ADMIN — TOGGLE PRO
// ============================================================

app.post('/api/admin/users/:id/toggle-pro', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const user = users.find((u) => u.id === id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  if (isAdmin(user.username)) {
    return res.status(400).json({ error: 'Le créateur est PRO d\'office' });
  }

  user.isPro = !user.isPro;
  res.json({ success: true, isPro: user.isPro });
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
  if (!GROQ_API_KEY) {
    console.warn('⚠️  GROQ_API_KEY non définie : l\'assistant IA renverra une erreur.');
  } else {
    console.log('✓ Assistant IA (Groq) prêt.');
  }
});

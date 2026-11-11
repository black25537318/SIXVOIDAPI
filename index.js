const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// Carrega variáveis do .env sem depender de ferramenta externa.
const envFile = path.join(__dirname, '.env');
if (fs.existsSync(envFile)) {
  for (const line of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (match && !Object.prototype.hasOwnProperty.call(process.env, match[1])) {
      process.env[match[1]] = match[2].replace(/^(['"])(.*)\1$/, '$2');
    }
  }
}

const express = require('express');
const app = express();
const PORT = Number(process.env.PORT || 3000);
const HOST = '0.0.0.0';
const ROOT = __dirname;
const bla = ROOT;
const SECRET_DIR = path.join(ROOT, 'lib', 'secret');
const KEYS_FILE = path.join(SECRET_DIR, 'keys.json');
const USERS_FILE = path.join(SECRET_DIR, 'usuarios.json');
const METRICS_FILE = path.join(SECRET_DIR, 'metrics.json');

app.set('trust proxy', 1);
app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));
app.use(express.static(path.join(ROOT, 'public')));

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return fallback; }
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temp = `${file}.tmp`;
  fs.writeFileSync(temp, JSON.stringify(value, null, 2));
  fs.renameSync(temp, file);
}

let key = readJson(KEYS_FILE, []);
if (!Array.isArray(key)) key = [];

let users = readJson(USERS_FILE, []);
if (!Array.isArray(users)) users = [];

let metrics = readJson(METRICS_FILE, {
  totalRequests: 0,
  startedAt: new Date().toISOString()
});

if (!metrics || typeof metrics !== 'object') {
  metrics = {
    totalRequests: 0,
    startedAt: new Date().toISOString()
  };
}

if (!Number.isFinite(Number(metrics.totalRequests))) {
  metrics.totalRequests = 0;
}

const sessions = new Map();
const loginAttempts = new Map();
const SESSION_TTL = 8 * 60 * 60 * 1000;

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const OWNER_WHATSAPP = String(process.env.OWNER_WHATSAPP || '').replace(/\D/g, '');
const OWNER_INSTAGRAM = String(process.env.OWNER_INSTAGRAM || '').replace(/^@/, '').trim();

// Mercado Pago: credenciais privadas ficam somente no servidor.
const MP_ACCESS_TOKEN = String(process.env.MP_ACCESS_TOKEN || '').trim();
const MP_PUBLIC_KEY = String(process.env.MP_PUBLIC_KEY || '').trim();
const MP_WEBHOOK_SECRET = String(process.env.MP_WEBHOOK_SECRET || '').trim();
const SITE_URL = String(process.env.SITE_URL || '').trim().replace(/\/$/, '');

const ORDERS_FILE = path.join(SECRET_DIR, 'orders.json');

let orders = readJson(ORDERS_FILE, []);
if (!Array.isArray(orders)) orders = [];

const PLAN_DEFINITIONS = [
  {
    id: '1000',
    label: '1.000 requisições',
    amount: 1000,
    price: Number(process.env.PRICE_1000 || 0)
  },
  {
    id: '5000',
    label: '5.000 requisições',
    amount: 5000,
    price: Number(process.env.PRICE_5000 || 0)
  },
  {
    id: '10000',
    label: '10.000 requisições',
    amount: 10000,
    price: Number(process.env.PRICE_10000 || 0)
  },
  {
    id: '25000',
    label: '25.000 requisições',
    amount: 25000,
    price: Number(process.env.PRICE_25000 || 0)
  },
  {
    id: '50000',
    label: '50.000 requisições',
    amount: 50000,
    price: Number(process.env.PRICE_50000 || 0)
  }
];

function saveOrders() {
  writeJson(ORDERS_FILE, orders);
}

function getPlan(id) {
  return PLAN_DEFINITIONS.find(plan =>
    plan.id === String(id) &&
    Number.isFinite(plan.price) &&
    plan.price > 0
  );
}

console.log('[SIXVOID] ADMIN_PASSWORD carregada:', Boolean(ADMIN_PASSWORD));
console.log('[SIXVOID] Tamanho da senha:', ADMIN_PASSWORD.length);

function parseCookies(req) {
  const raw = req.headers.cookie || '';

  return Object.fromEntries(
    raw.split(';')
      .map(v => v.trim())
      .filter(Boolean)
      .map(v => {
        const i = v.indexOf('=');
        return i < 0
          ? [v, '']
          : [v.slice(0, i), decodeURIComponent(v.slice(i + 1))];
      })
  );
}

function isAdmin(req) {
  const token = parseCookies(req).sixvoid_admin;

  if (!token) return false;

  const session = sessions.get(token);

  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(token);
    return false;
  }

  session.expiresAt = Date.now() + SESSION_TTL;
  return true;
}

function requireAdmin(req, res, next) {
  if (!isAdmin(req)) {
    return res.status(401).json({
      success: false,
      message: 'Sessão administrativa expirada.'
    });
  }

  next();
}

function sameSecret(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));

  return aa.length === bb.length &&
    crypto.timingSafeEqual(aa, bb);
}

function saveKeys() {
  writeJson(KEYS_FILE, key);
}

function saveUsers() {
  writeJson(USERS_FILE, users);
}

function saveMetrics() {
  writeJson(METRICS_FILE, metrics);
}

// Bloqueia imediatamente qualquer chamada feita com uma credencial suspensa.
app.use((req, res, next) => {
  const apikey = req.query?.apikey;

  if (!apikey || req.path.startsWith('/api/admin/')) {
    return next();
  }

  const item = key.find(entry => entry?.apikey === apikey);

  if (item?.blocked) {
    return res.status(403).json({
      status: false,
      message: 'Esta API Key foi bloqueada pelo administrador.'
    });
  }

  next();
});

// Configuração pública: nunca envia a senha administrativa ao navegador.
app.get('/api/public/config', (req, res) => {
  res.json({
    brand: 'SIXVOID APIS',
    supportWhatsapp: OWNER_WHATSAPP,
    instagram: OWNER_INSTAGRAM,
    instagramUrl: OWNER_INSTAGRAM
      ? `https://instagram.com/${encodeURIComponent(OWNER_INSTAGRAM)}`
      : '',
    mercadoPagoPublicKey: MP_PUBLIC_KEY,
    paymentsEnabled: Boolean(MP_ACCESS_TOKEN && MP_PUBLIC_KEY),
    plans: PLAN_DEFINITIONS
      .filter(plan => Number.isFinite(plan.price) && plan.price > 0)
      .map(plan => ({
        id: plan.id,
        label: plan.label,
        amount: plan.amount,
        price: plan.price
      }))
  });
});

app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    service: 'SIXVOID APIS'
  });
});

// ==================== ADMINISTRAÇÃO ====================

app.post('/api/admin/login', (req, res) => {
  if (!ADMIN_PASSWORD) {
    return res.status(503).json({
      success: false,
      message: 'Configure ADMIN_PASSWORD na hospedagem antes de acessar o painel.'
    });
  }

  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const attempt = loginAttempts.get(ip) || {
    count: 0,
    until: 0
  };

  if (attempt.until > Date.now() && attempt.count >= 8) {
    return res.status(429).json({
      success: false,
      message: 'Muitas tentativas. Aguarde alguns minutos.'
    });
  }

  const password = req.body && req.body.password;

  if (!sameSecret(password, ADMIN_PASSWORD)) {
    attempt.count += 1;

    if (attempt.count >= 8) {
      attempt.until = Date.now() + 10 * 60 * 1000;
    }

    loginAttempts.set(ip, attempt);

    return res.status(401).json({
      success: false,
      message: 'Senha incorreta.'
    });
  }

  loginAttempts.delete(ip);

  const token = crypto.randomBytes(32).toString('hex');

  sessions.set(token, {
    expiresAt: Date.now() + SESSION_TTL
  });

  res.setHeader(
    'Set-Cookie',
    `sixvoid_admin=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL / 1000}${req.secure ? '; Secure' : ''}`
  );

  res.json({
    success: true,
    message: 'Acesso autorizado.'
  });
});

app.post('/api/admin/logout', (req, res) => {
  const token = parseCookies(req).sixvoid_admin;

  if (token) sessions.delete(token);

  res.setHeader(
    'Set-Cookie',
    'sixvoid_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' +
    (req.secure ? '; Secure' : '')
  );

  res.json({ success: true });
});

app.get('/api/admin/session', (req, res) => {
  res.json({
    authenticated: isAdmin(req)
  });
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const totalKeys = key.length;
  const activeKeys = key.filter(item =>
    Number(item?.request) > 0 && !item?.blocked
  ).length;

  const blockedKeys = key.filter(item =>
    Boolean(item?.blocked)
  ).length;

  const exhaustedKeys = key.filter(item =>
    Number(item?.request) <= 0
  ).length;

  res.json({
    success: true,
    stats: {
      totalKeys,
      activeKeys,
      exhaustedKeys,
      blockedKeys,
      requests: Number(metrics.totalRequests) || 0,
      registeredUsers: users.length
    }
  });
});

app.get('/api/admin/keys', requireAdmin, (req, res) => {
  res.json({
    success: true,
    keys: key.map(item => ({
      apikey: String(item.apikey),
      request: Number(item.request) || 0,
      blocked: Boolean(item.blocked)
    }))
  });
});

app.post('/api/admin/keys', requireAdmin, (req, res) => {
  const limit = Number(req.body?.limit);

  if (
    !Number.isSafeInteger(limit) ||
    limit < 1 ||
    limit > 1000000000
  ) {
    return res.status(400).json({
      success: false,
      message: 'Informe um limite válido entre 1 e 1.000.000.000.'
    });
  }

  let apikey;

  do {
    apikey = `sv_${crypto.randomBytes(18).toString('hex')}`;
  } while (key.some(item => item.apikey === apikey));

  key.push({
    apikey,
    request: limit,
    blocked: false
  });

  saveKeys();

  res.status(201).json({
    success: true,
    key: {
      apikey,
      request: limit
    }
  });
});

app.post('/api/admin/keys/:apikey/block', requireAdmin, (req, res) => {
  const item = key.find(entry =>
    entry.apikey === req.params.apikey
  );

  if (!item) {
    return res.status(404).json({
      success: false,
      message: 'Chave não encontrada.'
    });
  }

  item.blocked = req.body?.blocked === true;
  saveKeys();

  res.json({
    success: true,
    blocked: item.blocked
  });
});

app.delete('/api/admin/keys/:apikey', requireAdmin, (req, res) => {
  const index = key.findIndex(item =>
    item.apikey === req.params.apikey
  );

  if (index < 0) {
    return res.status(404).json({
      success: false,
      message: 'Chave não encontrada.'
    });
  }

  key.splice(index, 1);
  saveKeys();

  res.json({
    success: true,
    message: 'Chave removida.'
  });
});

app.post('/api/admin/keys/:apikey/recharge', requireAdmin, (req, res) => {
  const amount = Number(req.body?.amount);

  if (
    !Number.isSafeInteger(amount) ||
    amount < 1 ||
    amount > 1000000000
  ) {
    return res.status(400).json({
      success: false,
      message: 'Informe uma recarga válida.'
    });
  }

  const item = key.find(entry =>
    entry.apikey === req.params.apikey
  );

  if (!item) {
    return res.status(404).json({
      success: false,
      message: 'Chave não encontrada.'
    });
  }

  item.request = Math.max(0, Number(item.request) || 0) + amount;
  saveKeys();

  res.json({
    success: true,
    key: {
      apikey: item.apikey,
      request: item.request
    }
  });
});

// ==================== ROTAS PRINCIPAIS ====================

app.get('/', (req, res) => {
  res.sendFile(path.join(ROOT, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
  res.redirect('/admin.html');
});

app.get('/solicitar-key', (req, res) => {
  res.redirect('/solicitar-key.html');
});

const gerarnick = require('./lib/gerarnick.js');
const { playstore, nerding } = require('./apis/scraper.js');
const { PlayStoreSearch } = require('./lib/scraper/pesquisas.js');
const { Estadao } = require('./lib/scraper/noticias.js');
const fetch = require('node-fetch');

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  return response.json();
}

async function getBuffer(url) {
  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(`Falha ao buscar mídia: ${response.status}`);
  }

  return response.buffer();
}

async function Request(url) {
  const response = await fetch(url);
  return response.json();
}

async function listkeys(apikey, req) {
  const index = key.findIndex(item => item?.apikey === apikey);

  if (index < 0) return false;

  key[index].request = Math.max(
    0,
    (Number(key[index].request) || 0) - 2
  );

  saveKeys();

  metrics.totalRequests = (Number(metrics.totalRequests) || 0) + 1;
  metrics.lastRequestAt = new Date().toISOString();

  saveMetrics();

  const ip = String(
    req.headers['x-real-ip'] ||
    req.ip ||
    req.socket.remoteAddress ||
    'unknown'
  );

  let user = users.find(item => item.key === apikey);

  if (!user) {
    user = {
      key: apikey,
      IP: []
    };

    users.push(user);
  }

  if (!Array.isArray(user.IP)) user.IP = [];

  if (ip !== 'unknown' && !user.IP.includes(ip)) {
    user.IP.push(ip);
  }

  saveUsers();

  return true;
}

// ==================== VERIFICAÇÃO DE KEY ====================

app.get('/api/keyerrada', (req, res) => {
  apikey = req.query.apikey;

  var ITC = key.map(i => i?.apikey)?.indexOf(apikey);

  if (ITC < 0) {
    return res.json({
      key: 'Sua apikey é invalida Ou acabou as requets'
    });
  } else {
    return res.json({
      key: `Sua ApiKey está 100% ✅ - Requests Restantes: ${key[ITC]?.request}`
    });
  }
});

// Rotas antigas bloqueadas: gerenciamento agora exige sessão administrativa e POST/DELETE.
app.get('/api/add-key', (req, res) => {
  res.status(405).json({
    resultado: 'Método desativado. Use o painel administrativo autenticado.'
  });
});

app.get('/api/del-key', (req, res) => {
  res.status(405).json({
    msg: 'Método desativado. Use o painel administrativo autenticado.'
  });
});

// ==================== PLAY STORE ====================

app.get('/api/playstore', async (req, res, next) => {
  apikey = req.query.apikey;

  if (key[key.map(i => i?.apikey)?.indexOf(apikey)]?.request <= 0) {
    return res.sendFile(path.join(__dirname, './public/', 'limited.html'));
  }

  if (!apikey) {
    return res.json({
      resultado: 'Cade o parametro apikey?'
    });
  }

  if (!key.map(i => i.apikey)?.includes(apikey)) {
    return res.sendFile(path.join(__dirname, './public/', 'limited.html'));
  }

  await listkeys(apikey, req);

  nome = req.query.nome;

  if (!nome) {
    return res.json({
      status: false,
      criador: 'SANDRO BOT',
      mensagem: 'Coloque o parametro: nome'
    });
  }

  PlayStoreSearch(nome)
    .then(data => {
      res.json({
        pesquisa: data
      });
    })
    .catch(e => {
      res.json({
        msg: 'Erro no Servidor Interno'
      });
    });
});

// ==================== PLAQUINHAS ====================

app.get('/api/plaq', async (req, res, next) => {
  var textoo = req.query.texto;

  bala = await getBuffer(
    `https://umethroo.sirv.com/Torcedora-da-sele%C3%A7%C3%A3o-brasileira-nua-mostrando-a-bunda-236x300.jpg?text.0.text=${textoo}&text.0.position.x=-64%25&text.0.position.y=-39%25&text.0.size=25&text.0.color=1b1a1a&text.0.font.family=Architects%20Daughter`
  );

  res.type('jpg');
  res.send(bala);
});

app.get('/api/plaq1', async (req, res, next) => {
  var textoo = req.query.texto;

  bala = await getBuffer(
    `https://raptibef.sirv.com/images%20(1).jpeg?profile=Zanga%202.0&text.0.text=${textoo}`
  );

  res.type('jpg');
  res.send(bala);
});

app.get('/api/plaq2', async (req, res, next) => {
  var textoo = req.query.texto;

  bala = await getBuffer(
    `https://raptibef.sirv.com/images.jpeg?profile=Zanga%203.0&text.0.text=${textoo}&text.0.outline.blur=63`
  );

  res.type('jpg');
  res.send(bala);
});

app.get('/api/plaq3', async (req, res, next) => {
  var textoo = req.query.texto;

  bala = await getBuffer(
    `https://umethroo.sirv.com/peito1.jpg?text.0.text=${textoo}&text.0.position.x=-4%25&text.0.position.y=-6%25&text.0.size=14&text.0.color=000000&text.0.font.family=Shadows%20Into%20Light&text.0.font.weight=700`
  );

  res.type('jpg');
  res.send(bala);
});

app.get('/api/plaq4', async (req, res, next) => {
  var textoo = req.query.texto;

  bala = await getBuffer(
    `https://clutamac.sirv.com/1011b781-bab1-49e3-89db-ee2c064868fa%20(1).jpg?text.0.text=${textoo}&text.0.position.gravity=northwest&text.0.position.x=22%25&text.0.position.y=60%25&text.0.size=12&text.0.color=000000&text.0.opacity=47&text.0.font.family=Roboto%20Mono&text.0.font.style=italic`
  );

  res.type('jpg');
  res.send(bala);
});

app.get('/api/plaq5', async (req, res, next) => {
  var textoo = req.query.texto;

  bala = await getBuffer(
    `https://umethroo.sirv.com/Torcedora-da-sele%C3%A7%C3%A3o-brasileira-nua-mostrando-a-bunda-236x300.jpg?text.0.text=${textoo}&text.0.position.x=-64%25&text.0.position.y=-39%25&text.0.size=25&text.0.color=1b1a1a&text.0.font.family=Architects%20Daughter`
  );

  res.type('jpg');
  res.send(bala);
});

app.get('/api/plaq6', async (req, res, next) => {
  var textoo = req.query.texto;

  bala = await getBuffer(
    `https://blackzin.sirv.com/Plaq18/20220212_213215.jpg?text.0.text=${textoo}&text.0.position.gravity=northwest&text.0.position.x=43%25&text.0.position.y=18%25&text.0.size=15&text.0.color=000000&text.0.opacity=57&text.0.font.family=Vollkorn&text.0.font.weight=800&text.0.font.style=italic&text.0.background.color=000000&text.0.outline.blur=32&text.0.outline.opacity=46&text.1.text=Sandro bot%3F&text.1.position.gravity=center&text.1.position.x=10%25&text.1.position.y=30%25&text.1.size=20&text.1.color=000000&text.1.opacity=59&text.1.font.family=Playball&text.1.font.weight=700&text.1.outline.opacity=0`
  );

  res.type('jpg');
  res.send(bala);
});

app.get('/api/plaq7', async (req, res, next) => {
  var textoo = req.query.texto;

  bala = await getBuffer(
    `https://ubbornag.sirv.com/Screenshot_20210513-151821.png?text.0.text=${textoo}&text.0.position.x=-40%25&text.0.position.y=-65%25&text.0.size=30&text.0.color=000000&text.0.opacity=53&text.0.font.family=Shadows%20Into%20Light20Two&text.0.outline.blur=15`
  );

  res.type('jpg');
  res.send(bala);
});

app.get('/api/plaq8', async (req, res, next) => {
  var textoo = req.query.texto;

  bala = await getBuffer(
    `https://lculitas.sirv.com/ETw3FRnXgAI3Up_.jpg?text.0.text=${textoo}&text.0.position.gravity=center&text.0.align=left&text.0.size=46&text.0.color=221b1b&text.0.opacity=47&text.0.font.family=Architects%20Daughter&text.0.background.color=783852&text.0.background.opacity=5&text.0.outline.blur=58`
  );

  res.type('jpg');
  res.send(bala);
});

// ==================== TTP ====================

app.get('/api/ttp', async (req, res) => {
  texto = req.query.texto;

  if (!texto) {
    return res.json({
      status: false,
      msg: 'Cade o parametro texto??'
    });
  }

  apikey = req.query.apikey;

  if (key[key.map(i => i?.apikey)?.indexOf(apikey)]?.request <= 0) {
    return res.sendFile(path.join(__dirname, './public/', 'limited.html'));
  }

  if (!apikey) {
    return res.json({
      resultado: 'Cade o parametro apikey?'
    });
  }

  if (!key.map(i => i.apikey)?.includes(apikey)) {
    return res.sendFile(path.join(__dirname, './public/', 'limited.html'));
  }

  await listkeys(apikey, req);

  cor = [
    'f702ff',
    'ff0202',
    '00ff2e',
    'efff00',
    '00ecff',
    '3100ff',
    'ffb400',
    'ff00b0',
    '00ff95',
    'efff00'
  ];

  fonte = [
    'Days%20One',
    'Domine',
    'Exo',
    'Fredoka%20One',
    'Gentium%20Basic',
    'Gloria%20Hallelujah',
    'Great%20Vibes',
    'Orbitron',
    'PT%20Serif',
    'Pacifico'
  ];

  cores = cor[Math.floor(Math.random() * cor.length)];
  fontes = fonte[Math.floor(Math.random() * fonte.length)];

  sitee = `https://huratera.sirv.com/PicsArt_08-01-10.00.42.png?profile=Example-Text&text.0.text=${texto}&text.0.outline.color=000000&text.0.outline.blur=0&text.0.outline.opacity=55&text.0.color=${cores}&text.0.font.family=${fontes}&text.0.background.color=ff0000`;

  res.type('jpg');
  res.send(await getBuffer(sitee));
});

// ==================== ROTAS NSFW ====================

app.get('/nsfw/ass', async (req, res, next) => {
  apikey = req.query.apikey;

  if (key[key.map(i => i?.apikey)?.indexOf(apikey)]?.request <= 0) {
    return res.sendFile(path.join(__dirname, './public/', 'limited.html'));
  }

  if (!apikey) {
    return res.json({
      resultado: 'Cade o parametro apikey?'
    });
  }

  if (!key.map(i => i.apikey)?.includes(apikey)) {
    return res.sendFile(path.join(__dirname, './public/', 'limited.html'));
  }

  await listkeys(apikey, req);

  const ass = JSON.parse(
    fs.readFileSync(bla + '/data/ass.json')
  );

  const randass = ass[Math.floor(Math.random() * ass.length)];
  data = await fetch(randass).then(v => v.buffer());

  await fs.writeFileSync(bla + '/tmp/ass.jpeg', data);
  res.sendFile(bla + '/tmp/ass.jpeg');
});

app.get('/nsfw/cum', async (req, res, next) => {
  apikey = req.query.apikey;

  if (key[key.map(i => i?.apikey)?.indexOf(apikey)]?.request <= 0) {
    return res.sendFile(path.join(__dirname, './public/', 'limited.html'));
  }

  if (!apikey) {
    return res.json({
      resultado: 'Cade o parametro apikey?'
    });
  }

  if (!key.map(i => i.apikey)?.includes(apikey)) {
    return res.sendFile(path.join(__dirname, './public/', 'limited.html'));
  }

  await listkeys(apikey, req);

  const cum = JSON.parse(
    fs.readFileSync(bla + '/data/cum.json')
  );

  const randcum = cum[Math.floor(Math.random() * cum.length)];
  data = await fetch(randcum).then(v => v.buffer());

  await fs.writeFileSync(bla + '/tmp/cum.jpeg', data);
  res.sendFile(bla + '/tmp/cum.jpeg');
});

app.get('/nsfw/gangbang', async (req, res, next) => {
  apikey = req.query.apikey;

  if (key[key.map(i => i?.apikey)?.indexOf(apikey)]?.request <= 0) {
    return res.sendFile(path.join(__dirname, './public/', 'limited.html'));
  }

  if (!apikey) {
    return res.json({
      resultado: 'Cade o parametro apikey?'
    });
  }

  if (!key.map(i => i.apikey)?.includes(apikey)) {
    return res.sendFile(path.join(__dirname, './public/', 'limited.html'));
  }

  await listkeys(apikey, req);

  const gangbang = JSON.parse(
    fs.readFileSync(bla + '/data/gangbang.json')
  );

  const randgangbang = gangbang[
    Math.floor(Math.random() * gangbang.length)
  ];

  data = await fetch(randgangbang).then(v => v.buffer());

  await fs.writeFileSync(bla + '/tmp/gangbang.jpg', data);
  res.sendFile(bla + '/tmp/gangbang.jpg');
});

// ==================== PESQUISA XNXX ====================

app.get('/api/xnxxsearch', async (req, res, next) => {
  apikey = req.query.apikey;

  if (key[key.map(i => i?.apikey)?.indexOf(apikey)]?.request <= 0) {
    return res.sendFile(path.join(__dirname, './public/', 'limited.html'));
  }

  if (!apikey) {
    return res.json({
      resultado: 'Cade o parametro apikey?'
    });
  }

  if (!key.map(i => i.apikey)?.includes(apikey)) {
    return res.sendFile(path.join(__dirname, './public/', 'limited.html'));
  }

  await listkeys(apikey, req);

  q = req.query.q;

  if (!q) {
    return res.json({
      status: false,
      criador: 'SANDRO BOT',
      mensagem: 'Coloque o parametro: q'
    });
  }

  xnxxsearch(q)
    .then(result => {
      res.json({
        status: true,
        código: 200,
        criador: `${criador}`,
        resultado: result
      });
    })
    .catch(e => {
      res.json({
        msg: 'Erro no Servidor Interno'
      });
    });
});

// ==================== GERAR NICK ====================

app.get('/api/fazernick', async (req, res) => {
  apikey = req.query.apikey;

  if (key[key.map(i => i?.apikey)?.indexOf(apikey)]?.request <= 0) {
    return res.sendFile(path.join(__dirname, './public/', 'limited.html'));
  }

  if (!apikey) {
    return res.json({
      resultado: 'Cade o parametro apikey?'
    });
  }

  if (!key.map(i => i.apikey)?.includes(apikey)) {
    return res.sendFile(path.join(__dirname, './public/', 'limited.html'));
  }

  await listkeys(apikey, req);

  let nome = req.query.nome || res.json({
    msg: 'insira o parâmetro: ?nome='
  });

  await gerarnick(nome)
    .then(nicks => {
      res.send(nicks);
    })
    .catch(e => {
      res.json({
        erro: 'Erro no Servidor Interno'
      });
    });
});

// ==================== METADINHA ====================

app.get('/random/metadinha', async (req, res, next) => {
  apikey = req.query.apikey;

  if (key[key.map(i => i?.apikey)?.indexOf(apikey)]?.request <= 0) {
    return res.sendFile(path.join(__dirname, './public/', 'limited.html'));
  }

  if (!apikey) {
    return res.json({
      resultado: 'Cade o parametro apikey?'
    });
  }

  if (!key.map(i => i.apikey)?.includes(apikey)) {
    return res.sendFile(path.join(__dirname, './public/', 'limited.html'));
  }

  await listkeys(apikey, req);

  json = JSON.parse(
    fs.readFileSync(bla + '/lib/metadinha.json').toString()
  );

  random = json[Math.floor(Math.random() * json.length)];
  res.json(random);
});

// ==================== NERDING ====================

app.get('/api/nerding', async (req, res, next) => {
  try {
    const apikey = req.query.apikey;
    const q = req.query.q;

    if (!apikey) {
      return res.json({
        resultado: 'Cade o parametro apikey?'
      });
    }

    if (!q) {
      return res.json({
        status: false,
        criador: 'SANDRO BOT',
        mensagem: 'Coloque o parametro: q'
      });
    }

    if (!key || !Array.isArray(key)) {
      return res.json({
        erro: 'Erro no servidor: banco de keys não carregado'
      });
    }

    const keyIndex = key.findIndex(i => i?.apikey === apikey);

    if (keyIndex === -1) {
      return res.sendFile(path.join(__dirname, './public/', 'limited.html'));
    }

    if (key[keyIndex]?.request <= 0) {
      return res.sendFile(path.join(__dirname, './public/', 'limited.html'));
    }

    await listkeys(apikey, req);

    nerding(q)
      .then(resultado => {
        res.json({
          status: true,
          código: 200,
          criador: 'SANDRO BOT',
          resultado: resultado
        });
      })
      .catch(e => {
        console.error('Erro no nerding:', e);

        res.json({
          msg: 'Erro no Servidor Interno'
        });
      });

  } catch (error) {
    console.error('Erro interno:', error);

    res.json({
      msg: 'Erro no Servidor Interno'
    });
  }
});

// ==================== NOTÍCIAS ESTADÃO ====================

app.get('/api/noticias/estadao', async (req, res, next) => {
  apikey = req.query.apikey;

  if (key[key.map(i => i?.apikey)?.indexOf(apikey)]?.request <= 0) {
    return res.sendFile(path.join(__dirname, './public/', 'limited.html'));
  }

  if (!apikey) {
    return res.json({
      resultado: 'Cade o parametro apikey?'
    });
  }

  if (!key.map(i => i.apikey)?.includes(apikey)) {
    return res.sendFile(path.join(__dirname, './public/', 'limited.html'));
  }

  await listkeys(apikey, req);

  Estadao()
    .then(data => {
      res.json({
        pesquisa: data
      });
    })
    .catch(e => {
      res.json({
        msg: 'Erro no Servidor Interno'
      });
    });
});

// ==================== LOJA / MERCADO PAGO ====================

function findOrder(orderId) {
  return orders.find(order => order.id === String(orderId));
}

function generateApiKey() {
  let apikey;

  do {
    apikey = `sv_${crypto.randomBytes(18).toString('hex')}`;
  } while (key.some(item => item.apikey === apikey));

  return apikey;
}

function fulfillOrder(order) {
  if (!order || order.fulfilledAt) return order;

  const plan = getPlan(order.planId);

  if (!plan) {
    throw new Error('Plano do pedido não existe mais.');
  }

  let item = null;

  if (order.kind === 'recharge') {
    item = key.find(entry => entry.apikey === order.existingKey);

    if (!item) {
      throw new Error('A API Key informada não foi encontrada.');
    }

    item.request = Math.max(0, Number(item.request) || 0) + plan.amount;

  } else {
    const apikey = generateApiKey();

    item = {
      apikey,
      request: plan.amount,
      blocked: false
    };

    key.push(item);
  }

  saveKeys();

  order.status = 'approved';
  order.apikey = item.apikey;
  order.remaining = Number(item.request) || 0;
  order.fulfilledAt = new Date().toISOString();
  order.updatedAt = order.fulfilledAt;

  saveOrders();

  return order;
}

async function mpRequest(endpoint, options = {}) {
  if (!MP_ACCESS_TOKEN) {
    throw new Error('MP_ACCESS_TOKEN não configurado.');
  }

  const response = await fetch(
    `https://api.mercadopago.com${endpoint}`,
    {
      ...options,
      headers: {
        Authorization: `Bearer ${MP_ACCESS_TOKEN}`,
        'Content-Type': 'application/json',
        ...(options.headers || {})
      }
    }
  );

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const error = new Error(
      data.message ||
      data.error ||
      `Mercado Pago respondeu HTTP ${response.status}`
    );

    error.status = response.status;
    throw error;
  }

  return data;
}

function validWebhookSignature(req) {
  if (!MP_WEBHOOK_SECRET) return false;

  const signature = String(req.headers['x-signature'] || '');
  const requestId = String(req.headers['x-request-id'] || '');
  const dataId = String(
    req.query['data.id'] ||
    req.query.id ||
    ''
  ).toLowerCase();

  const parts = Object.fromEntries(
    signature
      .split(',')
      .map(part => part.trim().split('=').map(v => v.trim()))
  );

  if (!parts.ts || !parts.v1 || !requestId || !dataId) {
    return false;
  }

  const timestamp = Number(parts.ts);

  if (
    !Number.isFinite(timestamp) ||
    Math.abs(Date.now() - timestamp * 1000) > 5 * 60 * 1000
  ) {
    return false;
  }

  const manifest =
    `id:${dataId};request-id:${requestId};ts:${parts.ts};`;

  const expected = crypto
    .createHmac('sha256', MP_WEBHOOK_SECRET)
    .update(manifest)
    .digest('hex');

  const received = Buffer.from(parts.v1, 'hex');
  const calculated = Buffer.from(expected, 'hex');

  return received.length === calculated.length &&
    crypto.timingSafeEqual(received, calculated);
}

async function syncPayment(paymentId) {
  const payment = await mpRequest(
    `/v1/payments/${encodeURIComponent(paymentId)}`,
    {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    }
  );

  const order = findOrder(payment.external_reference);

  if (!order) return null;

  order.paymentId = String(payment.id);
  order.paymentStatus = String(payment.status || 'unknown');
  order.updatedAt = new Date().toISOString();

  if (payment.status === 'approved') {
    fulfillOrder(order);
  } else {
    order.status =
      payment.status === 'rejected' ||
      payment.status === 'cancelled'
        ? 'rejected'
        : 'pending';

    saveOrders();
  }

  return order;
}

app.get('/api/payments/plans', (req, res) => {
  res.json({
    success: true,
    enabled: Boolean(MP_ACCESS_TOKEN && MP_PUBLIC_KEY),
    publicKey: MP_PUBLIC_KEY,
    plans: PLAN_DEFINITIONS
      .filter(plan => Number.isFinite(plan.price) && plan.price > 0)
      .map(plan => ({
        id: plan.id,
        label: plan.label,
        amount: plan.amount,
        price: plan.price
      }))
  });
});

// ==================== CRIAR PEDIDO ====================

app.post('/api/payments/orders', (req, res) => {
  try {
    if (!MP_ACCESS_TOKEN || !MP_PUBLIC_KEY) {
      return res.status(503).json({
        success: false,
        message: 'Pagamentos ainda não estão configurados.'
      });
    }

    const kind = req.body?.kind === 'recharge'
      ? 'recharge'
      : 'new';

    const name = String(req.body?.name || '')
      .trim()
      .slice(0, 70);

    const email = String(req.body?.email || '')
      .trim()
      .toLowerCase()
      .slice(0, 120);

    const plan = getPlan(req.body?.planId);

    if (!name) {
      return res.status(400).json({
        success: false,
        message: 'Informe seu nome.'
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Informe um e-mail válido.'
      });
    }

    if (!plan) {
      return res.status(400).json({
        success: false,
        message: 'Plano indisponível. Consulte os planos ativos.'
      });
    }

    let existingKey = '';

    if (kind === 'recharge') {
      existingKey = String(req.body?.apiKey || '').trim();

      const found = key.find(entry =>
        entry.apikey === existingKey
      );

      if (!found) {
        return res.status(404).json({
          success: false,
          message: 'API Key não encontrada. Confira a chave digitada.'
        });
      }

      if (found.blocked) {
        return res.status(403).json({
          success: false,
          message: 'Esta API Key está bloqueada e não pode ser recarregada.'
        });
      }
    }

    const id = crypto.randomBytes(18).toString('hex');

    const order = {
      id,
      kind,
      name,
      email,
      planId: plan.id,
      price: Number(plan.price.toFixed(2)),
      existingKey,
      status: 'created',
      paymentStatus: 'not_created',
      createdAt: new Date().toISOString()
    };

    orders.push(order);
    saveOrders();

    res.status(201).json({
      success: true,
      orderId: id,
      amount: order.price,
      publicKey: MP_PUBLIC_KEY,
      description:
        `${kind === 'recharge' ? 'Recarga' : 'Nova API Key'} SIXVOID - ${plan.label}`
    });

  } catch (error) {
    console.error(
      '[SIXVOID] Erro ao criar pedido:',
      error.message
    );

    res.status(500).json({
      success: false,
      message: 'Não foi possível criar o pedido.'
    });
  }
});

// ==================== PROCESSAR PAGAMENTO ====================

app.post('/api/payments/process', async (req, res) => {
  try {
    const order = findOrder(req.body?.orderId);

    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Pedido não encontrado.'
      });
    }

    if (order.fulfilledAt) {
      return res.json({
        success: true,
        status: 'approved',
        apikey: order.apikey,
        remaining: order.remaining
      });
    }

    if (order.paymentId) {
      return res.json({
        success: true,
        status: order.status,
        paymentId: order.paymentId
      });
    }

    if (order.paymentProcessing) {
      return res.status(409).json({
        success: false,
        message: 'Pagamento já está sendo processado. Aguarde.'
      });
    }

    const form = req.body?.formData || {};

    const method = String(
      form.payment_method_id || ''
    ).trim();

    const payerEmail = String(
      form.payer?.email || order.email
    ).trim().toLowerCase();

    if (!method) {
      return res.status(400).json({
        success: false,
        message: 'Método de pagamento não informado.'
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(payerEmail)) {
      return res.status(400).json({
        success: false,
        message: 'E-mail do pagador inválido.'
      });
    }

    if (method !== 'pix' && !String(form.token || '').trim()) {
      return res.status(400).json({
        success: false,
        message: 'Token do cartão não informado.'
      });
    }

    const plan = getPlan(order.planId);

    if (!plan) {
      return res.status(400).json({
        success: false,
        message: 'Plano indisponível.'
      });
    }

    order.paymentProcessing = true;
    saveOrders();

    const payload = {
      transaction_amount: Number(order.price),
      description:
        `${order.kind === 'recharge' ? 'Recarga' : 'Nova API Key'} SIXVOID - ${plan.label}`,
      payment_method_id: method,
      payer: {
        email: payerEmail
      },
      external_reference: order.id,
      notification_url: SITE_URL
        ? `${SITE_URL}/api/payments/webhook`
        : undefined
    };

    if (form.token) payload.token = form.token;
    if (form.installments) {
      payload.installments = Number(form.installments);
    }

    if (form.issuer_id) {
      payload.issuer_id = form.issuer_id;
    }

    if (
      form.payer?.identification?.type &&
      form.payer?.identification?.number
    ) {
      payload.payer.identification = {
        type: String(form.payer.identification.type),
        number: String(form.payer.identification.number)
      };
    }

    const payment = await mpRequest(
      '/v1/payments',
      {
        method: 'POST',
        headers: {
          'X-Idempotency-Key': order.id
        },
        body: JSON.stringify(payload)
      }
    );

    order.paymentProcessing = false;
    order.paymentId = String(payment.id);
    order.paymentStatus = String(payment.status || 'pending');
    order.updatedAt = new Date().toISOString();

    if (payment.status === 'approved') {
      fulfillOrder(order);

      return res.json({
        success: true,
        status: 'approved',
        apikey: order.apikey,
        remaining: order.remaining
      });
    }

    order.status = payment.status === 'rejected'
      ? 'rejected'
      : 'pending';

    saveOrders();

    const transaction =
      payment.point_of_interaction?.transaction_data || {};

    res.json({
      success: true,
      status: order.status,
      paymentId: order.paymentId,
      paymentMethod: method,

      pix: method === 'pix'
        ? {
            qrCode: transaction.qr_code || '',
            qrCodeBase64: transaction.qr_code_base64 || '',
            ticketUrl: transaction.ticket_url || ''
          }
        : null,

      message:
        payment.status_detail ||
        'Aguardando confirmação do pagamento.'
    });

  } catch (error) {
    const order = findOrder(req.body?.orderId);

    if (order) {
      order.paymentProcessing = false;
      saveOrders();
    }

    console.error(
      '[SIXVOID] Erro no pagamento:',
      error.message
    );

    res.status(error.status || 500).json({
      success: false,
      message: error.message || 'Falha ao processar pagamento.'
    });
  }
});

// ==================== CONSULTAR PEDIDO ====================

app.get('/api/payments/orders/:id', async (req, res) => {
  try {
    const order = findOrder(req.params.id);

    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Pedido não encontrado.'
      });
    }

    if (
      order.paymentId &&
      !order.fulfilledAt &&
      order.status !== 'rejected'
    ) {
      await syncPayment(order.paymentId);
    }

    const fresh = findOrder(req.params.id);

    res.json({
      success: true,
      status: fresh.status,
      paymentStatus: fresh.paymentStatus,
      apikey: fresh.fulfilledAt
        ? fresh.apikey
        : undefined,
      remaining: fresh.fulfilledAt
        ? fresh.remaining
        : undefined
    });

  } catch (error) {
    console.error(
      '[SIXVOID] Erro ao consultar pedido:',
      error.message
    );

    res.status(502).json({
      success: false,
      message: 'Não foi possível consultar o pagamento agora.'
    });
  }
});

// ==================== WEBHOOK MERCADO PAGO ====================

app.post('/api/payments/webhook', async (req, res) => {
  try {
    if (!MP_WEBHOOK_SECRET || !validWebhookSignature(req)) {
      return res.status(401).send('Assinatura inválida.');
    }

    const type = String(
      req.query.type || req.body?.type || ''
    );

    const paymentId = String(
      req.query['data.id'] ||
      req.body?.data?.id ||
      ''
    );

    if (type === 'payment' && paymentId) {
      await syncPayment(paymentId);
    }

    return res.sendStatus(200);

  } catch (error) {
    console.error(
      '[SIXVOID] Erro no webhook:',
      error.message
    );

    return res.sendStatus(500);
  }
});

// ==================== INICIAR SERVIDOR ====================

app.listen(PORT, HOST, () => {
  console.log(`SIXVOID APIS online em http://${HOST}:${PORT}`);

  if (!ADMIN_PASSWORD) {
    console.warn(
      'ATENÇÃO: defina ADMIN_PASSWORD nas variáveis de ambiente para habilitar o painel.'
    );
  }
});


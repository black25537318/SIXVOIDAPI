
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// Carrega variáveis do .env
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
const ORDERS_FILE = path.join(SECRET_DIR, 'orders.json');
const ACCOUNTS_FILE = path.join(SECRET_DIR, 'contas.json');
const USER_SESSIONS_FILE = path.join(SECRET_DIR, 'sessoes-site.json');

app.set('trust proxy', 1);
app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));

// ==========================================
// CONTAS DO SITE SIXVOID (CADASTRO ABERTO)
// ==========================================

const USER_SESSION_TTL = 30 * 24 * 60 * 60 * 1000;
let siteAccounts = readJson(ACCOUNTS_FILE, []);
if (!Array.isArray(siteAccounts)) siteAccounts = [];
let userSessions = readJson(USER_SESSIONS_FILE, {});
if (!userSessions || typeof userSessions !== 'object' || Array.isArray(userSessions)) userSessions = {};
const userLoginAttempts = new Map();

function saveSiteAccounts() {
  writeJson(ACCOUNTS_FILE, siteAccounts);
}

function saveUserSessions() {
  writeJson(USER_SESSIONS_FILE, userSessions);
}

function cleanExpiredUserSessions() {
  let changed = false;
  for (const [token, session] of Object.entries(userSessions)) {
    if (!session || Number(session.expiresAt) <= Date.now()) {
      delete userSessions[token];
      changed = true;
    }
  }
  if (changed) saveUserSessions();
}
cleanExpiredUserSessions();

function getSiteSession(req) {
  const token = parseCookies(req).sixvoid_user;
  if (!token) return null;
  const session = userSessions[hashToken(token)];
  if (!session || Number(session.expiresAt) <= Date.now()) {
    if (session) {
      delete userSessions[hashToken(token)];
      saveUserSessions();
    }
    return null;
  }
  const account = siteAccounts.find(item => item.id === session.userId);
  if (!account) return null;
  return { token, session, account };
}

function requireSitePage(req, res, next) {
  if (!getSiteSession(req)) {
    const nextPath = encodeURIComponent(req.originalUrl || '/');
    return res.redirect(`/login.html?next=${nextPath}`);
  }
  next();
}

function hashPassword(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(String(password), salt, 64, (error, derivedKey) => {
      if (error) return reject(error);
      resolve(derivedKey.toString('hex'));
    });
  });
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || '').trim());
}

function setUserCookie(res, token, req) {
  res.setHeader('Set-Cookie', `sixvoid_user=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${USER_SESSION_TTL / 1000}${req.secure ? '; Secure' : ''}`);
}

function clearUserCookie(res, req) {
  res.setHeader('Set-Cookie', `sixvoid_user=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${req.secure ? '; Secure' : ''}`);
}

app.post('/api/auth/register', async (req, res) => {
  try {
    const name = String(req.body?.name || '').trim().slice(0, 60);
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');

    if (name.length < 2) return res.status(400).json({ success: false, message: 'Informe seu nome.' });
    if (!validEmail(email)) return res.status(400).json({ success: false, message: 'Informe um e-mail válido.' });
    if (password.length < 8 || password.length > 128) return res.status(400).json({ success: false, message: 'A senha deve ter entre 8 e 128 caracteres.' });
    if (siteAccounts.some(item => item.email === email)) return res.status(409).json({ success: false, message: 'Este e-mail já possui uma conta. Faça login.' });

    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = await hashPassword(password, salt);
    const account = {
      id: crypto.randomUUID(),
      name,
      email,
      passwordSalt: salt,
      passwordHash,
      createdAt: new Date().toISOString()
    };
    siteAccounts.push(account);
    saveSiteAccounts();

    const token = crypto.randomBytes(32).toString('hex');
    userSessions[hashToken(token)] = { userId: account.id, expiresAt: Date.now() + USER_SESSION_TTL };
    saveUserSessions();
    setUserCookie(res, token, req);

    return res.status(201).json({ success: true, message: 'Conta criada com sucesso.', user: { id: account.id, name: account.name, email: account.email } });
  } catch (error) {
    console.error('[SITE REGISTER]', error);
    return res.status(500).json({ success: false, message: 'Não foi possível criar sua conta.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const attempt = userLoginAttempts.get(ip) || { count: 0, until: 0 };
    if (attempt.until > Date.now() && attempt.count >= 8) {
      return res.status(429).json({ success: false, message: 'Muitas tentativas. Aguarde 10 minutos.' });
    }

    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const account = siteAccounts.find(item => item.email === email);
    let valid = false;
    if (account && account.passwordSalt && account.passwordHash) {
      const calculated = await hashPassword(password, account.passwordSalt);
      valid = sameSecret(calculated, account.passwordHash);
    }

    if (!valid) {
      attempt.count += 1;
      if (attempt.count >= 8) attempt.until = Date.now() + 10 * 60 * 1000;
      userLoginAttempts.set(ip, attempt);
      return res.status(401).json({ success: false, message: 'E-mail ou senha incorretos.' });
    }

    userLoginAttempts.delete(ip);
    const token = crypto.randomBytes(32).toString('hex');
    userSessions[hashToken(token)] = { userId: account.id, expiresAt: Date.now() + USER_SESSION_TTL };
    saveUserSessions();
    setUserCookie(res, token, req);
    return res.json({ success: true, message: 'Login realizado com sucesso.', user: { id: account.id, name: account.name, email: account.email } });
  } catch (error) {
    console.error('[SITE LOGIN]', error);
    return res.status(500).json({ success: false, message: 'Não foi possível entrar na sua conta.' });
  }
});

app.get('/api/auth/me', (req, res) => {
  const auth = getSiteSession(req);
  if (!auth) return res.status(401).json({ authenticated: false });
  auth.session.expiresAt = Date.now() + USER_SESSION_TTL;
  saveUserSessions();
  res.json({ authenticated: true, user: { id: auth.account.id, name: auth.account.name, email: auth.account.email } });
});

app.post('/api/auth/logout', (req, res) => {
  const token = parseCookies(req).sixvoid_user;
  if (token && userSessions[hashToken(token)]) {
    delete userSessions[hashToken(token)];
    saveUserSessions();
  }
  clearUserCookie(res, req);
  res.json({ success: true });
});

// Protege somente as páginas de membros. Solicitar Key, admin, login e APIs continuam públicos.
app.use((req, res, next) => {
  const protectedPages = new Set(['/', '/index.html', '/docs.html']);
  if (!protectedPages.has(req.path)) return next();
  return requireSitePage(req, res, next);
});

app.get('/login', (req, res) => res.redirect('/login.html'));
app.use(express.static(path.join(ROOT, 'public')));

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
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
  metrics = { totalRequests: 0, startedAt: new Date().toISOString() };
}

if (!Number.isFinite(Number(metrics.totalRequests))) {
  metrics.totalRequests = 0;
}

let orders = readJson(ORDERS_FILE, []);
if (!Array.isArray(orders)) orders = [];

const sessions = new Map();
const loginAttempts = new Map();

const SESSION_TTL = 8 * 60 * 60 * 1000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';

const OWNER_WHATSAPP = String(process.env.OWNER_WHATSAPP || '').replace(/\D/g, '');
const OWNER_INSTAGRAM = String(process.env.OWNER_INSTAGRAM || '').replace(/^@/, '').trim();

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

  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
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

function saveOrders() {
  writeJson(ORDERS_FILE, orders);
}

function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

function publicOrder(order) {
  const result = {
    id: order.id,
    type: order.type,
    status: order.status,
    name: order.name,
    customerName: order.name,
    email: order.email,
    planId: order.planId,
    planLabel: order.planLabel,
    planName: order.planLabel,
    requests: order.requests,
    price: order.price,
    keyName: order.keyName || '',
    createdAt: order.createdAt,
    updatedAt: order.updatedAt || null
  };

  if (order.status === 'approved' && order.apikey) {
    result.apikey = order.apikey;
  }

  if (order.status === 'rejected') {
    result.reason = order.reason || 'Pedido recusado pelo administrador.';
  }

  return result;
}

// Bloqueia chamadas feitas com credenciais suspensas.
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

// ==========================================
// PLANOS SIXVOID APIS
// ==========================================

const PLAN_DEFINITIONS = [
  { id: '1000', label: '1.000 requisições', amount: 1000, price: 1 },
  { id: '5000', label: '5.000 requisições', amount: 5000, price: 2 },
  { id: '10000', label: '10.000 requisições', amount: 10000, price: 3 },
  { id: '20000', label: '20.000 requisições', amount: 20000, price: 4 },
  { id: '30000', label: '30.000 requisições', amount: 30000, price: 5 },
  { id: '40000', label: '40.000 requisições', amount: 40000, price: 6 },
  { id: '50000', label: '50.000 requisições', amount: 50000, price: 8 },
  { id: '75000', label: '75.000 requisições', amount: 75000, price: 11 },
  { id: '100000', label: '100.000 requisições', amount: 100000, price: 15 },
  { id: '150000', label: '150.000 requisições', amount: 150000, price: 22 },
  { id: '200000', label: '200.000 requisições', amount: 200000, price: 27 },
  { id: '250000', label: '250.000 requisições', amount: 250000, price: 30 },
  { id: '300000', label: '300.000 requisições', amount: 300000, price: 36 },
  { id: '400000', label: '400.000 requisições', amount: 400000, price: 44 },
  { id: '500000', label: '500.000 requisições', amount: 500000, price: 50 },
  { id: '600000', label: '600.000 requisições', amount: 600000, price: 58 },
  { id: '700000', label: '700.000 requisições', amount: 700000, price: 65 },
  { id: '800000', label: '800.000 requisições', amount: 800000, price: 70 },
  { id: '900000', label: '900.000 requisições', amount: 900000, price: 75 },
  { id: '1000000', label: '1.000.000 requisições', amount: 1000000, price: 80 }
].map(plan => ({
  ...plan,
  price: Number(process.env[`PRICE_${plan.id}`] || plan.price)
}));

app.get('/api/plans', (req, res) => {
  res.json({
    success: true,
    plans: PLAN_DEFINITIONS.map(plan => ({
      id: plan.id,
      label: plan.label,
      requests: plan.amount,
      price: plan.price,
      formattedPrice: `R$ ${plan.price.toFixed(2).replace('.', ',')}`
    }))
  });
});

// ==========================================
// PIX MANUAL - CONFIGURAÇÃO PÚBLICA
// ==========================================


const PIX_KEY = 'fellipycaua26@gmail.com';
const PIX_NAME = 'Cauã Fellipy Carvalho dos Santos';

app.get('/api/payments/plans', (req, res) => {
  res.json({
    success: true,
    enabled: true,
    pix: {
      key: PIX_KEY,
      name: PIX_NAME,
      type: 'E-mail'
    },
    plans: PLAN_DEFINITIONS.map(plan => ({
      id: plan.id,
      label: plan.label,
      requests: plan.amount,
      price: Number(plan.price)
    }))
  });
});


// ==========================================
// CRIAR PEDIDO DE COMPRA
// ==========================================

app.post('/api/payments/orders', (req, res) => {
  try {
    const {
      type,
      name,
      email,
      keyName,
      apiKey,
      planId
    } = req.body || {};

    if (!['new', 'recharge'].includes(type)) {
      return res.status(400).json({
        success: false,
        message: 'Tipo de pedido inválido.'
      });
    }

    if (!name || String(name).trim().length < 2) {
      return res.status(400).json({
        success: false,
        message: 'Informe seu nome.'
      });
    }

    if (
      !email ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email).trim())
    ) {
      return res.status(400).json({
        success: false,
        message: 'Informe um e-mail válido.'
      });
    }

    const plan = PLAN_DEFINITIONS.find(item => item.id === String(planId));

    if (!plan) {
      return res.status(400).json({
        success: false,
        message: 'Plano não encontrado.'
      });
    }

    let targetApiKey = null;
    let finalKeyName = '';

    if (type === 'new') {
      finalKeyName = String(keyName || '').trim();

      if (finalKeyName.length < 2 || finalKeyName.length > 50) {
        return res.status(400).json({
          success: false,
          message: 'Informe um nome para sua nova API Key.'
        });
      }
    }

    if (type === 'recharge') {
      targetApiKey = String(apiKey || '').trim();

      if (!targetApiKey) {
        return res.status(400).json({
          success: false,
          message: 'Informe a API Key que deseja recarregar.'
        });
      }

      const existingKey = key.find(item => item?.apikey === targetApiKey);

      if (!existingKey) {
        return res.status(404).json({
          success: false,
          message: 'A API Key informada não foi encontrada.'
        });
      }

      if (existingKey.blocked) {
        return res.status(403).json({
          success: false,
          message: 'Esta API Key está bloqueada.'
        });
      }

      finalKeyName = existingKey.name || 'API Key';
    }

    const accessToken = crypto.randomBytes(32).toString('hex');

    const order = {
      id: crypto.randomBytes(12).toString('hex'),
      type,
      status: 'pending',
      name: String(name).trim(),
      email: String(email).trim().toLowerCase(),
      planId: plan.id,
      planLabel: plan.label,
      requests: plan.amount,
      price: Number(plan.price),
      keyName: finalKeyName,
      targetApiKey,
      accessTokenHash: hashToken(accessToken),
      createdAt: new Date().toISOString(),
      updatedAt: null,
      apikey: null
    };

    orders.unshift(order);
    saveOrders();

    return res.status(201).json({
      success: true,
      order: publicOrder(order),
      accessToken,
      pix: {
        key: PIX_KEY,
        name: PIX_NAME,
        amount: Number(plan.price)
      }
    });
  } catch (error) {
    console.error('[PIX CREATE ORDER]', error);

    return res.status(500).json({
      success: false,
      message: 'Não foi possível criar seu pedido.'
    });
  }
});

// ==========================================
// CONSULTAR PEDIDO DO CLIENTE
// ==========================================

app.get('/api/payments/orders/:id', (req, res) => {
  const order = orders.find(item => item.id === req.params.id);

  if (!order) {
    return res.status(404).json({
      success: false,
      message: 'Pedido não encontrado.'
    });
  }

  const token = String(req.query.token || '');

  if (!token || !sameSecret(hashToken(token), order.accessTokenHash)) {
    return res.status(403).json({
      success: false,
      message: 'Token de acesso inválido.'
    });
  }

  return res.json({
    success: true,
    order: publicOrder(order)
  });
});

// ==========================================
// PAINEL ADMINISTRATIVO - PEDIDOS
// ==========================================

app.get('/api/admin/orders', requireAdmin, (req, res) => {
  res.json({
    success: true,
    orders: orders.map(publicOrder)
  });
});

// APROVAR PEDIDO
app.post('/api/admin/orders/:id/approve', requireAdmin, (req, res) => {
  try {
    const order = orders.find(item => item.id === req.params.id);

    if (!order) {
      return res.status(404).json({
        success: false,
        message: 'Pedido não encontrado.'
      });
    }

    if (order.status === 'approved') {
      return res.json({
        success: true,
        message: 'Este pedido já foi aprovado.',
        order: publicOrder(order)
      });
    }

    if (order.status === 'rejected') {
      return res.status(400).json({
        success: false,
        message: 'Este pedido já foi recusado.'
      });
    }

    if (order.status !== 'pending') {
      return res.status(409).json({
        success: false,
        message: 'Pedido não está disponível para aprovação.'
      });
    }

    if (order.type === 'new') {
      let apikey;

      do {
        apikey = `sv_${crypto.randomBytes(24).toString('hex')}`;
      } while (key.some(item => item.apikey === apikey));

      key.push({
        apikey,
        name: order.keyName || 'API Key',
        request: Number(order.requests),
        blocked: false
      });

      order.apikey = apikey;
    } else if (order.type === 'recharge') {
      const existingKey = key.find(item => item?.apikey === order.targetApiKey);

      if (!existingKey) {
        return res.status(404).json({
          success: false,
          message: 'A chave que receberia a recarga não foi encontrada.'
        });
      }

      if (existingKey.blocked) {
        return res.status(403).json({
          success: false,
          message: 'A chave está bloqueada e não pode receber recarga.'
        });
      }

      existingKey.request =
        Math.max(0, Number(existingKey.request) || 0) + Number(order.requests);

      order.apikey = existingKey.apikey;
    } else {
      return res.status(400).json({
        success: false,
        message: 'Tipo de pedido inválido.'
      });
    }

    saveKeys();

    order.status = 'approved';
    order.updatedAt = new Date().toISOString();

    saveOrders();

    return res.json({
      success: true,
      message: 'Pedido aprovado com sucesso.',
      order: publicOrder(order)
    });
  } catch (error) {
    console.error('[PIX APPROVE ORDER]', error);

    return res.status(500).json({
      success: false,
      message: 'Erro ao aprovar pedido.'
    });
  }
});

// RECUSAR PEDIDO
app.post('/api/admin/orders/:id/reject', requireAdmin, (req, res) => {
  const order = orders.find(item => item.id === req.params.id);

  if (!order) {
    return res.status(404).json({
      success: false,
      message: 'Pedido não encontrado.'
    });
  }

  if (order.status === 'approved') {
    return res.status(400).json({
      success: false,
      message: 'Não é possível recusar um pedido já aprovado.'
    });
  }

  if (order.status === 'rejected') {
    return res.json({
      success: true,
      message: 'Pedido já estava recusado.',
      order: publicOrder(order)
    });
  }

  order.status = 'rejected';
  order.reason = 'Pedido recusado pelo administrador.';
  order.updatedAt = new Date().toISOString();

  saveOrders();

  res.json({
    success: true,
    message: 'Pedido recusado.',
    order: publicOrder(order)
  });
});

// ==========================================
// HEALTH CHECK
// ==========================================

app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    service: 'SIXVOID APIS'
  });
});

// ==========================================
// LOGIN ADMINISTRATIVO
// ==========================================

app.post('/api/admin/login', (req, res) => {
  if (!ADMIN_PASSWORD) {
    return res.status(503).json({
      success: false,
      message: 'Configure ADMIN_PASSWORD na hospedagem antes de acessar o painel.'
    });
  }

  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const attempt = loginAttempts.get(ip) || { count: 0, until: 0 };

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
  res.json({ authenticated: isAdmin(req) });
});

// ==========================================
// ESTATÍSTICAS
// ==========================================

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const totalKeys = key.length;
  const activeKeys = key.filter(
    item => Number(item?.request) > 0 && !item?.blocked
  ).length;

  const blockedKeys = key.filter(item => Boolean(item?.blocked)).length;

  const exhaustedKeys = key.filter(
    item => Number(item?.request) <= 0
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

// ==========================================
// GERENCIAMENTO DE API KEYS
// ==========================================

app.get('/api/admin/keys', requireAdmin, (req, res) => {
  res.json({
    success: true,
    keys: key.map(item => ({
      apikey: String(item.apikey),
      name: item.name || 'API Key',
      request: Number(item.request) || 0,
      blocked: Boolean(item.blocked)
    }))
  });
});

app.post('/api/admin/keys', requireAdmin, (req, res) => {
  const limit = Number(req.body?.limit);

  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000000000) {
    return res.status(400).json({
      success: false,
      message: 'Informe um limite válido entre 1 e 1.000.000.000.'
    });
  }

  let apikey;

  do {
    apikey = `sv_${crypto.randomBytes(18).toString('hex')}`;
  } while (key.some(item => item.apikey === apikey));

  const name = String(req.body?.name || 'API Key').trim().slice(0, 50);

  key.push({
    apikey,
    name: name || 'API Key',
    request: limit,
    blocked: false
  });

  saveKeys();

  res.status(201).json({
    success: true,
    key: {
      apikey,
      name,
      request: limit
    }
  });
});

app.post('/api/admin/keys/:apikey/block', requireAdmin, (req, res) => {
  const item = key.find(entry => entry.apikey === req.params.apikey);

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
  const index = key.findIndex(item => item.apikey === req.params.apikey);

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

  if (!Number.isSafeInteger(amount) || amount < 1 || amount > 1000000000) {
    return res.status(400).json({
      success: false,
      message: 'Informe uma recarga válida.'
    });
  }

  const item = key.find(entry => entry.apikey === req.params.apikey);

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

// ==========================================
// ROTAS PRINCIPAIS
// ==========================================

app.get('/', (req, res) => {
  res.sendFile(path.join(ROOT, 'public', 'index.html'));
});

app.get('/admin', (req, res) => res.redirect('/admin.html'));
app.get('/solicitar-key', (req, res) => res.redirect('/solicitar-key.html'));

// ==========================================
// DEPENDÊNCIAS DAS APIS
// ==========================================

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

// ==========================================
// CONTROLE DE CRÉDITOS
// ==========================================

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
    user = { key: apikey, IP: [] };
    users.push(user);
  }

  if (!Array.isArray(user.IP)) user.IP = [];

  if (ip !== 'unknown' && !user.IP.includes(ip)) {
    user.IP.push(ip);
  }

  saveUsers();

  return true;
}

// ==========================================
// CONSULTAR API KEY
// ==========================================

app.get('/api/keyerrada', (req, res) => {
  const apikey = req.query.apikey;

  const ITC = key.map(i => i?.apikey).indexOf(apikey);

  if (ITC < 0) {
    return res.json({
      key: 'Sua apikey é invalida Ou acabou as requets'
    });
  }

  return res.json({
    key: `Sua ApiKey está 100% ✅ - Requests Restantes: ${key[ITC]?.request}`
  });
});

// Rotas antigas bloqueadas
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

// ==========================================
// PLAY STORE
// ==========================================

app.get('/api/playstore', async (req, res, next) => {
  const apikey = req.query.apikey;

  if (key[key.map(i => i?.apikey).indexOf(apikey)]?.request <= 0) {
    return res.sendFile(path.join(ROOT, 'public', 'limited.html'));
  }

  if (!apikey) {
    return res.json({ resultado: 'Cade o parametro apikey?' });
  }

  if (!key.map(i => i.apikey).includes(apikey)) {
    return res.sendFile(path.join(ROOT, 'public', 'limited.html'));
  }

  await listkeys(apikey, req);

  const nome = req.query.nome;

  if (!nome) {
    return res.json({
      status: false,
      criador: 'VOID',
      mensagem: 'Coloque o parametro: nome'
    });
  }

  PlayStoreSearch(nome)
    .then(data => res.json({ pesquisa: data }))
    .catch(e => res.json({ msg: 'Erro no Servidor Interno' }));
});

// ==========================================
// PLAQUINHAS
// ==========================================

app.get('/api/plaq', async (req, res, next) => {
  const textoo = req.query.texto;

  const bala = await getBuffer(
    `https://umethroo.sirv.com/Torcedora-da-sele%C3%A7%C3%A3o-brasileira-nua-mostrando-a-bunda-236x300.jpg?text.0.text=${textoo}&text.0.position.x=-64%25&text.0.position.y=-39%25&text.0.size=25&text.0.color=1b1a1a&text.0.font.family=Architects%20Daughter`
  );

  res.type('jpg');
  res.send(bala);
});

app.get('/api/plaq1', async (req, res, next) => {
  const textoo = req.query.texto;

  const bala = await getBuffer(
    `https://raptibef.sirv.com/images%20(1).jpeg?profile=Zanga%202.0&text.0.text=${textoo}`
  );

  res.type('jpg');
  res.send(bala);
});

app.get('/api/plaq2', async (req, res, next) => {
  const textoo = req.query.texto;

  const bala = await getBuffer(
    `https://raptibef.sirv.com/images.jpeg?profile=Zanga%203.0&text.0.text=${textoo}&text.0.outline.blur=63`
  );

  res.type('jpg');
  res.send(bala);
});

app.get('/api/plaq3', async (req, res, next) => {
  const textoo = req.query.texto;

  const bala = await getBuffer(
    `https://umethroo.sirv.com/peito1.jpg?text.0.text=${textoo}&text.0.position.x=-4%25&text.0.position.y=-6%25&text.0.size=14&text.0.color=000000&text.0.font.family=Shadows%20Into%20Light&text.0.font.weight=700`
  );

  res.type('jpg');
  res.send(bala);
});

app.get('/api/plaq4', async (req, res, next) => {
  const textoo = req.query.texto;

  const bala = await getBuffer(
    `https://clutamac.sirv.com/1011b781-bab1-49e3-89db-ee2c064868fa%20(1).jpg?text.0.text=${textoo}&text.0.position.gravity=northwest&text.0.position.x=22%25&text.0.position.y=60%25&text.0.size=12&text.0.color=000000&text.0.opacity=47&text.0.font.family=Roboto%20Mono&text.0.font.style=italic`
  );

  res.type('jpg');
  res.send(bala);
});

app.get('/api/plaq5', async (req, res, next) => {
  const textoo = req.query.texto;

  const bala = await getBuffer(
    `https://umethroo.sirv.com/Torcedora-da-sele%C3%A7%C3%A3o-brasileira-nua-mostrando-a-bunda-236x300.jpg?text.0.text=${textoo}&text.0.position.x=-64%25&text.0.position.y=-39%25&text.0.size=25&text.0.color=1b1a1a&text.0.font.family=Architects%20Daughter`
  );

  res.type('jpg');
  res.send(bala);
});

app.get('/api/plaq6', async (req, res, next) => {
  const textoo = req.query.texto;

  const bala = await getBuffer(
    `https://blackzin.sirv.com/Plaq18/20220212_213215.jpg?text.0.text=${textoo}&text.0.position.gravity=northwest&text.0.position.x=43%25&text.0.position.y=18%25&text.0.size=15&text.0.color=000000&text.0.opacity=57&text.0.font.family=Vollkorn&text.0.font.weight=800&text.0.font.style=italic&text.0.background.color=000000&text.0.outline.blur=32&text.0.outline.opacity=46&text.1.text=SIX VOID%3F&text.1.position.gravity=center&text.1.position.x=10%25&text.1.position.y=30%25&text.1.size=20&text.1.color=000000&text.1.opacity=59&text.1.font.family=Playball&text.1.font.weight=700&text.1.outline.opacity=0`
  );

  res.type('jpg');
  res.send(bala);
});

app.get('/api/plaq7', async (req, res, next) => {
  const textoo = req.query.texto;

  const bala = await getBuffer(
    `https://ubbornag.sirv.com/Screenshot_20210513-151821.png?text.0.text=${textoo}&text.0.position.x=-40%25&text.0.position.y=-65%25&text.0.size=30&text.0.color=000000&text.0.opacity=53&text.0.font.family=Shadows%20Into%20Light20Two&text.0.outline.blur=15`
  );

  res.type('jpg');
  res.send(bala);
});

app.get('/api/plaq8', async (req, res, next) => {
  const textoo = req.query.texto;

  const bala = await getBuffer(
    `https://lculitas.sirv.com/ETw3FRnXgAI3Up_.jpg?text.0.text=${textoo}&text.0.position.gravity=center&text.0.align=left&text.0.size=46&text.0.color=221b1b&text.0.opacity=47&text.0.font.family=Architects%20Daughter&text.0.background.color=783852&text.0.background.opacity=5&text.0.outline.blur=58`
  );

  res.type('jpg');
  res.send(bala);
});

// ==========================================
// TTP
// ==========================================

app.get('/api/ttp', async (req, res) => {
  const texto = req.query.texto;

  if (!texto) {
    return res.json({
      status: false,
      msg: 'Cade o parametro texto??'
    });
  }

  const apikey = req.query.apikey;

  if (key[key.map(i => i?.apikey).indexOf(apikey)]?.request <= 0) {
    return res.sendFile(path.join(ROOT, 'public', 'limited.html'));
  }

  if (!apikey) {
    return res.json({ resultado: 'Cade o parametro apikey?' });
  }

  if (!key.map(i => i.apikey).includes(apikey)) {
    return res.sendFile(path.join(ROOT, 'public', 'limited.html'));
  }

  await listkeys(apikey, req);

  const cor = [
    'f702ff', 'ff0202', '00ff2e', 'efff00', '00ecff',
    '3100ff', 'ffb400', 'ff00b0', '00ff95', 'efff00'
  ];

  const fonte = [
    'Days%20One', 'Domine', 'Exo', 'Fredoka%20One',
    'Gentium%20Basic', 'Gloria%20Hallelujah',
    'Great%20Vibes', 'Orbitron', 'PT%20Serif', 'Pacifico'
  ];

  const cores = cor[Math.floor(Math.random() * cor.length)];
  const fontes = fonte[Math.floor(Math.random() * fonte.length)];

  const sitee = `https://huratera.sirv.com/PicsArt_08-01-10.00.42.png?profile=Example-Text&text.0.text=${texto}&text.0.outline.color=000000&text.0.outline.blur=0&text.0.outline.opacity=55&text.0.color=${cores}&text.0.font.family=${fontes}&text.0.background.color=ff0000`;

  res.type('jpg');
  res.send(await getBuffer(sitee));
});

// ==========================================
// ROTAS NSFW
// ==========================================

app.get('/nsfw/ass', async (req, res, next) => {
  const apikey = req.query.apikey;

  if (key[key.map(i => i?.apikey).indexOf(apikey)]?.request <= 0) {
    return res.sendFile(path.join(ROOT, 'public', 'limited.html'));
  }

  if (!apikey) {
    return res.json({ resultado: 'Cade o parametro apikey?' });
  }

  if (!key.map(i => i.apikey).includes(apikey)) {
    return res.sendFile(path.join(ROOT, 'public', 'limited.html'));
  }

  await listkeys(apikey, req);

  const ass = JSON.parse(fs.readFileSync(bla + '/data/ass.json'));
  const randass = ass[Math.floor(Math.random() * ass.length)];

  const data = await fetch(randass).then(v => v.buffer());

  fs.writeFileSync(bla + '/tmp/ass.jpeg', data);

  res.sendFile(bla + '/tmp/ass.jpeg');
});

app.get('/nsfw/cum', async (req, res, next) => {
  const apikey = req.query.apikey;

  if (key[key.map(i => i?.apikey).indexOf(apikey)]?.request <= 0) {
    return res.sendFile(path.join(ROOT, 'public', 'limited.html'));
  }

  if (!apikey) {
    return res.json({ resultado: 'Cade o parametro apikey?' });
  }

  if (!key.map(i => i.apikey).includes(apikey)) {
    return res.sendFile(path.join(ROOT, 'public', 'limited.html'));
  }

  await listkeys(apikey, req);

  const cum = JSON.parse(fs.readFileSync(bla + '/data/cum.json'));
  const randcum = cum[Math.floor(Math.random() * cum.length)];

  const data = await fetch(randcum).then(v => v.buffer());

  fs.writeFileSync(bla + '/tmp/cum.jpeg', data);

  res.sendFile(bla + '/tmp/cum.jpeg');
});

app.get('/nsfw/gangbang', async (req, res, next) => {
  const apikey = req.query.apikey;

  if (key[key.map(i => i?.apikey).indexOf(apikey)]?.request <= 0) {
    return res.sendFile(path.join(ROOT, 'public', 'limited.html'));
  }

  if (!apikey) {
    return res.json({ resultado: 'Cade o parametro apikey?' });
  }

  if (!key.map(i => i.apikey).includes(apikey)) {
    return res.sendFile(path.join(ROOT, 'public', 'limited.html'));
  }

  await listkeys(apikey, req);

  const gangbang = JSON.parse(fs.readFileSync(bla + '/data/gangbang.json'));
  const randgangbang = gangbang[Math.floor(Math.random() * gangbang.length)];

  const data = await fetch(randgangbang).then(v => v.buffer());

  fs.writeFileSync(bla + '/tmp/gangbang.jpg', data);

  res.sendFile(bla + '/tmp/gangbang.jpg');
});

// ==========================================
// XNXX SEARCH
// ==========================================

app.get('/api/xnxxsearch', async (req, res, next) => {
  const apikey = req.query.apikey;

  if (key[key.map(i => i?.apikey).indexOf(apikey)]?.request <= 0) {
    return res.sendFile(path.join(ROOT, 'public', 'limited.html'));
  }

  if (!apikey) {
    return res.json({ resultado: 'Cade o parametro apikey?' });
  }

  if (!key.map(i => i.apikey).includes(apikey)) {
    return res.sendFile(path.join(ROOT, 'public', 'limited.html'));
  }

  await listkeys(apikey, req);

  const q = req.query.q;

  if (!q) {
    return res.json({
      status: false,
      criador: 'SIX VOID',
      mensagem: 'Coloque o parametro: q'
    });
  }

  return res.status(501).json({
    status: false,
    msg: 'A função xnxxsearch não está configurada neste arquivo.'
  });
});

// ==========================================
// GERAR NICK
// ==========================================

app.get('/api/fazernick', async (req, res) => {
  const apikey = req.query.apikey;

  if (key[key.map(i => i?.apikey).indexOf(apikey)]?.request <= 0) {
    return res.sendFile(path.join(ROOT, 'public', 'limited.html'));
  }

  if (!apikey) {
    return res.json({ resultado: 'Cade o parametro apikey?' });
  }

  if (!key.map(i => i.apikey).includes(apikey)) {
    return res.sendFile(path.join(ROOT, 'public', 'limited.html'));
  }

  await listkeys(apikey, req);

  const nome = req.query.nome;

  if (!nome) {
    return res.json({ msg: 'insira o parâmetro: ?nome=' });
  }

  try {
    const nicks = await gerarnick(nome);
    res.send(nicks);
  } catch (e) {
    res.json({ erro: 'Erro no Servidor Interno' });
  }
});

// ==========================================
// METADINHA
// ==========================================

app.get('/random/metadinha', async (req, res, next) => {
  const apikey = req.query.apikey;

  if (key[key.map(i => i?.apikey).indexOf(apikey)]?.request <= 0) {
    return res.sendFile(path.join(ROOT, 'public', 'limited.html'));
  }

  if (!apikey) {
    return res.json({ resultado: 'Cade o parametro apikey?' });
  }

  if (!key.map(i => i.apikey).includes(apikey)) {
    return res.sendFile(path.join(ROOT, 'public', 'limited.html'));
  }

  await listkeys(apikey, req);

  const json = JSON.parse(
    fs.readFileSync(bla + '/lib/metadinha.json').toString()
  );

  const random = json[Math.floor(Math.random() * json.length)];

  res.json(random);
});

// ==========================================
// NERDING
// ==========================================

app.get('/api/nerding', async (req, res, next) => {
  try {
    const apikey = req.query.apikey;
    const q = req.query.q;

    if (!apikey) {
      return res.json({ resultado: 'Cade o parametro apikey?' });
    }

    if (!q) {
      return res.json({
        status: false,
        criador: 'SIX VOID',
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
      return res.sendFile(path.join(ROOT, 'public', 'limited.html'));
    }

    if (key[keyIndex]?.request <= 0) {
      return res.sendFile(path.join(ROOT, 'public', 'limited.html'));
    }

    await listkeys(apikey, req);

    nerding(q)
      .then(resultado => {
        res.json({
          status: true,
          código: 200,
          criador: 'SIX VOID',
          resultado
        });
      })
      .catch(e => {
        console.error('Erro no nerding:', e);
        res.json({ msg: 'Erro no Servidor Interno' });
      });

  } catch (error) {
    console.error('Erro interno:', error);
    res.json({ msg: 'Erro no Servidor Interno' });
  }
});

// ==========================================
// NOTÍCIAS ESTADÃO
// ==========================================

app.get('/api/noticias/estadao', async (req, res, next) => {
  const apikey = req.query.apikey;

  if (key[key.map(i => i?.apikey).indexOf(apikey)]?.request <= 0) {
    return res.sendFile(path.join(ROOT, 'public', 'limited.html'));
  }

  if (!apikey) {
    return res.json({ resultado: 'Cade o parametro apikey?' });
  }

  if (!key.map(i => i.apikey).includes(apikey)) {
    return res.sendFile(path.join(ROOT, 'public', 'limited.html'));
  }

  await listkeys(apikey, req);

  Estadao()
    .then(data => res.json({ pesquisa: data }))
    .catch(e => res.json({ msg: 'Erro no Servidor Interno' }));
});

// ==========================================
// INICIAR SERVIDOR
// ==========================================

/* =========================================
   SIXVOID APIS — PLAYLIST AUTOMÁTICA
========================================= */

const MUSIC_DIR = path.join(ROOT, "public", "audio");

app.get("/api/music", async (req, res) => {
  try {
    await fs.promises.mkdir(MUSIC_DIR, { recursive: true });

    const files = await fs.promises.readdir(MUSIC_DIR, {
      withFileTypes: true
    });

    const extensions = [
      ".mp3", ".wav", ".ogg", ".m4a", ".aac", ".flac"
    ];

    const music = await Promise.all(
      files
        .filter(file =>
          file.isFile() &&
          extensions.includes(path.extname(file.name).toLowerCase())
        )
        .map(async file => {
          const extension = path.extname(file.name);
          const title = path.basename(file.name, extension);

          let cover = null;
          let artist = "SIXVOID SOUND SYSTEM";

          try {
            const metadata = await musicMetadata.parseFile(
              path.join(MUSIC_DIR, file.name)
            );

            artist =
              metadata.common.artist ||
              metadata.common.albumartist ||
              artist;

            const picture = metadata.common.picture?.[0];

            if (picture) {
              cover =
                "data:" + picture.format +
                ";base64," +
                picture.data.toString("base64");
            }
          } catch (error) {
            console.log("[MUSIC METADATA]", file.name, error.message);
          }

          return {
            title,
            artist,
            src: "/audio/" + encodeURIComponent(file.name),
            cover
          };
        })
    );

    music.sort((a, b) =>
      a.title.localeCompare(b.title, "pt-BR")
    );

    return res.json({
      status: true,
      total: music.length,
      music
    });

  } catch (error) {
    console.error("[SIXVOID MUSIC]", error);

    return res.status(500).json({
      status: false,
      message: "Não foi possível carregar a playlist."
    });
  }
});


app.listen(PORT, HOST, () => {
  console.log(`SIXVOID APIS online em http://${HOST}:${PORT}`);

  if (!ADMIN_PASSWORD) {
    console.warn(
      'ATENÇÃO: defina ADMIN_PASSWORD nas variáveis de ambiente para habilitar o painel.'
    );
  }

  console.log('Sistema Pix manual: ATIVO');
  console.log(`Chave Pix configurada: ${PIX_KEY}`);
});

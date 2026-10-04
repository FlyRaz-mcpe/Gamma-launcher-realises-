require('dotenv').config();

const express = require('express');
const session = require('express-session');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const Database = require('better-sqlite3');

const app = express();

const DATA_DIR = process.env.DATA_DIR || './data';
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(`${DATA_DIR}/gamma.db`);

const PORT = process.env.PORT || 3000;

const ALLOWED = new Set([
  'flyraz_mc',
  'yuno8340'
]);

const UPLOAD_DIR =
  process.env.UPLOAD_DIR || `${DATA_DIR}/uploads`;

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT,
    provider_id TEXT UNIQUE,
    username TEXT,
    created_at TEXT
  );

  CREATE TABLE IF NOT EXISTS releases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    version TEXT,
    category TEXT,
    description TEXT,
    filename TEXT,
    author TEXT,
    created_at TEXT
  );
`);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production'
    }
  })
);

app.use(express.static('public'));

/* APK upload */

const upload = multer({
  dest: UPLOAD_DIR + '/',
  limits: {
    fileSize: 500 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    const isApk = file.originalname
      .toLowerCase()
      .endsWith('.apk');

    cb(null, isApk);
  }
});

/* Check publisher */

function publisher(req) {
  return !!(
    req.session.user &&
    ALLOWED.has(
      (req.session.user.username || '').toLowerCase()
    )
  );
}

/* Current user */

app.get('/api/me', (req, res) => {
  res.json({
    user: req.session.user || null,
    publisher: publisher(req)
  });
});

/* Releases */

app.get('/api/releases', (req, res) => {
  const releases = db
    .prepare(`
      SELECT
        id,
        title,
        version,
        category,
        description,
        filename,
        author,
        created_at
      FROM releases
      ORDER BY id DESC
    `)
    .all();

  res.json(releases);
});

/* Download APK */

app.get('/download/:id', (req, res) => {
  const release = db
    .prepare('SELECT * FROM releases WHERE id = ?')
    .get(req.params.id);

  if (!release || !fs.existsSync(release.filename)) {
    return res.sendStatus(404);
  }

  res.download(
    release.filename,
    release.title + '.apk'
  );
});

/* Telegram Login */

app.post('/auth/telegram', (req, res) => {
  const data = { ...req.body };

  const hash = data.hash;

  delete data.hash;

  if (!hash) {
    return res.status(400).json({
      error: 'missing hash'
    });
  }

  const check = Object.keys(data)
    .sort()
    .map(key => `${key}=${data[key]}`)
    .join('\n');

  const secret = crypto
    .createHash('sha256')
    .update(process.env.TELEGRAM_BOT_TOKEN || '')
    .digest();

  const expected = crypto
    .createHmac('sha256', secret)
    .update(check)
    .digest('hex');

  if (
    !crypto.timingSafeEqual(
      Buffer.from(expected),
      Buffer.from(hash)
    )
  ) {
    return res.status(401).json({
      error: 'invalid telegram auth'
    });
  }

  if (
    data.auth_date &&
    Date.now() / 1000 - Number(data.auth_date) > 86400
  ) {
    return res.status(401).json({
      error: 'expired login'
    });
  }

  const username = (data.username || '').toLowerCase();

  db.prepare(`
    INSERT INTO users (
      provider,
      provider_id,
      username,
      created_at
    )
    VALUES (?, ?, ?, ?)

    ON CONFLICT(provider_id)
    DO UPDATE SET username = excluded.username
  `).run(
    'telegram',
    String(data.id),
    username,
    new Date().toISOString()
  );

  req.session.user = {
    provider: 'telegram',
    id: String(data.id),
    username
  };

  res.json({
    ok: true,
    user: req.session.user,
    publisher: ALLOWED.has(username)
  });
});

/* Discord Login */

app.get('/auth/discord', (req, res) => {
  const redirectUri =
    process.env.DISCORD_REDIRECT_URI ||
    `${process.env.SITE_URL}/auth/discord/callback`;

  const params = new URLSearchParams({
    client_id: process.env.DISCORD_CLIENT_ID || '',
    response_type: 'code',
    redirect_uri: redirectUri,
    scope: 'identify'
  });

  res.redirect(
    'https://discord.com/oauth2/authorize?' +
    params.toString()
  );
});

/* Discord Callback */

app.get('/auth/discord/callback', async (req, res) => {
  try {
    const redirectUri =
      process.env.DISCORD_REDIRECT_URI;

    const body = new URLSearchParams({
      client_id: process.env.DISCORD_CLIENT_ID || '',
      client_secret:
        process.env.DISCORD_CLIENT_SECRET || '',
      grant_type: 'authorization_code',
      code: req.query.code,
      redirect_uri: redirectUri || ''
    });

    const tokenResponse = await fetch(
      'https://discord.com/api/oauth2/token',
      {
        method: 'POST',
        headers: {
          'Content-Type':
            'application/x-www-form-urlencoded'
        },
        body
      }
    );

    const token = await tokenResponse.json();

    if (!token.access_token) {
      return res
        .status(500)
        .send('Discord token error');
    }

    const userResponse = await fetch(
      'https://discord.com/api/users/@me',
      {
        headers: {
          Authorization:
            `Bearer ${token.access_token}`
        }
      }
    );

    const user = await userResponse.json();

    const username =
      (user.username || '').toLowerCase();

    db.prepare(`
      INSERT INTO users (
        provider,
        provider_id,
        username,
        created_at
      )
      VALUES (?, ?, ?, ?)

      ON CONFLICT(provider_id)
      DO UPDATE SET username = excluded.username
    `).run(
      'discord',
      user.id,
      username,
      new Date().toISOString()
    );

    req.session.user = {
      provider: 'discord',
      id: user.id,
      username
    };

    res.redirect('/');
  } catch (error) {
    console.error(error);
    res
      .status(500)
      .send('Discord login failed');
  }
});

/* Logout */

app.post('/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({
      ok: true
    });
  });
});

/* Publish release */

app.post(
  '/api/releases',
  upload.single('apk'),
  (req, res) => {

    if (!publisher(req)) {
      return res.status(403).json({
        error:
          'Only @flyraz_mc and @yuno8340 can publish'
      });
    }

    if (!req.file) {
      return res.status(400).json({
        error: 'APK required'
      });
    }

    const release = db.prepare(`
      INSERT INTO releases (
        title,
        version,
        category,
        description,
        filename,
        author,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      req.body.title,
      req.body.version,
      req.body.category,
      req.body.description,
      req.file.path,
      req.session.user.username,
      new Date().toISOString()
    );

    res.json({
      ok: true,
      id: release.lastInsertRowid
    });
  }
);

/* Health check */

app.get('/healthz', (req, res) => {
  res.json({
    ok: true
  });
});

/* Start server */

app.listen(
  PORT,
  '0.0.0.0',
  () => {
    console.log(
      `Gamma Releases running on ${PORT}`
    );
  }
);
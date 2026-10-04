require('dotenv').config();

const express = require('express');
const session = require('express-session');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const Database = require('better-sqlite3');

const app = express();

const PORT = process.env.PORT || 3000;

const DATA_DIR = process.env.DATA_DIR || './data';
fs.mkdirSync(DATA_DIR, { recursive: true });

const UPLOAD_DIR =
  process.env.UPLOAD_DIR || `${DATA_DIR}/uploads`;

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new Database(`${DATA_DIR}/gamma.db`);

/*
========================================
  ПОЛЬЗОВАТЕЛИ, КОТОРЫМ РАЗРЕШЕНА ПУБЛИКАЦИЯ
========================================
*/

const ALLOWED = new Set([
  'flyraz_mc',
  'yuno8340'
]);

/*
========================================
  DATABASE
========================================
*/

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

/*
========================================
  MIDDLEWARE
========================================
*/

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret:
      process.env.SESSION_SECRET ||
      'change-this-secret',

    resave: false,

    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure:
        process.env.NODE_ENV === 'production'
    }
  })
);

/*
========================================
  INDEX.HTML В КОРНЕ ПРОЕКТА
========================================
*/

app.use(express.static('.'));

/*
========================================
  APK UPLOAD
========================================
*/

const upload = multer({
  dest: UPLOAD_DIR + '/',

  limits: {
    fileSize: 500 * 1024 * 1024
  },

  fileFilter: (req, file, cb) => {
    const isApk = file.originalname
      .toLowerCase()
      .endsWith('.apk');

    if (!isApk) {
      return cb(null, false);
    }

    cb(null, true);
  }
});

/*
========================================
  ПРОВЕРКА ПУБЛИКАТОРА
========================================

  ВАЖНО:
  Только Telegram-пользователи
  @flyraz_mc и @yuno8340
*/

function publisher(req) {
  return !!(
    req.session.user &&
    req.session.user.provider === 'telegram' &&
    ALLOWED.has(
      (req.session.user.username || '')
        .toLowerCase()
    )
  );
}

/*
========================================
  ТЕКУЩИЙ ПОЛЬЗОВАТЕЛЬ
========================================
*/

app.get('/api/me', (req, res) => {
  res.json({
    user: req.session.user || null,
    publisher: publisher(req)
  });
});

/*
========================================
  СПИСОК РЕЛИЗОВ
========================================
*/

app.get('/api/releases', (req, res) => {
  try {
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
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Failed to load releases'
    });
  }
});

/*
========================================
  СКАЧИВАНИЕ APK
========================================
*/

app.get('/download/:id', (req, res) => {
  try {
    const release = db
      .prepare(
        'SELECT * FROM releases WHERE id = ?'
      )
      .get(req.params.id);

    if (!release) {
      return res.sendStatus(404);
    }

    if (!fs.existsSync(release.filename)) {
      return res.sendStatus(404);
    }

    const safeTitle =
      (release.title || 'release')
        .replace(/[^a-zA-Z0-9а-яА-Я _.-]/g, '_');

    res.download(
      release.filename,
      safeTitle + '.apk'
    );

  } catch (error) {
    console.error(error);

    res.status(500).send(
      'Download error'
    );
  }
});

/*
========================================
  TELEGRAM LOGIN
========================================
*/

app.post('/auth/telegram', (req, res) => {
  try {
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
      .map(
        key =>
          `${key}=${data[key]}`
      )
      .join('\n');

    const secret = crypto
      .createHash('sha256')
      .update(
        process.env.TELEGRAM_BOT_TOKEN || ''
      )
      .digest();

    const expected = crypto
      .createHmac('sha256', secret)
      .update(check)
      .digest('hex');

    if (
      expected.length !== hash.length ||
      !crypto.timingSafeEqual(
        Buffer.from(expected),
        Buffer.from(hash)
      )
    ) {
      return res.status(401).json({
        error: 'invalid telegram auth'
      });
    }

    /*
      Telegram login должен быть свежим
    */

    if (
      data.auth_date &&
      Date.now() / 1000 -
        Number(data.auth_date) >
        86400
    ) {
      return res.status(401).json({
        error: 'expired login'
      });
    }

    const username =
      (data.username || '')
        .toLowerCase();

    /*
      Сохраняем пользователя
    */

    db.prepare(`
      INSERT INTO users (
        provider,
        provider_id,
        username,
        created_at
      )
      VALUES (?, ?, ?, ?)

      ON CONFLICT(provider_id)
      DO UPDATE SET
        username = excluded.username
    `).run(
      'telegram',
      String(data.id),
      username,
      new Date().toISOString()
    );

    /*
      Создаем сессию
    */

    req.session.user = {
      provider: 'telegram',
      id: String(data.id),
      username
    };

    res.json({
      ok: true,

      user: req.session.user,

      publisher:
        ALLOWED.has(username)
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Telegram login failed'
    });
  }
});

/*
========================================
  DISCORD LOGIN
========================================
*/

app.get('/auth/discord', (req, res) => {
  const redirectUri =
    process.env.DISCORD_REDIRECT_URI ||
    `${process.env.SITE_URL}/auth/discord/callback`;

  const params = new URLSearchParams({
    client_id:
      process.env.DISCORD_CLIENT_ID || '',

    response_type: 'code',

    redirect_uri:
      redirectUri,

    scope: 'identify'
  });

  res.redirect(
    'https://discord.com/oauth2/authorize?' +
    params.toString()
  );
});

/*
========================================
  DISCORD CALLBACK
========================================
*/

app.get(
  '/auth/discord/callback',
  async (req, res) => {

    try {

      if (!req.query.code) {
        return res
          .status(400)
          .send('Missing Discord code');
      }

      const redirectUri =
        process.env.DISCORD_REDIRECT_URI;

      const body =
        new URLSearchParams({
          client_id:
            process.env.DISCORD_CLIENT_ID || '',

          client_secret:
            process.env.DISCORD_CLIENT_SECRET || '',

          grant_type:
            'authorization_code',

          code:
            req.query.code,

          redirect_uri:
            redirectUri || ''
        });

      const tokenResponse =
        await fetch(
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

      const token =
        await tokenResponse.json();

      if (!token.access_token) {
        console.error(token);

        return res
          .status(500)
          .send(
            'Discord token error'
          );
      }

      /*
        Получаем Discord пользователя
      */

      const userResponse =
        await fetch(
          'https://discord.com/api/users/@me',
          {
            headers: {
              Authorization:
                `Bearer ${token.access_token}`
            }
          }
        );

      const user =
        await userResponse.json();

      const username =
        (user.username || '')
          .toLowerCase();

      /*
        Сохраняем пользователя
      */

      db.prepare(`
        INSERT INTO users (
          provider,
          provider_id,
          username,
          created_at
        )
        VALUES (?, ?, ?, ?)

        ON CONFLICT(provider_id)
        DO UPDATE SET
          username = excluded.username
      `).run(
        'discord',
        user.id,
        username,
        new Date().toISOString()
      );

      /*
        Discord может войти,
        но НЕ получает права публикации.
      */

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
        .send(
          'Discord login failed'
        );
    }
  }
);

/*
========================================
  ВЫХОД
========================================
*/

app.post('/auth/logout', (req, res) => {

  req.session.destroy(() => {

    res.json({
      ok: true
    });

  });
});

/*
========================================
  ПУБЛИКАЦИЯ APK
========================================
*/

app.post(
  '/api/releases',
  upload.single('apk'),

  (req, res) => {

    try {

      /*
        Проверяем права
      */

      if (!publisher(req)) {
        return res.status(403).json({
          error:
            'Only @flyraz_mc and @yuno8340 can publish'
        });
      }

      /*
        Проверяем APK
      */

      if (!req.file) {
        return res.status(400).json({
          error:
            'APK file required'
        });
      }

      /*
        Проверяем название
      */

      if (!req.body.title) {
        return res.status(400).json({
          error:
            'Title required'
        });
      }

      /*
        Проверяем версию
      */

      if (!req.body.version) {
        return res.status(400).json({
          error:
            'Version required'
        });
      }

      /*
        Сохраняем релиз
      */

      const release =
        db.prepare(`
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

          req.body.category ||
            'Other',

          req.body.description ||
            '',

          req.file.path,

          req.session.user.username,

          new Date().toISOString()
        );

      res.json({
        ok: true,

        id:
          release.lastInsertRowid
      });

    } catch (error) {

      console.error(error);

      /*
        Если база не сохранилась,
        удаляем загруженный APK
      */

      if (
        req.file &&
        fs.existsSync(req.file.path)
      ) {
        fs.unlinkSync(
          req.file.path
        );
      }

      res.status(500).json({
        error:
          'Failed to publish release'
      });
    }
  }
);

/*
========================================
  HEALTH CHECK
========================================
*/

app.get('/healthz', (req, res) => {

  res.json({
    ok: true
  });

});

/*
========================================
  404
========================================
*/

app.use((req, res) => {

  if (
    req.path.startsWith('/api/')
  ) {
    return res.status(404).json({
      error: 'Not found'
    });
  }

  res.status(404).send(
    'Page not found'
  );

});

/*
========================================
  START SERVER
========================================
*/

app.listen(
  PORT,
  '0.0.0.0',
  () => {

    console.log(
      `Gamma Releases running on port ${PORT}`
    );

  }
);

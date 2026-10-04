# Gamma Releases — Render Free

Готовый Node.js/Express проект для бесплатного Render Web Service.

## Что работает
- Telegram Login с проверкой подписи;
- Discord OAuth;
- публикация APK только для `@flyraz_mc` и `@yuno8340`;
- поиск, категории и скачивание;
- `/healthz` для Render health check;
- Render Blueprint `render.yaml`;
- сервер слушает `0.0.0.0` и `$PORT`.

## Важно про бесплатный Render
Free Web Service использует эфемерную файловую систему: локальная SQLite-база и загруженные APK могут исчезнуть при перезапуске, redeploy или spin-down. Поэтому эта версия подходит для теста/прототипа, но не для постоянного APK-хранилища.

Для постоянных релизов нужно вынести базу и APK в отдельное постоянное хранилище.

## Деплой
1. Создай GitHub-репозиторий и загрузи содержимое этой папки.
2. В Render выбери New → Blueprint и подключи репозиторий с `render.yaml`.
3. Выбери Free.
4. Добавь секреты/переменные окружения, которые помечены `sync: false`.
5. После деплоя сайт получит адрес `https://...onrender.com`.

## Telegram
В BotFather настрой Telegram Login для домена сайта и укажи токен в `TELEGRAM_BOT_TOKEN`.

## Discord
В Discord Developer Portal создай OAuth2 application и укажи callback:
`https://ТВОЙ-ДОМЕН.onrender.com/auth/discord/callback`

Не публикуй токены в GitHub.

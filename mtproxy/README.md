# MTProto proxy (mtg) — несколько пользователей (план A)

У каждого пользователя: **свой** `secret`, **свой** внешний TCP-порт, **свой** Docker-контейнер `mtproto-proxy-<slug>`.

Данные лежат в `mtproxy/users/<slug>/` (`config.toml` + `meta.json`). Каталог `users/` в `.gitignore`, чтобы не коммитить секреты.

Лимит на пользователя: `mtg` настроен на `concurrency = 3`, то есть максимум 3 одновременных подключения на один контейнер/secret.

## Требования

- Docker, `curl`, `ss` (iproute2)
- Запуск с правами, достаточными для `docker` (внутри скрипта — `sudo docker`)

## CLI

Из корня репозитория (или укажи каталог данных):

```bash
export MTPROXY_DATA_DIR=/opt/liberty/mtproxy   # опционально; по умолчанию ./mtproxy рядом со скриптом
sudo ./mtproxy-admin.sh add alice
sudo ./mtproxy-admin.sh add bob --domain cloudflare.com --port 17402
sudo ./mtproxy-admin.sh list
sudo ./mtproxy-admin.sh link alice
sudo ./mtproxy-admin.sh restart alice
sudo ./mtproxy-admin.sh logs alice
sudo ./mtproxy-admin.sh remove alice
sudo ./mtproxy-admin.sh start-all    # все из users/
sudo ./mtproxy-admin.sh stop-all
```

`slug`: только `a-z`, `0-9`, `_`, `-`, длина 1–48, с буквы или цифры (удобно для имён контейнеров).

## Порты

По умолчанию свободный порт выбирается **случайно** в диапазоне **17400–19999** (при нехватке попыток — линейный обход). Переопределение:

```bash
export MTPROXY_PORT_MIN=18000
export MTPROXY_PORT_MAX=18100
```

## Установка на сервер

Файлы копирует **`install.sh`**: при выборе MTProto при установке с нуля или через меню существующей установки «Добавить протокол» → в `$INSTALL_DIR` попадают `mtproxy-admin.sh`, `mtproxy/template/`, создаётся `mtproxy/users/`.

## Интеграция с Telegram-ботом Liberty

При `MTPROXY_ENABLED=true` бот при **создании клиента** (`/add_client`) вызывает `mtproxy-admin.sh add <client_id>` — **slug совпадает с ID клиента в БД** (12 hex). В `/get_config` и `/delete_client` ссылка на прокси и удаление контейнера подтягиваются автоматически.

Размести на сервере (рядом с `docker-compose`, обычно `/opt/liberty/`):

- `mtproxy-admin.sh` (исполняемый)
- каталог `mtproxy/template/config.toml` (как в репозитории)

Данные пользователей: `mtproxy/users/` (в `.gitignore`).

### Права для пользователя бота (systemd)

Скрипт по умолчанию вызывается как `sudo -n …`. Добавь в sudoers (пример, пользователь `vpn`):

```text
vpn ALL=(root) NOPASSWD: /opt/liberty/mtproxy-admin.sh
```

Либо добавь пользователя бота в группу `docker` и в `.env` бота:

```env
MTPROXY_USE_SUDO=false
```

(тогда `sudo` внутри `mtproxy-admin.sh` для docker всё ещё нужен — см. ниже.)

**Важно:** `mtproxy-admin.sh` сам вызывает `sudo docker`. Если бот без sudo, нужно либо дать NOPASSWD на весь скрипт (как выше), либо править скрипт/обёртку под `docker` без sudo.

Переменные в `telegram-bot/.env`: см. `.env.example`.

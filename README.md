# Liberty

Установщик VPN-сервера (AmneziaWG + Xray + опционально Hysteria2 и MTProto/mtg) и опционально Telegram-бота для управления клиентами.

## Что входит

- **Сервер**: AmneziaWG (WireGuard с обфускацией), опционально Xray-core (VLESS + XTLS-Reality + Vision), Hysteria2, MTProto-прокси для Telegram (`mtproxy-admin.sh`, отдельный контейнер на клиента через бота).
- **Telegram-бот**: управление клиентами WireGuard (добавление, удаление, выдача конфигов и QR, статус, перезапуск), опционально VLESS/Hysteria2/MTProto-ссылки.

## Установка

Запустите установщик из корня репозитория:

```bash
sudo ./install.sh
```

В интерактивном меню выберите:

1. **Установить сервер (AWG + Xray)** — только VPN-сервер; в конце можно согласиться установить бота.
2. **Установить только Telegram-бота** — для уже развёрнутой установки Liberty (путь к установке запросится или возьмётся `/opt/liberty`).
3. **Установить сервер (AWG + Xray) и Telegram-бота** — полная установка одной цепочкой.
4. **Выход**

При существующей установке сервера скрипт предложит меню: удаление, переустановка, **добавление протокола** (WG / Xray / Hysteria2 / MTProto), смена IP, установка/переустановка бота, выход.

## Требования

- Linux (Debian/Ubuntu или RHEL/CentOS)
- Права root
- Для бота: Python 3.8+, qrencode, wireguard-tools

## Структура после установки

- Сервер: `/opt/liberty/` (docker-compose, `config/wg/`, `config/xray/`, при необходимости `config/hysteria/`, `mtproxy/`, `mtproxy-admin.sh`).
- Бот (если установлен): `/opt/liberty/telegram-bot/` (venv, .env, systemd-сервис `vpn-bot.service`).

Подробнее про бота и команды — в [telegram-bot/README.md](telegram-bot/README.md). Про MTProto — в [mtproxy/README.md](mtproxy/README.md).

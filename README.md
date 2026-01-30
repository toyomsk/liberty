# Liberty

Установщик VPN-сервера (AmneziaWG + Xray) и опционально Telegram-бота для управления клиентами.

## Что входит

- **Сервер**: AmneziaWG (WireGuard с обфускацией), опционально Xray-core (VLESS + XTLS-Reality + Vision).
- **Telegram-бот**: управление клиентами WireGuard (добавление, удаление, выдача конфигов и QR, статус, перезапуск).

## Установка

Запустите установщик из корня репозитория:

```bash
sudo ./install.sh
```

В интерактивном меню выберите:

1. **Установить сервер (AWG + Xray)** — только VPN-сервер; в конце можно согласиться установить бота.
2. **Установить только Telegram-бота** — для уже развёрнутой установки Liberty (путь к установке запросится или возьмётся `/opt/docker/liberty`).
3. **Установить сервер (AWG + Xray) и Telegram-бота** — полная установка одной цепочкой.
4. **Выход**

При существующей установке сервера скрипт предложит меню: удаление, переустановка, смена IP, установка/переустановка бота, выход.

## Требования

- Linux (Debian/Ubuntu или RHEL/CentOS)
- Права root
- Для бота: Python 3.8+, qrencode, wireguard-tools

## Структура после установки

- Сервер: `/opt/docker/liberty/` (docker-compose, `config/wg/`, `config/xray/`).
- Бот (если установлен): `/opt/docker/liberty/telegram-bot/` (venv, .env, systemd-сервис `liberty-bot.service`).

Подробнее про бота и команды — в [telegram-bot/README.md](telegram-bot/README.md).

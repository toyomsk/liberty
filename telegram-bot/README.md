# Telegram Bot для управления Amnezia VPN

Telegram бот для управления клиентами и сервером Amnezia VPN (WireGuard).

## Возможности

- ✅ Создание новых VPN клиентов
- ✅ Просмотр списка всех клиентов
- ✅ Получение конфигурации клиента (файл + QR-код)
- ✅ Удаление клиентов
- ✅ Просмотр статуса сервера и активных подключений
- ✅ Перезапуск VPN сервера

## Требования

- Python 3.8+
- Docker и Docker Compose
- WireGuard (`wg` команда должна быть доступна)
- Установленный и настроенный Amnezia VPN сервер

## Установка

### 1. Клонирование репозитория

```bash
cd /opt/docker/amnezia
git clone <repository_url> telegram-bot-awg
cd telegram-bot-awg
```

### 2. Установка зависимостей

```bash
sudo apt install -y python3 python3-pip python3-venv qrencode wireguard-tools

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Создание бота в Telegram

1. Напишите [@BotFather](https://t.me/BotFather) в Telegram
2. Отправьте `/newbot`
3. Введите имя бота (например: My VPN Manager)
4. Введите username (например: myvpnmanager_bot)
5. Скопируйте TOKEN — он понадобится

### 4. Получение вашего Telegram ID

Напишите боту [@userinfobot](https://t.me/userinfobot) и скопируйте ваш ID.

### 5. Настройка конфигурации

```bash
cp .env.example .env
nano .env
```

Отредактируйте `.env` файл:

```env
BOT_TOKEN=your_bot_token_here
ADMIN_IDS=123456789
VPN_CONFIG_DIR=/opt/docker/amnezia/awg-config
DOCKER_COMPOSE_DIR=/opt/docker/amnezia
WG_PORT=51820
VPN_SUBNET=10.10.1.0/24
```

### 6. Запуск бота

```bash
source venv/bin/activate
python3 -m bot.main
```

Или запустите напрямую из корневой директории проекта:

```bash
cd /opt/docker/amnezia/telegram-bot-awg
venv/bin/python -m bot.main
```

## Автозапуск через systemd

### Создание сервиса

```bash
sudo nano /etc/systemd/system/vpn-bot.service
```

Содержимое:

```ini
[Unit]
Description=VPN Telegram Bot
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/docker/amnezia/telegram-bot-awg
Environment="PATH=/opt/docker/amnezia/telegram-bot-awg/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="PYTHONPATH=/opt/docker/amnezia/telegram-bot-awg"
EnvironmentFile=/opt/docker/amnezia/telegram-bot-awg/.env
ExecStart=/opt/docker/amnezia/telegram-bot-awg/venv/bin/python -m bot.main
StandardOutput=journal
StandardError=journal
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Включение автозапуска

```bash
sudo systemctl daemon-reload
sudo systemctl enable vpn-bot.service
sudo systemctl start vpn-bot.service
sudo systemctl status vpn-bot.service
```

## Команды бота

- `/start` или `/help` — Справка по командам
- `/add_client <имя>` — Создать нового клиента
- `/list_clients` — Показать всех клиентов
- `/get_config <имя>` — Получить конфиг клиента (файл + QR-код)
- `/delete_client <имя>` — Удалить клиента (с подтверждением)
- `/status` — Статус сервера и VPN
- `/restart` — Перезапустить VPN сервер

## Использование

1. Найдите бота в Telegram по username
2. Отправьте `/start`
3. Создайте клиента: `/add_client phone`
4. Получите конфиг: `/get_config phone`
5. Импортируйте конфиг в AmneziaVPN приложение или отсканируйте QR-код

## Структура проекта

```
telegram-bot-awg/
├── bot/
│   ├── __init__.py
│   ├── main.py              # Точка входа
│   ├── handlers.py          # Обработчики команд
│   ├── awg_manager.py       # Управление клиентами Amnezia WG
│   ├── db.py                # SQLite: клиенты (id, name), источник истины
│   ├── xray_manager.py      # Управление клиентами Xray (VLESS Reality)
│   └── utils.py             # Вспомогательные функции
├── config/
│   ├── __init__.py
│   └── settings.py          # Конфигурация
├── .env.example             # Пример конфигурации
├── requirements.txt         # Зависимости
├── README.md                # Документация
└── .gitignore
```

## Примечания

- Бот работает только с администраторами, указанными в `ADMIN_IDS`
- При создании клиента VPN сервер автоматически перезапускается
- При удалении клиента VPN сервер также перезапускается
- Конфигурации клиентов сохраняются в `DOCKER_COMPOSE_DIR`
- Серверный конфиг WireGuard находится в `VPN_CONFIG_DIR/wg0.conf`

## Устранение неполадок

### Бот не отвечает

- Проверьте, что токен бота правильный в `.env`
- Убедитесь, что бот запущен: `systemctl status vpn-bot`
- Проверьте логи: `journalctl -u vpn-bot -f`

### Ошибка при создании клиента

- Убедитесь, что путь к конфигурации VPN правильный
- Проверьте права доступа к файлам и директориям
- Убедитесь, что команда `wg` доступна в системе

### VPN не перезапускается

- Проверьте, что Docker Compose файл находится в `DOCKER_COMPOSE_DIR`
- Убедитесь, что контейнер называется `amnezia-awg`
- Проверьте права доступа к Docker

## Лицензия

MIT

#!/bin/bash

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Функция для вывода сообщений
info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Проверка, что скрипт запущен от root или с sudo
if [ "$EUID" -ne 0 ]; then 
    warn "Скрипт требует прав root для установки системных пакетов"
    warn "Запустите: sudo $0"
    exit 1
fi

info "Начинаем установку Telegram Bot для управления Amnezia VPN..."

# Определяем директорию установки
INSTALL_DIR=$(pwd)
info "Директория установки: $INSTALL_DIR"

# 1. Установка системных зависимостей
info "Установка системных зависимостей..."
if command -v apt-get &> /dev/null; then
    apt-get update
    apt-get install -y python3 python3-pip python3-venv qrencode wireguard-tools curl
elif command -v yum &> /dev/null; then
    yum install -y python3 python3-pip qrencode wireguard-tools curl
    python3 -m ensurepip --upgrade
else
    error "Не удалось определить менеджер пакетов (apt-get/yum)"
    exit 1
fi

# 2. Создание виртуального окружения
info "Создание виртуального окружения..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    info "Виртуальное окружение создано"
else
    warn "Виртуальное окружение уже существует"
fi

# 3. Активация виртуального окружения и установка зависимостей
info "Установка Python зависимостей..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
info "Python зависимости установлены"

# 4. Создание .env файла
info "Настройка конфигурации..."

if [ -f ".env" ]; then
    warn "Файл .env уже существует"
    read -p "Перезаписать существующий .env? (y/N): " overwrite
    if [[ ! $overwrite =~ ^[Yy]$ ]]; then
        info "Пропускаем создание .env"
        exit 0
    fi
fi

# Копируем .env.example в .env
cp .env.example .env

# Загружаем текущие значения из .env как дефолты для запросов
while IFS= read -r line; do
    [[ $line =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || continue
    export "${line%%=*}=${line#*=}"
done < .env 2>/dev/null || true

# Функция для запроса значения с дефолтом
ask_with_default() {
    local prompt=$1
    local default=$2
    local var_name=$3
    
    read -p "$prompt [$default]: " value
    if [ -z "$value" ]; then
        value=$default
    fi
    eval "$var_name='$value'"
}

# Интерактивное заполнение .env
echo ""
info "Заполнение конфигурации .env файла..."
echo ""

# BOT_TOKEN
echo "Для получения токена бота:"
echo "1. Напишите @BotFather в Telegram"
echo "2. Отправьте /newbot"
echo "3. Следуйте инструкциям"
echo ""
read -p "Введите BOT_TOKEN [${BOT_TOKEN:-}]: " val
if [ -n "$val" ]; then BOT_TOKEN="$val"; fi
if [ -z "$BOT_TOKEN" ]; then
    error "BOT_TOKEN обязателен!"
    exit 1
fi

# ADMIN_IDS
echo ""
echo "Для получения вашего Telegram ID:"
echo "Напишите @userinfobot в Telegram"
echo ""
read -p "Введите ADMIN_IDS (через запятую, если несколько) [${ADMIN_IDS:-}]: " val
if [ -n "$val" ]; then ADMIN_IDS="$val"; fi
if [ -z "$ADMIN_IDS" ]; then
    error "ADMIN_IDS обязателен!"
    exit 1
fi

# VPN_CONFIG_DIR
ask_with_default "Введите VPN_CONFIG_DIR" "${VPN_CONFIG_DIR:-/opt/docker/liberty/config/wg}" VPN_CONFIG_DIR

# DOCKER_COMPOSE_DIR
ask_with_default "Введите DOCKER_COMPOSE_DIR" "${DOCKER_COMPOSE_DIR:-/opt/docker/liberty}" DOCKER_COMPOSE_DIR

# DB_PATH (пусто = clients.db в директории бота)
ask_with_default "Введите DB_PATH (пусто = по умолчанию)" "${DB_PATH:-}" DB_PATH

# CLIENT_NAME_PREFIX (пусто = без префикса)
ask_with_default "Введите CLIENT_NAME_PREFIX (например vpn_, пусто = без префикса)" "${CLIENT_NAME_PREFIX:-}" CLIENT_NAME_PREFIX

# VPN_CLIENT_START_IP
ask_with_default "Введите VPN_CLIENT_START_IP" "${VPN_CLIENT_START_IP:-10}" VPN_CLIENT_START_IP

# DNS_SERVERS
ask_with_default "Введите DNS_SERVERS (через запятую)" "${DNS_SERVERS:-1.1.1.1,8.8.8.8}" DNS_SERVERS

# WG_INTERFACE
ask_with_default "Введите WG_INTERFACE" "${WG_INTERFACE:-wg0}" WG_INTERFACE

# EXTERNAL_IF
DEFAULT_EXTERNAL_IF=$(ip route 2>/dev/null | grep default | awk '{print $5}' | head -1)
ask_with_default "Введите EXTERNAL_IF (внешний сетевой интерфейс)" "${EXTERNAL_IF:-${DEFAULT_EXTERNAL_IF:-eth0}}" EXTERNAL_IF

# Xray (опционально)
echo ""
info "Xray (VLESS Reality): при пустом — бот читает из DOCKER_COMPOSE_DIR/.install_info"
ask_with_default "Введите XRAY_CONFIG_DIR (пусто = из .install_info)" "${XRAY_CONFIG_DIR:-}" XRAY_CONFIG_DIR
ask_with_default "Введите XRAY_PUBLIC_KEY (пусто = из .install_info)" "${XRAY_PUBLIC_KEY:-}" XRAY_PUBLIC_KEY
ask_with_default "Введите XRAY_PORT (пусто = из .install_info)" "${XRAY_PORT:-}" XRAY_PORT
ask_with_default "Введите XRAY_SERVER_NAME / SNI (пусто = из .install_info)" "${XRAY_SERVER_NAME:-}" XRAY_SERVER_NAME
ask_with_default "Введите XRAY_SHORT_ID (пусто = из .install_info)" "${XRAY_SHORT_ID:-}" XRAY_SHORT_ID

# Записываем значения в .env
info "Запись конфигурации в .env файл..."
cat > .env << EOF
# Токен бота от BotFather
BOT_TOKEN=$BOT_TOKEN

# ID администраторов (через запятую)
ADMIN_IDS=$ADMIN_IDS

# Путь к директории с конфигурацией WireGuard (Liberty)
VPN_CONFIG_DIR=$VPN_CONFIG_DIR

# Путь к директории с docker-compose (Liberty)
DOCKER_COMPOSE_DIR=$DOCKER_COMPOSE_DIR

# Путь к SQLite БД клиентов (пусто = clients.db в директории бота)
DB_PATH=$DB_PATH

# Префикс имён клиентов (пусто = без префикса)
CLIENT_NAME_PREFIX=$CLIENT_NAME_PREFIX

# Начальный IP адрес для клиентов (последний октет)
VPN_CLIENT_START_IP=$VPN_CLIENT_START_IP

# DNS серверы для клиентов (через запятую)
DNS_SERVERS=$DNS_SERVERS

# Имя интерфейса WireGuard (обычно wg0)
WG_INTERFACE=$WG_INTERFACE

# Имя внешнего сетевого интерфейса для получения IP адреса
EXTERNAL_IF=$EXTERNAL_IF

# Xray (VLESS Reality): пусто = бот читает из DOCKER_COMPOSE_DIR/.install_info
XRAY_CONFIG_DIR=$XRAY_CONFIG_DIR
XRAY_PUBLIC_KEY=$XRAY_PUBLIC_KEY
XRAY_PORT=$XRAY_PORT
XRAY_SERVER_NAME=$XRAY_SERVER_NAME
XRAY_SHORT_ID=$XRAY_SHORT_ID
EOF

info ".env файл создан успешно!"

# 5. Проверка существования директорий
info "Проверка директорий..."
if [ ! -d "$VPN_CONFIG_DIR" ]; then
    warn "Директория $VPN_CONFIG_DIR не существует"
    read -p "Создать директорию? (y/N): " create_dir
    if [[ $create_dir =~ ^[Yy]$ ]]; then
        mkdir -p "$VPN_CONFIG_DIR"
        info "Директория $VPN_CONFIG_DIR создана"
    fi
fi

if [ ! -d "$DOCKER_COMPOSE_DIR" ]; then
    warn "Директория $DOCKER_COMPOSE_DIR не существует"
    read -p "Создать директорию? (y/N): " create_dir
    if [[ $create_dir =~ ^[Yy]$ ]]; then
        mkdir -p "$DOCKER_COMPOSE_DIR"
        info "Директория $DOCKER_COMPOSE_DIR создана"
    fi
fi

# 6. Предложение создать systemd сервис
echo ""
read -p "Создать systemd сервис для автозапуска? (y/N): " create_service
if [[ $create_service =~ ^[Yy]$ ]]; then
    SERVICE_FILE="/etc/systemd/system/vpn-bot.service"
    
    if [ -f "$SERVICE_FILE" ]; then
        warn "Сервис $SERVICE_FILE уже существует"
        read -p "Перезаписать? (y/N): " overwrite_service
        if [[ ! $overwrite_service =~ ^[Yy]$ ]]; then
            info "Пропускаем создание сервиса"
        else
            create_service="y"
        fi
    fi
    
    if [[ $create_service =~ ^[Yy]$ ]]; then
        info "Создание systemd сервиса..."
        cat > "$SERVICE_FILE" << EOF
[Unit]
Description=VPN Telegram Bot
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="PYTHONPATH=$INSTALL_DIR"
EnvironmentFile=$INSTALL_DIR/.env
ExecStart=$INSTALL_DIR/venv/bin/python -m bot.main
StandardOutput=journal
StandardError=journal
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        info "Сервис создан: $SERVICE_FILE"
        
        read -p "Включить автозапуск и запустить сервис сейчас? (y/N): " enable_service
        if [[ $enable_service =~ ^[Yy]$ ]]; then
            systemctl enable vpn-bot.service
            systemctl start vpn-bot.service
            info "Сервис включен и запущен"
            echo ""
            info "Проверка статуса сервиса:"
            systemctl status vpn-bot.service --no-pager
        else
            info "Для запуска сервиса выполните:"
            echo "  sudo systemctl enable vpn-bot.service"
            echo "  sudo systemctl start vpn-bot.service"
        fi
    fi
fi

echo ""
info "Установка завершена!"
echo ""
info "Для запуска бота вручную выполните:"
echo "  cd $INSTALL_DIR"
echo "  source venv/bin/activate"
echo "  python3 -m bot.main"
echo ""
info "Или используйте systemd сервис:"
echo "  sudo systemctl start vpn-bot.service"
echo "  sudo systemctl status vpn-bot.service"
echo ""

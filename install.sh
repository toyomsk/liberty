#!/bin/bash

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Переменные
INSTALL_DIR="/opt/docker/amnezia-wg"
CONFIG_DIR="$INSTALL_DIR/awg-config"
COMPOSE_FILE="$INSTALL_DIR/docker-compose.yml"
WG_CONFIG="$CONFIG_DIR/wg0.conf"

# Переменные конфигурации (будут заполнены интерактивно)
WG_NETWORK=""
WG_PORT=""
WG_SERVER_IP=""

# Счетчик шагов
STEP=0

# Функции логирования
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    STEP=$((STEP + 1))
    echo -e "\n${YELLOW}=== Шаг $STEP: $1 ===${NC}"
}

# Функция для запроса ввода с валидацией
prompt_input() {
    local prompt_text="$1"
    local default_value="$2"
    local validation_func="$3"
    local input_value=""
    
    while true; do
        if [ -n "$default_value" ]; then
            echo -ne "${BLUE}[?]${NC} $prompt_text [по умолчанию: $default_value]: " >&2
        else
            echo -ne "${BLUE}[?]${NC} $prompt_text: " >&2
        fi
        # Читаем из /dev/tty чтобы гарантировать чтение из терминала
        read input_value < /dev/tty
        
        # Использовать значение по умолчанию если ввод пустой
        if [ -z "$input_value" ] && [ -n "$default_value" ]; then
            input_value="$default_value"
        fi
        
        # Валидация
        if [ -n "$validation_func" ]; then
            if eval "$validation_func \"$input_value\""; then
                echo "$input_value"
                return 0
            else
                log_error "Неверный формат. Попробуйте снова."
            fi
        else
            echo "$input_value"
            return 0
        fi
    done
}

# Валидация CIDR сети
validate_network() {
    local network="$1"
    # Проверка формата CIDR
    if [[ ! "$network" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        return 1
    fi
    
    local ip_part=$(echo "$network" | cut -d'/' -f1)
    local mask_part=$(echo "$network" | cut -d'/' -f2)
    
    # Проверка маски (1-32)
    if ! [[ "$mask_part" =~ ^[0-9]+$ ]] || [ "$mask_part" -lt 1 ] || [ "$mask_part" -gt 32 ]; then
        return 1
    fi
    
    # Проверка каждого октета IP
    IFS='.' read -r -a octets <<< "$ip_part"
    for octet in "${octets[@]}"; do
        if ! [[ "$octet" =~ ^[0-9]+$ ]] || [ "$octet" -lt 0 ] || [ "$octet" -gt 255 ]; then
            return 1
        fi
    done
    
    return 0
}

# Валидация порта
validate_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
        return 0
    fi
    return 1
}

# Вычисление первого IP адреса в сети для сервера
calculate_server_ip() {
    local network="$1"
    local base_ip=$(echo "$network" | cut -d'/' -f1)
    
    # Разбиваем IP на октеты
    IFS='.' read -r -a octets <<< "$base_ip"
    
    # Увеличиваем последний октет на 1 для сервера
    local last_octet=${octets[3]}
    local server_last_octet=$((last_octet + 1))
    
    # Проверка что не превысили 255
    if [ $server_last_octet -gt 255 ]; then
        server_last_octet=1
        # Если последний октет был 255, увеличиваем третий
        local third_octet=${octets[2]}
        local new_third=$((third_octet + 1))
        if [ $new_third -le 255 ]; then
            octets[2]=$new_third
            server_last_octet=1
        fi
    fi
    
    local server_ip="${octets[0]}.${octets[1]}.${octets[2]}.$server_last_octet"
    
    echo "$server_ip/32"
}

# Интерактивный запрос параметров конфигурации
get_config_params() {
    log_step "Настройка параметров WireGuard"
    
    echo ""
    log_info "Настройка параметров конфигурации WireGuard"
    echo ""
    
    # Запрос сети
    WG_NETWORK=$(prompt_input "Введите сеть WireGuard (CIDR формат, например 10.10.1.0/24)" "10.10.1.0/24" "validate_network")
    
    # Проверка что переменная установлена правильно
    if [[ -z "$WG_NETWORK" ]] || [[ "$WG_NETWORK" =~ \[.*\] ]]; then
        log_error "Ошибка: не удалось получить сеть WireGuard"
        exit 1
    fi
    
    # Вычисление IP адреса сервера
    WG_SERVER_IP=$(calculate_server_ip "$WG_NETWORK")
    log_info "IP адрес сервера будет: $WG_SERVER_IP"
    
    # Запрос порта
    WG_PORT=$(prompt_input "Введите порт для прослушивания WireGuard" "51820" "validate_port")
    
    # Проверка что переменная установлена правильно
    if [[ -z "$WG_PORT" ]] || [[ "$WG_PORT" =~ \[.*\] ]]; then
        log_error "Ошибка: не удалось получить порт WireGuard"
        exit 1
    fi
    
    echo ""
    log_success "Параметры конфигурации:"
    log_info "  Сеть: $WG_NETWORK"
    log_info "  IP сервера: $WG_SERVER_IP"
    log_info "  Порт: $WG_PORT"
    echo ""
}

# Проверка прав доступа
check_root() {
    log_step "Проверка прав доступа"
    if [ "$EUID" -ne 0 ]; then 
        log_error "Скрипт должен быть запущен с правами root (используйте sudo)"
        exit 1
    fi
    log_success "Права доступа проверены"
}

# Проверка операционной системы
check_os() {
    log_step "Проверка операционной системы"
    if [ ! -f /etc/os-release ]; then
        log_error "Не удалось определить операционную систему"
        exit 1
    fi
    
    . /etc/os-release
    if [ "$ID" != "ubuntu" ]; then
        log_error "Скрипт предназначен для Ubuntu. Обнаружена ОС: $ID"
        exit 1
    fi
    log_success "Обнаружена Ubuntu: $VERSION"
}

# Проверка наличия необходимых утилит
check_utils() {
    log_step "Проверка необходимых утилит"
    local missing_utils=()
    local packages_to_install=()
    
    # Проверяем curl
    if ! command -v curl &> /dev/null; then
        missing_utils+=("curl")
        packages_to_install+=("curl")
    fi
    
    # Проверяем wg (wireguard-tools)
    if ! command -v wg &> /dev/null; then
        missing_utils+=("wg")
        packages_to_install+=("wireguard-tools")
    fi
    
    if [ ${#packages_to_install[@]} -gt 0 ]; then
        log_info "Установка недостающих утилит: ${missing_utils[*]}"
        
        # Временно отключаем set -e для команд apt
        set +e
        apt update -qq 2>&1 | grep -v "can be upgraded" || true
        local install_result=0
        apt install -y ${packages_to_install[*]} > /dev/null 2>&1 || install_result=$?
        set -e
        
        if [ $install_result -ne 0 ]; then
            log_error "Не удалось установить пакеты: ${packages_to_install[*]}"
            exit 1
        fi
        
        # Проверяем что утилиты действительно установились
        for util in "${missing_utils[@]}"; do
            if ! command -v $util &> /dev/null; then
                log_error "Утилита $util не найдена после установки"
                exit 1
            fi
        done
    fi
    
    log_success "Все необходимые утилиты доступны"
}

# Тюнинг системных параметров (sysctl и limits)
tune_system() {
    log_step "Настройка системных параметров (sysctl, limits)"

    log_info "Обновление /etc/sysctl.conf..."
    echo -e " \
  fs.file-max = 51200 \
  \
  net.ipv4.ip_forward = 1 \
  \
  net.core.rmem_max = 67108864 \
  net.core.wmem_max = 67108864 \
  net.core.netdev_max_backlog = 250000 \
  net.core.somaxconn = 4096 \
  \
  net.ipv4.tcp_syncookies = 1 \
  net.ipv4.tcp_tw_reuse = 1 \
  net.ipv4.tcp_tw_recycle = 0 \
  net.ipv4.tcp_fin_timeout = 30 \
  net.ipv4.tcp_keepalive_time = 1200 \
  net.ipv4.ip_local_port_range = 10000 65000 \
  net.ipv4.tcp_max_syn_backlog = 8192 \
  net.ipv4.tcp_max_tw_buckets = 5000 \
  net.ipv4.tcp_fastopen = 3 \
  net.ipv4.tcp_mem = 25600 51200 102400 \
  net.ipv4.tcp_rmem = 4096 87380 67108864 \
  net.ipv4.tcp_wmem = 4096 65536 67108864 \
  net.ipv4.tcp_mtu_probing = 1 \
  net.ipv4.tcp_congestion_control = hybla \
  # for low-latency network, use cubic instead \
  # net.ipv4.tcp_congestion_control = cubic \
  " | sed -e 's/^\s\+//g' | tee -a /etc/sysctl.conf > /dev/null

    log_info "Применение sysctl настроек..."
    sysctl -p > /dev/null 2>&1 || log_error "Не удалось применить sysctl -p, проверьте /etc/sysctl.conf"

    # Дополнительно явно включаем ip_forward на текущую сессию
    if [ -w /proc/sys/net/ipv4/ip_forward ]; then
        echo 1 > /proc/sys/net/ipv4/ip_forward || log_error "Не удалось установить /proc/sys/net/ipv4/ip_forward=1"
    fi

    log_info "Обновление /etc/security/limits.conf..."
    mkdir -p /etc/security
    echo -e " \
  * soft nofile 51200 \
  * hard nofile 51200 \
  " | sed -e 's/^\s\+//g' | tee -a /etc/security/limits.conf > /dev/null

    log_success "Системные параметры обновлены (возможно, потребуется relogin/перезагрузка для limits.conf)"
}

# Установка Docker
install_docker() {
    log_step "Установка Docker"
    
    # Удаление старых версий
    log_info "Удаление старых версий Docker..."
    apt remove docker docker-engine docker.io containerd runc -y > /dev/null 2>&1 || true
    apt autoremove -y > /dev/null 2>&1
    
    # Установка зависимостей
    log_info "Установка зависимостей..."
    apt update -qq
    apt install -y ca-certificates curl gnupg > /dev/null 2>&1
    
    # Добавление GPG ключа
    log_info "Добавление GPG ключа Docker..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    
    # Добавление репозитория
    log_info "Добавление репозитория Docker..."
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
      $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Установка Docker
    log_info "Установка Docker CE..."
    apt update -qq
    apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin > /dev/null 2>&1
    
    log_success "Docker установлен"
}

# Создание структуры директорий
create_directories() {
    log_step "Создание структуры директорий"
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    log_success "Директории созданы: $INSTALL_DIR"
}

# Генерация конфигурации WireGuard
generate_config() {
    log_step "Генерация конфигурации WireGuard"
    
    # Генерация ключей сервера
    log_info "Генерация ключей сервера..."
    SERVER_PRIVATE_KEY=$(wg genkey)
    SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | wg pubkey)
    
    # Генерация PSK
    log_info "Генерация PSK..."
    PSK=$(wg genpsk)
    
    # Получение внешнего IP
    log_info "Получение внешнего IP адреса..."
    EXTERNAL_IF=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -n "$EXTERNAL_IF" ]; then
        EXTERNAL_IP=$(ip addr show "$EXTERNAL_IF" | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1 | head -1)
        if [ -z "$EXTERNAL_IP" ]; then
            # Fallback на внешний сервис если не удалось получить IP интерфейса
            EXTERNAL_IP=$(curl -s ifconfig.me || curl -s icanhazip.com || echo "НЕ_ОПРЕДЕЛЕН")
        fi
    else
        # Fallback на внешний сервис если не удалось определить интерфейс
        EXTERNAL_IP=$(curl -s ifconfig.me || curl -s icanhazip.com || echo "НЕ_ОПРЕДЕЛЕН")
    fi
    
    # Генерация параметров obfuscation
    log_info "Генерация параметров obfuscation..."
    OBFS_Jc=$((RANDOM % 200 + 50))  # 50-250
    OBFS_Jmin=$((RANDOM % 300 + 300))  # 300-600
    OBFS_Jmax=$((RANDOM % 300 + 400))  # 400-700
    OBFS_S1=$((RANDOM % 50 + 10))  # 10-60
    OBFS_S2=$((RANDOM % 50 + 10))  # 10-60
    # H1-H4: случайные числа в диапазоне 0-2147483647 (32-bit)
    # Используем /dev/urandom для генерации больших случайных чисел
    OBFS_H1=$(( $(od -An -N4 -tu4 /dev/urandom | tr -d ' ') % 2147483648 ))
    OBFS_H2=$(( $(od -An -N4 -tu4 /dev/urandom | tr -d ' ') % 2147483648 ))
    OBFS_H3=$(( $(od -An -N4 -tu4 /dev/urandom | tr -d ' ') % 2147483648 ))
    OBFS_H4=$(( $(od -An -N4 -tu4 /dev/urandom | tr -d ' ') % 2147483648 ))
    
    # Создание базового конфига
    log_info "Создание конфигурации сервера..."
    
    # Проверка что переменные установлены правильно
    if [[ "$WG_SERVER_IP" =~ \[.*\] ]] || [[ "$WG_PORT" =~ \[.*\] ]]; then
        log_error "Ошибка: переменные конфигурации содержат недопустимые значения"
        log_error "WG_SERVER_IP=$WG_SERVER_IP"
        log_error "WG_PORT=$WG_PORT"
        exit 1
    fi
    
    cat > "$WG_CONFIG" << EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = $WG_SERVER_IP
ListenPort = $WG_PORT
Jc = $OBFS_Jc
Jmin = $OBFS_Jmin
Jmax = $OBFS_Jmax
S1 = $OBFS_S1
S2 = $OBFS_S2
H1 = $OBFS_H1
H2 = $OBFS_H2
H3 = $OBFS_H3
H4 = $OBFS_H4

PostUp = iptables -A INPUT -p udp --dport $WG_PORT -m conntrack --ctstate NEW -j ACCEPT --wait 10 --wait-interval 50; iptables -A FORWARD -i eth0 -o wg0 -j ACCEPT --wait 10 --wait-interval 50; iptables -A FORWARD -i wg0 -j ACCEPT --wait 10 --wait-interval 50; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE --wait 10 --wait-interval 50; ip6tables -A FORWARD -i wg0 -j ACCEPT --wait 10 --wait-interval 50; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE --wait 10 --wait-interval 50

PostDown = iptables -D INPUT -p udp --dport $WG_PORT -m conntrack --ctstate NEW -j ACCEPT --wait 10 --wait-interval 50; iptables -D FORWARD -i eth0 -o wg0 -j ACCEPT --wait 10 --wait-interval 50; iptables -D FORWARD -i wg0 -j ACCEPT --wait 10 --wait-interval 50; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE --wait 10 --wait-interval 50; ip6tables -D FORWARD -i wg0 -j ACCEPT --wait 10 --wait-interval 50; ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE --wait 10 --wait-interval 50
EOF
    
    log_success "Конфигурация WireGuard создана"
    log_info "Публичный ключ сервера: $SERVER_PUBLIC_KEY"
    log_info "Внешний IP сервера: $EXTERNAL_IP"
}

# Создание docker-compose.yml
create_docker_compose() {
    log_step "Создание docker-compose.yml"
    
    cat > "$COMPOSE_FILE" << EOF
services:
  amnezia-awg:
    image: amneziavpn/amnezia-wg:latest
    container_name: amnezia-awg

    network_mode: host

    privileged: true
    cap_add:
      - NET_ADMIN
      - SYS_MODULE

    volumes:
      - /lib/modules:/lib/modules:ro
      - ./awg-config:/opt/amnezia/awg

    command: >
      sh -c "awg-quick up /opt/amnezia/awg/wg0.conf && tail -f /dev/null"

    restart: always
EOF
    
    log_success "docker-compose.yml создан"
}

# Запуск контейнера
start_container() {
    log_step "Запуск контейнера"
    
    cd "$INSTALL_DIR"
    log_info "Запуск docker compose..."
    docker compose up -d
    
    # Небольшая задержка для запуска контейнера
    sleep 3
    
    log_success "Контейнер запущен"
}

# Проверка работоспособности
check_status() {
    log_step "Проверка работоспособности"
    
    local checks_passed=0
    local checks_failed=0
    
    # Проверка статуса контейнера
    log_info "Проверка статуса контейнера..."
    if docker ps | grep -q amnezia-awg; then
        log_success "Контейнер amnezia-awg запущен"
        checks_passed=$((checks_passed + 1))
    else
        log_error "Контейнер amnezia-awg не найден в списке запущенных"
        checks_failed=$((checks_failed + 1))
    fi
    
    # Проверка логов
    log_info "Проверка логов контейнера..."
    if docker logs amnezia-awg --tail 20 2>&1 | grep -q "wg0.conf\|WireGuard\|wg-quick"; then
        log_success "Логи контейнера выглядят нормально"
        checks_passed=$((checks_passed + 1))
    else
        log_error "Проблемы в логах контейнера"
        docker logs amnezia-awg --tail 20
        checks_failed=$((checks_failed + 1))
    fi
    
    # Проверка интерфейса wg0
    log_info "Проверка интерфейса wg0..."
    if ip a | grep -q wg0; then
        log_success "Интерфейс wg0 найден"
        checks_passed=$((checks_passed + 1))
    else
        log_error "Интерфейс wg0 не найден"
        checks_failed=$((checks_failed + 1))
    fi
    
    # Проверка конфигурации WireGuard
    log_info "Проверка конфигурации WireGuard..."
    if wg show &> /dev/null; then
        log_success "WireGuard конфигурация активна"
        checks_passed=$((checks_passed + 1))
        wg show
    else
        log_error "WireGuard конфигурация не активна"
        checks_failed=$((checks_failed + 1))
    fi
    
    # Проверка порта
    log_info "Проверка порта $WG_PORT..."
    if ss -ulnp 2>/dev/null | grep -q ":$WG_PORT "; then
        log_success "Порт $WG_PORT прослушивается"
        checks_passed=$((checks_passed + 1))
    else
        log_error "Порт $WG_PORT не прослушивается"
        checks_failed=$((checks_failed + 1))
    fi
    
    # Итоговый результат
    echo ""
    if [ $checks_failed -eq 0 ]; then
        log_success "Все проверки пройдены успешно ($checks_passed/$((checks_passed + checks_failed)))"
        return 0
    else
        log_error "Некоторые проверки не пройдены ($checks_passed успешно, $checks_failed ошибок)"
        return 1
    fi
}

# Вывод финальной информации
print_summary() {
    log_step "Итоговая информация"
    
    echo ""
    echo "=========================================="
    echo "  Установка завершена"
    echo "=========================================="
    echo ""
    echo "Директория установки: $INSTALL_DIR"
    echo "Конфигурация: $WG_CONFIG"
    echo ""
    echo "Параметры конфигурации:"
    echo "  Сеть: $WG_NETWORK"
    echo "  IP сервера: $WG_SERVER_IP"
    echo "  Порт: $WG_PORT"
    echo ""
    
    # Вывод публичного ключа сервера
    if [ -f "$WG_CONFIG" ]; then
        SERVER_PRIVATE_KEY=$(grep "PrivateKey" "$WG_CONFIG" | awk '{print $3}')
        SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | wg pubkey)
        echo "Публичный ключ сервера: $SERVER_PUBLIC_KEY"
        echo ""
    fi
    
    echo "Для просмотра логов: docker logs amnezia-awg"
    echo "Для остановки: cd $INSTALL_DIR && docker compose down"
    echo "Для перезапуска: cd $INSTALL_DIR && docker compose restart"
    echo ""
}

# Главная функция
main() {
    echo ""
    echo "=========================================="
    echo "  Установка amnezia-wg в Docker"
    echo "=========================================="
    echo ""
    
    check_root
    check_os
    check_utils
    tune_system

    # Запрос параметров конфигурации перед установкой
    get_config_params
    
    install_docker
    create_directories
    generate_config
    create_docker_compose
    start_container
    
    # Небольшая задержка перед проверками
    sleep 5
    
    if check_status; then
        print_summary
        exit 0
    else
        log_error "Установка завершена с ошибками. Проверьте логи выше."
        exit 1
    fi
}

# Запуск главной функции
main

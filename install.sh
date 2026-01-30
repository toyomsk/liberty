#!/bin/bash

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Переменные
INSTALL_DIR="/opt/docker/liberty"
CONFIG_DIR="$INSTALL_DIR/config"
COMPOSE_FILE="$INSTALL_DIR/docker-compose.yml"
WG_CONFIG="$CONFIG_DIR/wg/wg0.conf"
INSTALL_INFO_FILE="$INSTALL_DIR/.install_info"

# Переменные конфигурации (будут заполнены интерактивно)
WG_NETWORK=""
WG_PORT=""
WG_SERVER_IP=""
EXTERNAL_IF=""
EXTERNAL_IP=""

# Переменные для obfuscation (будут сохранены в метаданных)
OBFS_Jc=""
OBFS_Jmin=""
OBFS_Jmax=""
OBFS_S1=""
OBFS_S2=""
OBFS_H1=""
OBFS_H2=""
OBFS_H3=""
OBFS_H4=""
PSK=""

# Переменные для Xray-core (VLESS + XTLS-Reality + Vision)
XRAY_ENABLED=false
XRAY_PORT=""
XRAY_UUID=""
XRAY_SERVER_NAME=""
XRAY_SHORT_ID=""
XRAY_DEST=""
XRAY_XVER=0
XRAY_PRIVATE_KEY=""
XRAY_PUBLIC_KEY=""
XRAY_CONFIG="$CONFIG_DIR/xray/config.json"

# Переменные для нового пользователя
NEW_USER=""
NEW_USER_SSH_KEY=""
CREATE_USER=false

# Флаг: после установки сервера сразу установить бота (пункт меню 3)
INSTALL_BOT_AFTER_SERVER=""

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

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
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

# Валидация интерфейса
validate_interface() {
    local iface="$1"
    # Проверяем что интерфейс существует
    if ip link show "$iface" &>/dev/null; then
        return 0
    fi
    return 1
}

# Получение интерфейса по умолчанию
get_default_interface() {
    local default_if=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -n "$default_if" ]; then
        echo "$default_if"
    else
        echo "eth0"
    fi
}

# Валидация имени пользователя
validate_username() {
    local username="$1"
    # Проверка формата имени пользователя (только буквы, цифры, дефисы и подчеркивания, начинается с буквы)
    if [[ "$username" =~ ^[a-z][a-z0-9_-]*$ ]] && [ ${#username} -le 32 ]; then
        # Проверка что пользователь не существует
        if ! id "$username" &>/dev/null; then
            return 0
        else
            log_error "Пользователь $username уже существует"
            return 1
        fi
    else
        log_error "Неверный формат имени пользователя (только строчные буквы, цифры, дефисы и подчеркивания, начинается с буквы, до 32 символов)"
        return 1
    fi
}

# Валидация SSH ключа
validate_ssh_key() {
    local ssh_key="$1"
    # Проверка что это похоже на SSH ключ (начинается с ssh-rsa, ssh-ed25519, ecdsa и т.д.)
    if [[ "$ssh_key" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-dss) ]]; then
        return 0
    else
        log_error "Неверный формат SSH ключа. Ожидается ключ типа ssh-rsa, ssh-ed25519 и т.д."
        return 1
    fi
}

# Интерактивный запрос параметров пользователя
get_user_params() {
    log_step "Настройка пользователя и SSH"
    
    # Проверяем, есть ли уже созданный пользователь из предыдущей установки
    local existing_user=""
    
    # Сначала проверяем, загружена ли переменная NEW_USER из метаданных
    if [ -n "$NEW_USER" ] && id "$NEW_USER" &>/dev/null; then
        existing_user="$NEW_USER"
        log_info "Обнаружен существующий пользователь из предыдущей установки: $existing_user"
        log_info "Пропускаем создание пользователя"
        CREATE_USER=false
        return 0
    fi
    
    # Если переменная не загружена, проверяем файл метаданных напрямую
    if [ -z "$existing_user" ] && [ -f "$INSTALL_INFO_FILE" ]; then
        local saved_user=$(grep "^NEW_USER=" "$INSTALL_INFO_FILE" 2>/dev/null | cut -d'"' -f2)
        if [ -n "$saved_user" ] && id "$saved_user" &>/dev/null; then
            existing_user="$saved_user"
            log_info "Обнаружен существующий пользователь из предыдущей установки: $existing_user"
            log_info "Пропускаем создание пользователя"
            CREATE_USER=false
            NEW_USER="$existing_user"
            return 0
        fi
    fi
    
    # Проверяем наличие пользователей с sudo настройками (которые могли быть созданы скриптом)
    # Ищем пользователей с файлами в /etc/sudoers.d/ и SSH ключами
    if [ -z "$existing_user" ] && [ -d "/etc/sudoers.d" ]; then
        for sudo_file in /etc/sudoers.d/*; do
            if [ -f "$sudo_file" ] && grep -q "NOPASSWD: ALL" "$sudo_file" 2>/dev/null; then
                local potential_user=$(basename "$sudo_file")
                # Проверяем что это не системный пользователь и есть SSH директория
                if id "$potential_user" &>/dev/null && \
                   [ "$potential_user" != "root" ] && \
                   [ -d "/home/$potential_user/.ssh" ] && \
                   [ -f "/home/$potential_user/.ssh/authorized_keys" ]; then
                    existing_user="$potential_user"
                    log_info "Обнаружен существующий пользователь с SSH доступом: $existing_user"
                    log_info "Пропускаем создание пользователя"
                    CREATE_USER=false
                    NEW_USER="$existing_user"
                    return 0
                fi
            fi
        done
    fi
    
    echo ""
    log_info "Вы можете создать нового пользователя и настроить SSH безопасность"
    echo ""
    
    local create_user_choice=""
    while [[ ! "$create_user_choice" =~ ^[yYnN]$ ]]; do
        echo -ne "${BLUE}[?]${NC} Создать нового пользователя и настроить SSH? (y/n) [по умолчанию: n]: " >&2
        read create_user_choice < /dev/tty
        if [ -z "$create_user_choice" ]; then
            create_user_choice="n"
        fi
    done
    
    if [[ "$create_user_choice" =~ ^[yY]$ ]]; then
        CREATE_USER=true
        
        # Запрос имени пользователя
        NEW_USER=$(prompt_input "Введите имя нового пользователя" "" "validate_username")
        
        # Запрос SSH ключа
        echo ""
        log_info "Введите SSH публичный ключ (ssh-rsa, ssh-ed25519 и т.д.)"
        log_info "Пример: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ..."
        echo ""
        
        local ssh_key_input=""
        while true; do
            echo -ne "${BLUE}[?]${NC} SSH ключ: " >&2
            read ssh_key_input < /dev/tty
            
            if [ -z "$ssh_key_input" ]; then
                log_error "SSH ключ не может быть пустым"
                continue
            fi
            
            # Валидация SSH ключа
            if validate_ssh_key "$ssh_key_input"; then
                NEW_USER_SSH_KEY="$ssh_key_input"
                break
            else
                log_error "Неверный формат SSH ключа. Попробуйте снова."
            fi
        done
        
        echo ""
        log_success "Параметры пользователя:"
        log_info "  Имя пользователя: $NEW_USER"
        log_info "  SSH ключ: ${NEW_USER_SSH_KEY:0:50}..."
        echo ""
    else
        CREATE_USER=false
        log_info "Создание пользователя пропущено"
    fi
}

# Создание пользователя и настройка SSH
setup_user_and_ssh() {
    if [ "$CREATE_USER" != "true" ]; then
        return 0
    fi
    
    log_step "Создание пользователя и настройка SSH"
    
    # Проверка что пользователь не существует
    if id "$NEW_USER" &>/dev/null; then
        log_error "Пользователь $NEW_USER уже существует. Пропускаем создание пользователя."
        return 1
    fi
    
    # Создание пользователя
    log_info "Создание пользователя $NEW_USER..."
    useradd -m -s /bin/bash "$NEW_USER" || {
        log_error "Не удалось создать пользователя $NEW_USER"
        exit 1
    }
    log_success "Пользователь $NEW_USER создан"
    
    # Настройка sudo для нового пользователя
    log_info "Настройка sudo для пользователя $NEW_USER..."
    usermod -aG sudo "$NEW_USER" || {
        log_error "Не удалось добавить пользователя $NEW_USER в группу sudo"
        exit 1
    }
    log_success "Пользователь $NEW_USER добавлен в группу sudo"
    
    # Настройка sudo без пароля для нового пользователя
    log_info "Настройка sudo без пароля для пользователя $NEW_USER..."
    local sudoers_file="/etc/sudoers.d/$NEW_USER"
    echo "$NEW_USER ALL=(ALL) NOPASSWD: ALL" > "$sudoers_file"
    chmod 0440 "$sudoers_file"
    log_success "Sudo без пароля настроен для пользователя $NEW_USER"
    
    # Создание директории .ssh
    local ssh_dir="/home/$NEW_USER/.ssh"
    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"
    chown "$NEW_USER:$NEW_USER" "$ssh_dir"
    
    # Добавление SSH ключа
    log_info "Добавление SSH ключа..."
    echo "$NEW_USER_SSH_KEY" > "$ssh_dir/authorized_keys"
    chmod 600 "$ssh_dir/authorized_keys"
    chown "$NEW_USER:$NEW_USER" "$ssh_dir/authorized_keys"
    log_success "SSH ключ добавлен"
    
    # Настройка SSH для отключения root входа
    log_info "Настройка SSH для отключения root входа..."
    local sshd_config="/etc/ssh/sshd_config"
    
    # Создаем резервную копию
    cp "$sshd_config" "${sshd_config}.backup.$(date +%Y%m%d_%H%M%S)"
    
    # Отключаем root вход (обрабатываем закомментированные строки)
    if grep -qE "^[[:space:]]*PermitRootLogin" "$sshd_config"; then
        # Заменяем существующую строку (включая закомментированную)
        sed -i 's/^[[:space:]]*#*[[:space:]]*PermitRootLogin.*/PermitRootLogin no/' "$sshd_config"
    else
        echo "PermitRootLogin no" >> "$sshd_config"
    fi
    
    # Убеждаемся что парольная аутентификация включена для нового пользователя (на случай если нужно)
    if ! grep -qE "^[[:space:]]*PasswordAuthentication" "$sshd_config"; then
        echo "PasswordAuthentication yes" >> "$sshd_config"
    fi
    
    # Перезапуск SSH службы
    log_info "Перезапуск SSH службы..."
    systemctl restart ssh || {
        log_error "Не удалось перезапустить SSH службу. Проверьте конфигурацию вручную!"
        log_error "Резервная копия: ${sshd_config}.backup.*"
        exit 1
    }
    
    log_success "SSH настроен: root вход отключен"
    log_warning "ВАЖНО: Убедитесь, что вы можете подключиться как $NEW_USER перед закрытием текущей сессии!"
    echo ""
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

# Выбор типа VPN
choose_vpn_type() {
    echo "" >&2
    echo -e "${BLUE}[INFO]${NC} Выберите тип VPN для установки:" >&2
    echo "" >&2
    echo "  1) Только WireGuard" >&2
    echo "  2) Только Xray-core (VLESS + XTLS-Reality + Vision)" >&2
    echo "  3) Оба (WireGuard + Xray-core)" >&2
    echo "" >&2
    
    local vpn_choice=""
    while [[ ! "$vpn_choice" =~ ^[1-3]$ ]]; do
        echo -ne "${BLUE}[?]${NC} Ваш выбор (1-3) [по умолчанию: 1]: " >&2
        read vpn_choice < /dev/tty
        if [ -z "$vpn_choice" ]; then
            vpn_choice="1"
        fi
    done
    
    # Выводим только число в stdout, все остальное в stderr
    echo "$vpn_choice"
}

# Интерактивный запрос параметров конфигурации
get_config_params() {
    log_step "Настройка параметров VPN"

    echo ""
    log_info "Настройка параметров конфигурации VPN"
    echo ""
    
    # Выбор типа VPN
    local vpn_choice=$(choose_vpn_type)
    
    # Устанавливаем XRAY_ENABLED на основе выбора (в родительском процессе)
    # Убираем пробелы и переводы строк из выбора
    vpn_choice=$(echo "$vpn_choice" | tr -d '[:space:]')
    
    case "$vpn_choice" in
        1)
            XRAY_ENABLED=false
            log_info "Выбран только WireGuard"
            ;;
        2)
            XRAY_ENABLED=true
            log_info "Выбран только Xray-core"
            ;;
        3)
            XRAY_ENABLED=true
            log_info "Выбраны оба: WireGuard + Xray-core"
            ;;
        *)
            log_error "Неизвестный выбор VPN: '$vpn_choice', используем по умолчанию WireGuard"
            XRAY_ENABLED=false
            ;;
    esac
    
    # Настройка WireGuard (если не выбран только Xray)
    if [ "$vpn_choice" != "2" ]; then
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

        # Определение интерфейса по умолчанию
        local default_if=$(get_default_interface)

        # Запрос интерфейса для выхода в интернет
        EXTERNAL_IF=$(prompt_input "Введите интерфейс для выхода в интернет" "$default_if" "validate_interface")

        # Проверка что переменная установлена правильно
        if [[ -z "$EXTERNAL_IF" ]] || [[ "$EXTERNAL_IF" =~ \[.*\] ]]; then
            log_error "Ошибка: не удалось получить интерфейс"
            exit 1
        fi
    else
        # Если только Xray, все равно нужен интерфейс
        local default_if=$(get_default_interface)
        EXTERNAL_IF=$(prompt_input "Введите интерфейс для выхода в интернет" "$default_if" "validate_interface")
        if [[ -z "$EXTERNAL_IF" ]] || [[ "$EXTERNAL_IF" =~ \[.*\] ]]; then
            log_error "Ошибка: не удалось получить интерфейс"
            exit 1
        fi
    fi
    
    # Настройка Xray (если включен)
    if [ "$XRAY_ENABLED" = "true" ]; then
        echo ""
        log_info "Настройка параметров Xray-core"
        echo ""
        
        # Запрос порта Xray
        XRAY_PORT=$(prompt_input "Введите порт для Xray (VLESS)" "443" "validate_port")
        
        # Проверка что переменная установлена правильно
        if [[ -z "$XRAY_PORT" ]] || [[ "$XRAY_PORT" =~ \[.*\] ]]; then
            log_error "Ошибка: не удалось получить порт Xray"
            exit 1
        fi
        
        # Выбор SNI для Reality
        echo ""
        log_info "Выберите SNI (Server Name Indication) для Reality:"
        echo "  Можно выбрать популярный сайт для маскировки трафика"
        echo ""
        local sni_choice=""
        local sni_options=("microsoft.com" "cloudflare.com" "google.com" "apple.com" "amazon.com" "bing.com" "github.com" "netflix.com" "tiktok.com" "wikipedia.org" "bbc.com" "yahoo.com" "spotify.com" "Ввести вручную")
        local sni_count=${#sni_options[@]}
        local sni_index=1
        for sni_option in "${sni_options[@]}"; do
            echo "  $sni_index) $sni_option"
            sni_index=$((sni_index + 1))
        done
        echo ""
        
        while true; do
            echo -ne "${BLUE}[?]${NC} Ваш выбор (1-$sni_count) [по умолчанию: 1]: " >&2
            read sni_choice < /dev/tty
            if [ -z "$sni_choice" ]; then
                sni_choice="1"
            fi
            if [[ "$sni_choice" =~ ^[0-9]+$ ]] && [ "$sni_choice" -ge 1 ] && [ "$sni_choice" -le "$sni_count" ]; then
                break
            fi
        done
        
        if [ "$sni_choice" = "$sni_count" ]; then
            echo -ne "${BLUE}[?]${NC} Введите SNI вручную: " >&2
            read XRAY_SERVER_NAME < /dev/tty
            if [ -z "$XRAY_SERVER_NAME" ]; then
                XRAY_SERVER_NAME="microsoft.com"
                log_warning "SNI не введен, используется по умолчанию: $XRAY_SERVER_NAME"
            fi
        else
            XRAY_SERVER_NAME="${sni_options[$((sni_choice - 1))]}"
        fi
        
        # Destination для Reality (можно использовать тот же SNI)
        echo ""
        log_info "Destination для Reality (поддельный сайт)"
        XRAY_DEST=$(prompt_input "Введите destination (hostname:port)" "${XRAY_SERVER_NAME}:443" "")
        if [ -z "$XRAY_DEST" ]; then
            XRAY_DEST="${XRAY_SERVER_NAME}:443"
        fi
        
        echo ""
        log_success "Параметры Xray:"
        log_info "  Порт: $XRAY_PORT"
        log_info "  SNI: $XRAY_SERVER_NAME"
        log_info "  Destination: $XRAY_DEST"
        echo ""
    fi

    echo ""
    log_success "Параметры конфигурации:"
    if [ "$XRAY_ENABLED" != "true" ] || [ "$vpn_choice" != "2" ]; then
        log_info "  WireGuard сеть: $WG_NETWORK"
        log_info "  WireGuard IP сервера: $WG_SERVER_IP"
        log_info "  WireGuard порт: $WG_PORT"
    fi
    if [ "$XRAY_ENABLED" = "true" ]; then
        log_info "  Xray порт: $XRAY_PORT"
        log_info "  Xray SNI: $XRAY_SERVER_NAME"
    fi
    log_info "  Внешний интерфейс: $EXTERNAL_IF"
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

    # Проверяем ifconfig (net-tools)
    if ! command -v ifconfig &> /dev/null; then
        missing_utils+=("ifconfig")
        packages_to_install+=("net-tools")
    fi

    # Проверяем jq для работы с JSON (опционально, но полезно)
    if ! command -v jq &> /dev/null; then
        missing_utils+=("jq")
        packages_to_install+=("jq")
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
  net.core.default_qdisc = fq \
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
  net.ipv4.tcp_congestion_control = bbr \
  # for low-latency network: cubic; for high-latency: hybla \
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
    # Удаляем существующий ключ, если есть, чтобы избежать интерактивного запроса
    rm -f /etc/apt/keyrings/docker.gpg
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --batch --dearmor -o /etc/apt/keyrings/docker.gpg
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
    mkdir -p "$CONFIG_DIR/wg" "$CONFIG_DIR/xray"
    log_success "Директории созданы: $INSTALL_DIR"
}

# Генерация конфигурации WireGuard
generate_config() {
    log_step "Генерация конфигурации WireGuard"

    # Генерация ключей сервера через контейнер Amnezia WG
    log_info "Генерация ключей сервера (через контейнер)..."
    if ! command -v docker &>/dev/null || ! docker info &>/dev/null; then
        log_error "Для генерации ключей нужен Docker. Установите Docker и запустите скрипт снова."
        exit 1
    fi
    docker pull amneziavpn/amnezia-wg:latest -q >/dev/null 2>&1 || true
    SERVER_PRIVATE_KEY=$(docker run --rm amneziavpn/amnezia-wg:latest wg genkey 2>/dev/null | tr -d '\r\n')
    SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | docker run --rm -i amneziavpn/amnezia-wg:latest wg pubkey 2>/dev/null | tr -d '\r\n')

    # Генерация PSK (сохраняем для метаданных)
    log_info "Генерация PSK..."
    PSK=$(docker run --rm amneziavpn/amnezia-wg:latest wg genpsk 2>/dev/null | tr -d '\r\n')

    if [ -z "$SERVER_PRIVATE_KEY" ] || [ -z "$SERVER_PUBLIC_KEY" ] || [ -z "$PSK" ]; then
        log_error "Не удалось сгенерировать ключи WireGuard через контейнер"
        exit 1
    fi
    log_success "Ключи WireGuard сгенерированы"

    # Получение внешнего IP
    log_info "Получение внешнего IP адреса для интерфейса $EXTERNAL_IF..."
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

    # Генерация параметров obfuscation согласно документации AmneziaWG
    log_info "Генерация параметров obfuscation..."
    # Jc: количество junk пакетов (0-128, рекомендуется 3-10)
    OBFS_Jc=$((RANDOM % 8 + 3))  # 3-10
    
    # Jmin/Jmax: размер junk пакетов в байтах (0-1280, рекомендуется 50-1000 или 10-50)
    # Используем рекомендуемый диапазон 50-1000
    OBFS_Jmin=$((RANDOM % 950 + 50))  # 50-1000
    OBFS_Jmax=$((RANDOM % 950 + 50))  # 50-1000
    # Убеждаемся что Jmax >= Jmin
    if [ $OBFS_Jmax -lt $OBFS_Jmin ]; then
        local temp=$OBFS_Jmin
        OBFS_Jmin=$OBFS_Jmax
        OBFS_Jmax=$temp
    fi
    
    # S1, S2: случайные префиксы для handshake (0-64 байта, рекомендуется 15-150 с ограничением S1 + 56 ≠ S2)
    # Используем диапазон 15-64 (в пределах документации)
    OBFS_S1=$((RANDOM % 50 + 15))  # 15-64
    OBFS_S2=$((RANDOM % 50 + 15))  # 15-64
    # Убеждаемся что S1 + 56 ≠ S2 (требование документации)
    while [ $((OBFS_S1 + 56)) -eq $OBFS_S2 ]; do
        OBFS_S2=$((RANDOM % 50 + 15))
    done
    
    # H1-H4: динамические константы заголовков, заменяющие стандартные идентификаторы типов пакетов WireGuard
    # Генерируем случайные 32-bit числа
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
EOF
    
    # Устанавливаем правильные права доступа на конфиг
    chmod 600 "$WG_CONFIG"
    chown root:root "$WG_CONFIG"
    
    log_success "Конфигурация WireGuard создана"
    log_info "Публичный ключ сервера: $SERVER_PUBLIC_KEY"
    log_info "Внешний IP сервера: $EXTERNAL_IP"
    
    # Сохраняем метаданные после генерации конфига (без дополнительного шага)
    save_install_info "true"
}

# Генерация параметров Xray
generate_xray_params() {
    if [ "$XRAY_ENABLED" != "true" ]; then
        return 0
    fi
    
    log_step "Генерация параметров Xray"
    
    # Генерация UUID и x25519 только через контейнер Xray (Docker обязателен)
    if ! command -v docker &> /dev/null || ! docker info &> /dev/null; then
        log_error "Для Xray нужен Docker. Установите Docker и запустите скрипт снова."
        exit 1
    fi
    docker pull teddysun/xray:latest -q >/dev/null 2>&1 || true

    # Первый клиент не создаём — клиенты добавляются только через бота
    XRAY_UUID=""

    # Генерация короткого ID для Reality (8 байт в hex, 16 символов)
    log_info "Генерация короткого ID для Reality..."
    XRAY_SHORT_ID=$(openssl rand -hex 8 | head -c 16)
    if [ -z "$XRAY_SHORT_ID" ]; then
        # Fallback: используем случайные байты
        XRAY_SHORT_ID=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n' | head -c 16)
    fi
    log_success "Short ID сгенерирован: $XRAY_SHORT_ID"
    
    # Генерация x25519 ключей Reality только через контейнер Xray
    log_info "Генерация x25519 ключей Reality через контейнер Xray..."
    local key_output
    key_output=$(docker run --rm --entrypoint "" teddysun/xray:latest /usr/bin/xray x25519 2>&1) || \
    key_output=$(docker run --rm teddysun/xray:latest /usr/bin/xray x25519 2>&1) || \
    key_output=$(docker run --rm --entrypoint /usr/bin/xray teddysun/xray:latest x25519 2>&1) || true
    if echo "$key_output" | grep -qi "Private key:"; then
        XRAY_PRIVATE_KEY=$(echo "$key_output" | grep -i "Private key:" | sed 's/.*[Pp]rivate [Kk]ey:[[:space:]]*//' | tr -d '\r\n' | head -1)
        XRAY_PUBLIC_KEY=$(echo "$key_output" | grep -i "Public key:" | sed 's/.*[Pp]ublic [Kk]ey:[[:space:]]*//' | tr -d '\r\n' | head -1)
    fi
    if ([ -z "$XRAY_PRIVATE_KEY" ] || [ -z "$XRAY_PUBLIC_KEY" ]) && echo "$key_output" | grep -qi "PrivateKey:"; then
        [ -z "$XRAY_PRIVATE_KEY" ] && XRAY_PRIVATE_KEY=$(echo "$key_output" | grep -i "PrivateKey:" | sed 's/.*[Pp]rivate[Kk]ey:[[:space:]]*//' | tr -d '\r\n' | head -1)
        [ -z "$XRAY_PUBLIC_KEY" ] && XRAY_PUBLIC_KEY=$(echo "$key_output" | grep -i "Password:" | sed 's/.*[Pp]assword:[[:space:]]*//' | tr -d '\r\n' | head -1)
    fi
    if [ -z "$XRAY_PRIVATE_KEY" ] && echo "$key_output" | grep -q "Private:"; then
        XRAY_PRIVATE_KEY=$(echo "$key_output" | grep "Private:" | awk '{print $2}' | tr -d '\r\n' | head -1)
        [ -z "$XRAY_PUBLIC_KEY" ] && XRAY_PUBLIC_KEY=$(echo "$key_output" | grep "Public:" | awk '{print $2}' | tr -d '\r\n' | head -1)
    fi
    if [ -z "$XRAY_PRIVATE_KEY" ] || [ -z "$XRAY_PUBLIC_KEY" ]; then
        log_error "Не удалось сгенерировать x25519 ключи через контейнер Xray (проверьте вывод: xray x25519)"
        exit 1
    fi
    
    # Xray Reality ожидает base64.RawURLEncoding (документация: xray x25519 по умолчанию)
    # Преобразуем + → -, / → _ (стандартный base64 от OpenSSL в URL-safe)
    XRAY_PRIVATE_KEY=$(echo -n "$XRAY_PRIVATE_KEY" | tr '+/' '-_')
    XRAY_PUBLIC_KEY=$(echo -n "$XRAY_PUBLIC_KEY" | tr '+/' '-_')
    
    log_success "Ключи Reality сгенерированы"
    log_info "  Private Key: ${XRAY_PRIVATE_KEY:0:32}..."
    log_info "  Public Key: ${XRAY_PUBLIC_KEY:0:32}..."
    
    # XVER для Reality (обычно 0)
    XRAY_XVER=0
    
    echo ""
}

# Генерация конфигурации Xray
generate_xray_config() {
    if [ "$XRAY_ENABLED" != "true" ]; then
        return 0
    fi
    
    log_step "Генерация конфигурации Xray"
    
    # Проверка что все параметры установлены (XRAY_UUID не нужен — клиенты через бота)
    if [ -z "$XRAY_PORT" ] || [ -z "$XRAY_SERVER_NAME" ] || [ -z "$XRAY_SHORT_ID" ] || [ -z "$XRAY_DEST" ] || [ -z "$XRAY_PRIVATE_KEY" ]; then
        log_error "Не все параметры Xray установлены"
        exit 1
    fi
    
    log_info "Создание JSON конфигурации Xray (клиенты — пустой массив, добавляются через бота)..."
    
    # Создаем JSON конфиг для Xray; clients пустой — клиенты добавляются через Telegram-бота
    cat > "$XRAY_CONFIG" << EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": ${XRAY_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${XRAY_DEST}",
          "xver": ${XRAY_XVER},
          "serverNames": [
            "${XRAY_SERVER_NAME}"
          ],
          "privateKey": "${XRAY_PRIVATE_KEY}",
          "shortIds": [
            "${XRAY_SHORT_ID}"
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
EOF
    
    # Устанавливаем правильные права доступа
    chmod 600 "$XRAY_CONFIG"
    chown root:root "$XRAY_CONFIG"
    
    log_success "Конфигурация Xray создана: $XRAY_CONFIG"
    log_info "  Порт: $XRAY_PORT"
    log_info "  SNI: $XRAY_SERVER_NAME"
    log_info "  Public Key: ${XRAY_PUBLIC_KEY:0:32}..."
    echo ""
}

# Создание скрипта запуска Xray
create_xray_startup_script() {
    if [ "$XRAY_ENABLED" != "true" ]; then
        return 0
    fi
    
    log_step "Создание скрипта запуска Xray"
    
    local xray_startup_script="$INSTALL_DIR/start-xray.sh"
    
    cat > "$xray_startup_script" << 'XRAY_SCRIPT_EOF'
#!/bin/bash

echo "Xray container startup"

# Запуск Xray
exec xray -config /etc/xray/config.json
XRAY_SCRIPT_EOF
    
    chmod +x "$xray_startup_script"
    log_success "Скрипт запуска Xray создан: $xray_startup_script"
}

# Заглушка client.txt для Xray (клиенты добавляются через бота)
generate_xray_client_config() {
    if [ "$XRAY_ENABLED" != "true" ]; then
        return 0
    fi
    local client_config_file="$CONFIG_DIR/xray/client.txt"
    echo "# Клиенты Xray добавляются через Telegram-бота" > "$client_config_file"
    chmod 600 "$client_config_file"
    chown root:root "$client_config_file" 2>/dev/null || true
    log_info "Файл $client_config_file создан (заглушка)"
}

# Создание универсальных правил блокировки торрентов
setup_torrent_blocking() {
    log_step "Настройка универсальной блокировки торрентов"
    
    log_info "Применение правил блокировки торрент трафика..."
    
    # Определяем SSH порт для информационного сообщения
    local ssh_port=$(grep -E "^[[:space:]]*Port[[:space:]]+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
    if [ -z "$ssh_port" ]; then
        ssh_port=22
    fi
    
    # Блокируем только новые соединения на торрент порты (не установленные)
    # DHT ports: 6881-6889, 4444, 49001
    # Other common torrent ports: 51413
    # ВАЖНО: НЕ блокируем широкий диапазон 49152-65534, так как это динамические порты!
    
    # OUTPUT - исходящий трафик (только новые соединения)
    iptables -I OUTPUT -m state --state NEW -p tcp --dport 6881:6889 -j DROP 2>/dev/null || true
    iptables -I OUTPUT -m state --state NEW -p udp --dport 6881:6889 -j DROP 2>/dev/null || true
    iptables -I OUTPUT -m state --state NEW -p tcp --dport 4444 -j DROP 2>/dev/null || true
    iptables -I OUTPUT -m state --state NEW -p udp --dport 4444 -j DROP 2>/dev/null || true
    iptables -I OUTPUT -m state --state NEW -p tcp --dport 49001 -j DROP 2>/dev/null || true
    iptables -I OUTPUT -m state --state NEW -p udp --dport 49001 -j DROP 2>/dev/null || true
    iptables -I OUTPUT -m state --state NEW -p tcp --dport 51413 -j DROP 2>/dev/null || true
    iptables -I OUTPUT -m state --state NEW -p udp --dport 51413 -j DROP 2>/dev/null || true
    
    # INPUT - входящий трафик (только новые соединения)
    # Торрент порты не пересекаются с SSH (22) и VPN портами, поэтому безопасно блокировать
    iptables -I INPUT -m state --state NEW -p tcp --dport 6881:6889 -j DROP 2>/dev/null || true
    iptables -I INPUT -m state --state NEW -p udp --dport 6881:6889 -j DROP 2>/dev/null || true
    iptables -I INPUT -m state --state NEW -p tcp --dport 4444 -j DROP 2>/dev/null || true
    iptables -I INPUT -m state --state NEW -p udp --dport 4444 -j DROP 2>/dev/null || true
    iptables -I INPUT -m state --state NEW -p tcp --dport 49001 -j DROP 2>/dev/null || true
    iptables -I INPUT -m state --state NEW -p udp --dport 49001 -j DROP 2>/dev/null || true
    iptables -I INPUT -m state --state NEW -p tcp --dport 51413 -j DROP 2>/dev/null || true
    iptables -I INPUT -m state --state NEW -p udp --dport 51413 -j DROP 2>/dev/null || true
    
    # FORWARD - транзитный трафик (только новые соединения)
    iptables -I FORWARD -m state --state NEW -p tcp --dport 6881:6889 -j DROP 2>/dev/null || true
    iptables -I FORWARD -m state --state NEW -p udp --dport 6881:6889 -j DROP 2>/dev/null || true
    iptables -I FORWARD -m state --state NEW -p tcp --dport 4444 -j DROP 2>/dev/null || true
    iptables -I FORWARD -m state --state NEW -p udp --dport 4444 -j DROP 2>/dev/null || true
    iptables -I FORWARD -m state --state NEW -p tcp --dport 49001 -j DROP 2>/dev/null || true
    iptables -I FORWARD -m state --state NEW -p udp --dport 49001 -j DROP 2>/dev/null || true
    iptables -I FORWARD -m state --state NEW -p tcp --dport 51413 -j DROP 2>/dev/null || true
    iptables -I FORWARD -m state --state NEW -p udp --dport 51413 -j DROP 2>/dev/null || true
    
    # Блокировка BitTorrent протокола по строкам (только для новых соединений)
    # Исключаем SSH и VPN порты из проверки строк
    if iptables -m string --help &>/dev/null 2>&1; then
        # OUTPUT - только для новых соединений
        iptables -I OUTPUT -m state --state NEW -m string --string "BitTorrent" --algo bm -j DROP 2>/dev/null || true
        iptables -I OUTPUT -m state --state NEW -m string --string "BitTorrent protocol" --algo bm -j DROP 2>/dev/null || true
        iptables -I OUTPUT -m state --state NEW -m string --string "d1:ad2:id20:" --algo bm -j DROP 2>/dev/null || true
        iptables -I OUTPUT -m state --state NEW -m string --string "d1:md11:ut_metadata" --algo bm -j DROP 2>/dev/null || true
        
        # INPUT - только для новых соединений
        iptables -I INPUT -m state --state NEW -m string --string "BitTorrent" --algo bm -j DROP 2>/dev/null || true
        iptables -I INPUT -m state --state NEW -m string --string "BitTorrent protocol" --algo bm -j DROP 2>/dev/null || true
        iptables -I INPUT -m state --state NEW -m string --string "d1:ad2:id20:" --algo bm -j DROP 2>/dev/null || true
        iptables -I INPUT -m state --state NEW -m string --string "d1:md11:ut_metadata" --algo bm -j DROP 2>/dev/null || true
        
        # FORWARD - только для новых соединений
        iptables -I FORWARD -m state --state NEW -m string --string "BitTorrent" --algo bm -j DROP 2>/dev/null || true
        iptables -I FORWARD -m state --state NEW -m string --string "BitTorrent protocol" --algo bm -j DROP 2>/dev/null || true
        iptables -I FORWARD -m state --state NEW -m string --string "d1:ad2:id20:" --algo bm -j DROP 2>/dev/null || true
        iptables -I FORWARD -m state --state NEW -m string --string "d1:md11:ut_metadata" --algo bm -j DROP 2>/dev/null || true
    fi
    
    log_success "Универсальные правила блокировки торрентов применены"
    log_info "SSH порт ($ssh_port) и VPN порты исключены из блокировки"
}

# Удаление правил блокировки торрентов (при удалении установки)
remove_torrent_blocking() {
    log_info "Удаление правил блокировки торрентов..."
    # OUTPUT
    iptables -D OUTPUT -m state --state NEW -p tcp --dport 6881:6889 -j DROP 2>/dev/null || true
    iptables -D OUTPUT -m state --state NEW -p udp --dport 6881:6889 -j DROP 2>/dev/null || true
    iptables -D OUTPUT -m state --state NEW -p tcp --dport 4444 -j DROP 2>/dev/null || true
    iptables -D OUTPUT -m state --state NEW -p udp --dport 4444 -j DROP 2>/dev/null || true
    iptables -D OUTPUT -m state --state NEW -p tcp --dport 49001 -j DROP 2>/dev/null || true
    iptables -D OUTPUT -m state --state NEW -p udp --dport 49001 -j DROP 2>/dev/null || true
    iptables -D OUTPUT -m state --state NEW -p tcp --dport 51413 -j DROP 2>/dev/null || true
    iptables -D OUTPUT -m state --state NEW -p udp --dport 51413 -j DROP 2>/dev/null || true
    # INPUT
    iptables -D INPUT -m state --state NEW -p tcp --dport 6881:6889 -j DROP 2>/dev/null || true
    iptables -D INPUT -m state --state NEW -p udp --dport 6881:6889 -j DROP 2>/dev/null || true
    iptables -D INPUT -m state --state NEW -p tcp --dport 4444 -j DROP 2>/dev/null || true
    iptables -D INPUT -m state --state NEW -p udp --dport 4444 -j DROP 2>/dev/null || true
    iptables -D INPUT -m state --state NEW -p tcp --dport 49001 -j DROP 2>/dev/null || true
    iptables -D INPUT -m state --state NEW -p udp --dport 49001 -j DROP 2>/dev/null || true
    iptables -D INPUT -m state --state NEW -p tcp --dport 51413 -j DROP 2>/dev/null || true
    iptables -D INPUT -m state --state NEW -p udp --dport 51413 -j DROP 2>/dev/null || true
    # FORWARD
    iptables -D FORWARD -m state --state NEW -p tcp --dport 6881:6889 -j DROP 2>/dev/null || true
    iptables -D FORWARD -m state --state NEW -p udp --dport 6881:6889 -j DROP 2>/dev/null || true
    iptables -D FORWARD -m state --state NEW -p tcp --dport 4444 -j DROP 2>/dev/null || true
    iptables -D FORWARD -m state --state NEW -p udp --dport 4444 -j DROP 2>/dev/null || true
    iptables -D FORWARD -m state --state NEW -p tcp --dport 49001 -j DROP 2>/dev/null || true
    iptables -D FORWARD -m state --state NEW -p udp --dport 49001 -j DROP 2>/dev/null || true
    iptables -D FORWARD -m state --state NEW -p tcp --dport 51413 -j DROP 2>/dev/null || true
    iptables -D FORWARD -m state --state NEW -p udp --dport 51413 -j DROP 2>/dev/null || true
    # BitTorrent string rules
    if iptables -m string --help &>/dev/null 2>&1; then
        iptables -D OUTPUT -m state --state NEW -m string --string "BitTorrent" --algo bm -j DROP 2>/dev/null || true
        iptables -D OUTPUT -m state --state NEW -m string --string "BitTorrent protocol" --algo bm -j DROP 2>/dev/null || true
        iptables -D OUTPUT -m state --state NEW -m string --string "d1:ad2:id20:" --algo bm -j DROP 2>/dev/null || true
        iptables -D OUTPUT -m state --state NEW -m string --string "d1:md11:ut_metadata" --algo bm -j DROP 2>/dev/null || true
        iptables -D INPUT -m state --state NEW -m string --string "BitTorrent" --algo bm -j DROP 2>/dev/null || true
        iptables -D INPUT -m state --state NEW -m string --string "BitTorrent protocol" --algo bm -j DROP 2>/dev/null || true
        iptables -D INPUT -m state --state NEW -m string --string "d1:ad2:id20:" --algo bm -j DROP 2>/dev/null || true
        iptables -D INPUT -m state --state NEW -m string --string "d1:md11:ut_metadata" --algo bm -j DROP 2>/dev/null || true
        iptables -D FORWARD -m state --state NEW -m string --string "BitTorrent" --algo bm -j DROP 2>/dev/null || true
        iptables -D FORWARD -m state --state NEW -m string --string "BitTorrent protocol" --algo bm -j DROP 2>/dev/null || true
        iptables -D FORWARD -m state --state NEW -m string --string "d1:ad2:id20:" --algo bm -j DROP 2>/dev/null || true
        iptables -D FORWARD -m state --state NEW -m string --string "d1:md11:ut_metadata" --algo bm -j DROP 2>/dev/null || true
    fi
    log_success "Правила блокировки торрентов удалены"
}

# Открытие порта Xray в фаерволе (ufw или iptables)
open_firewall_xray_port() {
    [ "$XRAY_ENABLED" != "true" ] || [ -z "$XRAY_PORT" ] && return 0
    log_step "Открытие порта Xray $XRAY_PORT в фаерволе"
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        if ufw status 2>/dev/null | grep -q "${XRAY_PORT}/tcp"; then
            log_info "Порт $XRAY_PORT уже разрешён в ufw"
        else
            ufw allow "${XRAY_PORT}/tcp" comment 'Xray VLESS' 2>/dev/null || true
            log_success "Порт $XRAY_PORT открыт в ufw"
        fi
    else
        # iptables: разрешаем входящий TCP на порт Xray (в начало цепочки)
        if iptables -C INPUT -p tcp --dport "$XRAY_PORT" -j ACCEPT 2>/dev/null; then
            log_info "Порт $XRAY_PORT уже разрешён в iptables"
        else
            iptables -I INPUT -p tcp --dport "$XRAY_PORT" -j ACCEPT 2>/dev/null || true
            log_success "Порт $XRAY_PORT открыт в iptables"
        fi
    fi
}

# Открытие порта WireGuard в фаерволе (ufw или iptables, UDP)
open_firewall_wg_port() {
    [ -z "$WG_NETWORK" ] || [ -z "$WG_PORT" ] && return 0
    log_step "Открытие порта WireGuard $WG_PORT в фаерволе"
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        if ufw status 2>/dev/null | grep -q "${WG_PORT}/udp"; then
            log_info "Порт $WG_PORT уже разрешён в ufw"
        else
            ufw allow "${WG_PORT}/udp" comment 'WireGuard' 2>/dev/null || true
            log_success "Порт $WG_PORT открыт в ufw"
        fi
    else
        if iptables -C INPUT -p udp --dport "$WG_PORT" -j ACCEPT 2>/dev/null; then
            log_info "Порт $WG_PORT уже разрешён в iptables"
        else
            iptables -I INPUT -p udp --dport "$WG_PORT" -j ACCEPT 2>/dev/null || true
            log_success "Порт $WG_PORT открыт в iptables"
        fi
    fi
}

# Создание скрипта запуска контейнера
create_startup_script() {
    log_step "Создание скрипта запуска контейнера"
    
    local startup_script="$INSTALL_DIR/start-wg.sh"
    
    cat > "$startup_script" << 'SCRIPT_EOF'
#!/bin/bash

echo "Container startup"

# kill daemons in case of restart
wg-quick down /opt/amnezia/awg/wg0.conf 2>/dev/null || true

# start daemons if configured
if [ -f /opt/amnezia/awg/wg0.conf ]; then 
    wg-quick up /opt/amnezia/awg/wg0.conf
fi

# Allow traffic on the TUN interface.
iptables -A INPUT -i wg0 -j ACCEPT
iptables -A FORWARD -i wg0 -j ACCEPT
iptables -A OUTPUT -o wg0 -j ACCEPT

# Allow forwarding traffic only from the VPN.
iptables -A FORWARD -i wg0 -o EXTERNAL_IF_PLACEHOLDER -s WG_NETWORK_PLACEHOLDER -j ACCEPT

iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -t nat -A POSTROUTING -s WG_NETWORK_PLACEHOLDER -o EXTERNAL_IF_PLACEHOLDER -j MASQUERADE

tail -f /dev/null
SCRIPT_EOF
    
    # Заменяем плейсхолдеры на реальные значения (используем | как разделитель для sed)
    sed -i "s|EXTERNAL_IF_PLACEHOLDER|$EXTERNAL_IF|g" "$startup_script"
    sed -i "s|WG_NETWORK_PLACEHOLDER|$WG_NETWORK|g" "$startup_script"
    
    chmod +x "$startup_script"
    log_success "Скрипт запуска создан: $startup_script"
}

# Создание docker-compose.yml
create_docker_compose() {
    log_step "Создание docker-compose.yml"
    
    # Начинаем создание docker-compose.yml
    cat > "$COMPOSE_FILE" << 'COMPOSE_EOF'
services:
COMPOSE_EOF
    
    # Добавляем сервис WireGuard если он нужен
    if [ -n "$WG_NETWORK" ]; then
        cat >> "$COMPOSE_FILE" << EOF
  liberty-wg:
    image: amneziavpn/amnezia-wg:latest
    container_name: liberty-wg

    network_mode: host

    privileged: true
    cap_add:
      - NET_ADMIN
      - SYS_MODULE

    volumes:
      - /lib/modules:/lib/modules:ro
      - ./config/wg:/opt/amnezia/awg
      - ./start-wg.sh:/start-wg.sh:ro

    command: /start-wg.sh

    restart: always
EOF
    fi
    
    # Добавляем сервис Xray если он включен
    if [[ "$XRAY_ENABLED" == "true" ]]; then
        cat >> "$COMPOSE_FILE" << EOF
  xray-core:
    image: teddysun/xray:latest
    container_name: xray-core

    network_mode: host

    volumes:
      - ./config/xray/config.json:/etc/xray/config.json:ro

    command: ["/usr/bin/xray", "-config", "/etc/xray/config.json"]

    restart: always
EOF
    fi
    
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

    # Проверка статуса контейнера WireGuard (если установлен)
    if [ -n "$WG_NETWORK" ]; then
        log_info "Проверка статуса контейнера WireGuard..."
        if docker ps | grep -q liberty-wg; then
            log_success "Контейнер liberty-wg запущен"
            checks_passed=$((checks_passed + 1))
        else
            log_error "Контейнер liberty-wg не найден в списке запущенных"
            checks_failed=$((checks_failed + 1))
        fi

        # Проверка логов WireGuard
        log_info "Проверка логов контейнера WireGuard..."
        if docker logs liberty-wg --tail 20 2>&1 | grep -q "wg0.conf\|WireGuard\|wg-quick"; then
            log_success "Логи контейнера WireGuard выглядят нормально"
            checks_passed=$((checks_passed + 1))
        else
            log_error "Проблемы в логах контейнера WireGuard"
            docker logs liberty-wg --tail 20
            checks_failed=$((checks_failed + 1))
        fi

        # Проверка интерфейса wg0 и конфигурации WG внутри контейнера (на хосте wg0 нет)
        log_info "Проверка WireGuard в контейнере..."
        if docker exec liberty-wg wg show wg0 &>/dev/null; then
            log_success "WireGuard конфигурация активна (в контейнере)"
            checks_passed=$((checks_passed + 2))
            docker exec liberty-wg wg show wg0 2>/dev/null || true
        else
            log_error "WireGuard конфигурация не активна в контейнере"
            checks_failed=$((checks_failed + 2))
        fi

        # Проверка порта WireGuard
        if [ -n "$WG_PORT" ]; then
            log_info "Проверка порта WireGuard $WG_PORT..."
            if ss -ulnp 2>/dev/null | grep -q ":$WG_PORT "; then
                log_success "Порт WireGuard $WG_PORT прослушивается"
                checks_passed=$((checks_passed + 1))
            else
                log_error "Порт WireGuard $WG_PORT не прослушивается"
                checks_failed=$((checks_failed + 1))
            fi
        fi
    fi

    # Проверка статуса контейнера Xray (если установлен)
    if [ "$XRAY_ENABLED" = "true" ]; then
        log_info "Проверка статуса контейнера Xray..."
        if docker ps | grep -q xray-core; then
            log_success "Контейнер xray-core запущен"
            checks_passed=$((checks_passed + 1))
        else
            log_error "Контейнер xray-core не найден в списке запущенных"
            checks_failed=$((checks_failed + 1))
        fi

        # Проверка логов Xray
        log_info "Проверка логов контейнера Xray..."
        if docker logs xray-core --tail 20 2>&1 | grep -q "started\|listening\|VLESS"; then
            log_success "Логи контейнера Xray выглядят нормально"
            checks_passed=$((checks_passed + 1))
        else
            log_warning "Проверка логов Xray..."
            docker logs xray-core --tail 20
            checks_failed=$((checks_failed + 1))
        fi

        # Проверка порта Xray
        if [ -n "$XRAY_PORT" ]; then
            log_info "Проверка порта Xray $XRAY_PORT..."
            if ss -tlnp 2>/dev/null | grep -q ":$XRAY_PORT "; then
                log_success "Порт Xray $XRAY_PORT прослушивается"
                checks_passed=$((checks_passed + 1))
            else
                log_error "Порт Xray $XRAY_PORT не прослушивается"
                checks_failed=$((checks_failed + 1))
            fi
        fi
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

# Проверка существующей установки
check_existing_installation() {
    local installed=false
    
    # Проверка директории установки
    if [ -d "$INSTALL_DIR" ]; then
        installed=true
    fi
    
    # Проверка docker-compose.yml
    if [ -f "$COMPOSE_FILE" ]; then
        installed=true
    fi
    
    # Проверка конфига wg0.conf
    if [ -f "$WG_CONFIG" ]; then
        installed=true
    fi
    
    # Проверка запущенных контейнеров
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qE "^(liberty-wg|xray-core)$"; then
        installed=true
    fi
    
    if [ "$installed" = true ]; then
        return 0
    else
        return 1
    fi
}

# Сохранение метаданных установки
save_install_info() {
    local silent="${1:-false}"
    
    if [ "$silent" != "true" ]; then
        log_step "Сохранение метаданных установки"
    fi
    
    # Загружаем приватный ключ из конфига если он еще не загружен
    if [ -z "$SERVER_PRIVATE_KEY" ] && [ -f "$WG_CONFIG" ]; then
        SERVER_PRIVATE_KEY=$(grep "PrivateKey" "$WG_CONFIG" | awk '{print $3}')
        SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | wg pubkey)
    fi
    
    cat > "$INSTALL_INFO_FILE" << EOF
# Метаданные установки Liberty
# Создано: $(date)

EXTERNAL_IP="$EXTERNAL_IP"
WG_NETWORK="$WG_NETWORK"
WG_PORT="$WG_PORT"
EXTERNAL_IF="$EXTERNAL_IF"
NEW_USER="$NEW_USER"
OBFS_Jc="$OBFS_Jc"
OBFS_Jmin="$OBFS_Jmin"
OBFS_Jmax="$OBFS_Jmax"
OBFS_S1="$OBFS_S1"
OBFS_S2="$OBFS_S2"
OBFS_H1="$OBFS_H1"
OBFS_H2="$OBFS_H2"
OBFS_H3="$OBFS_H3"
OBFS_H4="$OBFS_H4"
SERVER_PRIVATE_KEY="$SERVER_PRIVATE_KEY"
SERVER_PUBLIC_KEY="$SERVER_PUBLIC_KEY"
PSK="$PSK"
XRAY_ENABLED="$XRAY_ENABLED"
XRAY_PORT="$XRAY_PORT"
XRAY_UUID="$XRAY_UUID"
XRAY_SERVER_NAME="$XRAY_SERVER_NAME"
XRAY_SHORT_ID="$XRAY_SHORT_ID"
XRAY_DEST="$XRAY_DEST"
XRAY_XVER="$XRAY_XVER"
XRAY_PRIVATE_KEY="$XRAY_PRIVATE_KEY"
XRAY_PUBLIC_KEY="$XRAY_PUBLIC_KEY"
EOF
    
    chmod 600 "$INSTALL_INFO_FILE"
    if [ "$silent" != "true" ]; then
        log_success "Метаданные сохранены в $INSTALL_INFO_FILE"
    fi
}

# Загрузка метаданных установки
load_install_info() {
    if [ ! -f "$INSTALL_INFO_FILE" ]; then
        log_error "Файл метаданных не найден: $INSTALL_INFO_FILE"
        return 1
    fi
    
    # Загружаем переменные из файла
    . "$INSTALL_INFO_FILE"
    
    log_success "Метаданные загружены"
    return 0
}

# Установка Telegram-бота для управления клиентами
install_bot() {
    local SCRIPT_DIR
    SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
    local BOT_DIR="$INSTALL_DIR/telegram-bot"

    log_step "Установка Telegram-бота"

    # Проверка наличия исходников бота
    if [ ! -d "$SCRIPT_DIR/telegram-bot" ] || [ ! -f "$SCRIPT_DIR/telegram-bot/requirements.txt" ]; then
        log_error "Директория telegram-bot не найдена рядом со скриптом или отсутствует requirements.txt"
        return 1
    fi

    # Установка системных зависимостей для бота
    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        apt-get install -y -qq python3 python3-pip python3-venv qrencode wireguard-tools curl 2>/dev/null || true
    elif command -v yum &>/dev/null; then
        yum install -y python3 python3-pip qrencode wireguard-tools curl 2>/dev/null || true
        python3 -m ensurepip --upgrade 2>/dev/null || true
    fi

    mkdir -p "$BOT_DIR"
    # Копируем файлы бота (исключая venv, __pycache__, .env, .git)
    if command -v rsync &>/dev/null; then
        rsync -a --exclude=venv --exclude=__pycache__ --exclude=.env --exclude=.git \
            "$SCRIPT_DIR/telegram-bot/" "$BOT_DIR/"
    else
        for item in "$SCRIPT_DIR/telegram-bot"/*; do
            [ -e "$item" ] || continue
            name=$(basename "$item")
            [ "$name" = "venv" ] || [ "$name" = ".env" ] || [ "$name" = ".git" ] && continue
            cp -R "$item" "$BOT_DIR/" 2>/dev/null || cp "$item" "$BOT_DIR/"
        done
        for dir in "$SCRIPT_DIR/telegram-bot"/bot "$SCRIPT_DIR/telegram-bot"/config; do
            [ -d "$dir" ] && [ ! -d "$BOT_DIR/$(basename "$dir")" ] && cp -R "$dir" "$BOT_DIR/"
        done
    fi

    # Виртуальное окружение и зависимости
    if [ ! -d "$BOT_DIR/venv" ]; then
        python3 -m venv "$BOT_DIR/venv"
        log_success "Виртуальное окружение создано"
    fi
    # shellcheck source=/dev/null
    "$BOT_DIR/venv/bin/pip" install -q --upgrade pip
    "$BOT_DIR/venv/bin/pip" install -q -r "$BOT_DIR/requirements.txt"
    log_success "Python-зависимости установлены"

    # .env: не перезаписывать без подтверждения
    local create_env=true
    if [ -f "$BOT_DIR/.env" ]; then
        echo ""
        local overwrite_env=""
        while [[ ! "$overwrite_env" =~ ^[yYnN]$ ]]; do
            echo -ne "${BLUE}[?]${NC} Файл .env уже существует. Перезаписать? (y/N): " >&2
            read overwrite_env < /dev/tty
        done
        [[ ! "$overwrite_env" =~ ^[yY]$ ]] && create_env=false
    fi

    if [ "$create_env" = true ]; then
        echo ""
        log_info "Введите BOT_TOKEN (от @BotFather) и ADMIN_IDS (Telegram ID через запятую)."
        local BOT_TOKEN="" ADMIN_IDS=""
        while [ -z "$BOT_TOKEN" ]; do
            echo -ne "${BLUE}[?]${NC} BOT_TOKEN: " >&2
            read BOT_TOKEN < /dev/tty
        done
        while [ -z "$ADMIN_IDS" ]; do
            echo -ne "${BLUE}[?]${NC} ADMIN_IDS (через запятую): " >&2
            read ADMIN_IDS < /dev/tty
        done
        local DEFAULT_EXTERNAL_IF="eth0"
        command -v ip &>/dev/null && DEFAULT_EXTERNAL_IF=$(ip route 2>/dev/null | grep default | awk '{print $5}' | head -1) || true
        [ -z "$DEFAULT_EXTERNAL_IF" ] && DEFAULT_EXTERNAL_IF="eth0"
        cat > "$BOT_DIR/.env" << EOF
# Токен бота от BotFather
BOT_TOKEN=$BOT_TOKEN

# ID администраторов (через запятую)
ADMIN_IDS=$ADMIN_IDS

# Путь к директории с конфигурацией WireGuard (Liberty)
VPN_CONFIG_DIR=$INSTALL_DIR/config/wg

# Путь к директории с docker-compose (Liberty)
DOCKER_COMPOSE_DIR=$INSTALL_DIR

# Начальный IP адрес для клиентов (последний октет)
VPN_CLIENT_START_IP=2

# DNS серверы для клиентов (через запятую)
DNS_SERVERS=1.1.1.1,8.8.8.8

# Имя интерфейса WireGuard (обычно wg0)
WG_INTERFACE=wg0

# Имя внешнего сетевого интерфейса
EXTERNAL_IF=$DEFAULT_EXTERNAL_IF
EOF
        chmod 600 "$BOT_DIR/.env"
        log_success "Файл .env создан"
    fi

    # Предложение systemd-сервиса
    echo ""
    local create_svc=""
    while [[ ! "$create_svc" =~ ^[yYnN]$ ]]; do
        echo -ne "${BLUE}[?]${NC} Создать systemd-сервис для автозапуска бота? (y/N): " >&2
        read create_svc < /dev/tty
    done
    if [[ "$create_svc" =~ ^[yY]$ ]]; then
        local SERVICE_FILE="/etc/systemd/system/liberty-bot.service"
        cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Liberty Telegram Bot (VPN management)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$BOT_DIR
Environment="PATH=$BOT_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="PYTHONPATH=$BOT_DIR"
EnvironmentFile=$BOT_DIR/.env
ExecStart=$BOT_DIR/venv/bin/python -m bot.main
StandardOutput=journal
StandardError=journal
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        log_success "Сервис создан: $SERVICE_FILE"
        local enable_svc=""
        while [[ ! "$enable_svc" =~ ^[yYnN]$ ]]; do
            echo -ne "${BLUE}[?]${NC} Включить автозапуск и запустить сервис сейчас? (y/N): " >&2
            read enable_svc < /dev/tty
        done
        if [[ "$enable_svc" =~ ^[yY]$ ]]; then
            systemctl enable liberty-bot.service
            systemctl start liberty-bot.service
            log_success "Сервис liberty-bot включен и запущен"
        fi
    fi

    echo ""
    log_success "Установка Telegram-бота завершена."
    log_info "Запуск вручную: cd $BOT_DIR && $BOT_DIR/venv/bin/python -m bot.main"
    log_info "Сервис: systemctl start liberty-bot.service"
    echo ""
}

# Интерактивное меню в начале (сервер / только бот / сервер и бот / выход)
show_start_menu() {
    echo ""
    echo "  1) Установить сервер (AWG + Xray)"
    echo "  2) Установить только Telegram-бота"
    echo "  3) Установить сервер (AWG + Xray) и Telegram-бота"
    echo "  4) Выход"
    echo ""
    local choice=""
    while [[ ! "$choice" =~ ^[1-4]$ ]]; do
        echo -ne "${BLUE}[?]${NC} Ваш выбор (1-4): " >&2
        read choice < /dev/tty
    done
    case "$choice" in
        1) ;;
        2)
            if [ -f "/opt/docker/liberty/.install_info" ]; then
                INSTALL_DIR="/opt/docker/liberty"
            else
                echo ""
                log_info "Укажите путь к установке Liberty (директория с .install_info и config/)."
                local path_liberty=""
                while [ -z "$path_liberty" ] || [ ! -d "$path_liberty" ]; do
                    echo -ne "${BLUE}[?]${NC} Путь [/opt/docker/liberty]: " >&2
                    read path_liberty < /dev/tty
                    [ -z "$path_liberty" ] && path_liberty="/opt/docker/liberty"
                    [ ! -d "$path_liberty" ] && log_error "Директория не найдена: $path_liberty"
                done
                INSTALL_DIR="$path_liberty"
            fi
            install_bot
            exit 0
            ;;
        3)
            INSTALL_BOT_AFTER_SERVER=1
            ;;
        4)
            log_info "Выход из скрипта"
            exit 0
            ;;
    esac
}

# Интерактивное меню выбора действия (при существующей установке)
show_installation_menu() {
    echo ""
    echo "=========================================="
    echo "  Обнаружена существующая установка"
    echo "=========================================="
    echo ""
    log_info "Выберите действие:"
    echo ""
    echo "  1) Удаление всего установленного"
    echo "  2) Полная переустановка с нуля"
    echo "  3) Изменение IP-адреса и порта сервера"
    echo "  4) Установить или переустановить Telegram-бота"
    echo "  5) Выход"
    echo ""
    
    local choice=""
    while [[ ! "$choice" =~ ^[1-5]$ ]]; do
        echo -ne "${BLUE}[?]${NC} Ваш выбор (1-5): " >&2
        read choice < /dev/tty
    done
    
    case "$choice" in
        1)
            uninstall
            exit 0
            ;;
        2)
            reinstall
            ;;
        3)
            change_server_ip
            exit 0
            ;;
        4)
            install_bot
            log_info "Для выхода запустите скрипт снова."
            exit 0
            ;;
        5)
            log_info "Выход из скрипта"
            exit 0
            ;;
    esac
}

# Удаление установки
uninstall() {
    local skip_confirm="${1:-false}"
    
    if [ "$skip_confirm" != "true" ]; then
        log_step "Удаление установки"
        
        echo ""
        log_warning "ВНИМАНИЕ: Это действие удалит все установленные компоненты!"
        log_info "Будут удалены:"
        log_info "  - Docker контейнер liberty-wg (если установлен)"
        log_info "  - Docker контейнер xray-core (если установлен)"
        log_info "  - Директория $INSTALL_DIR со всем содержимым"
        log_info "  - Все конфигурации и клиентские конфиги"
        echo ""
        
        local confirm=""
        while [[ ! "$confirm" =~ ^[yYnN]$ ]]; do
            echo -ne "${RED}[?]${NC} Вы уверены? (y/n): " >&2
            read confirm < /dev/tty
        done
        
        if [[ ! "$confirm" =~ ^[yY]$ ]]; then
            log_info "Удаление отменено"
            return 1
        fi
    fi

    # Загружаем метаданные для удаления правил фаервола (до удаления директории)
    local uninstall_wg_port=""
    local uninstall_xray_port=""
    local uninstall_xray_enabled=""
    if [ -f "$INSTALL_INFO_FILE" ]; then
        # shellcheck source=/dev/null
        . "$INSTALL_INFO_FILE" 2>/dev/null || true
        uninstall_wg_port="$WG_PORT"
        uninstall_xray_port="$XRAY_PORT"
        uninstall_xray_enabled="$XRAY_ENABLED"
    fi
    # Удаление правил фаервола (порты WG и Xray)
    log_info "Удаление правил фаервола для портов Liberty..."
    if [ -n "$uninstall_wg_port" ]; then
        if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
            ufw delete allow "${uninstall_wg_port}/udp" 2>/dev/null || true
        else
            iptables -D INPUT -p udp --dport "$uninstall_wg_port" -j ACCEPT 2>/dev/null || true
        fi
        log_info "Правило для WireGuard (порт $uninstall_wg_port) удалено"
    fi
    if [ "$uninstall_xray_enabled" = "true" ] && [ -n "$uninstall_xray_port" ]; then
        if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
            ufw delete allow "${uninstall_xray_port}/tcp" 2>/dev/null || true
        else
            iptables -D INPUT -p tcp --dport "$uninstall_xray_port" -j ACCEPT 2>/dev/null || true
        fi
        log_info "Правило для Xray (порт $uninstall_xray_port) удалено"
    fi
    remove_torrent_blocking

    # Остановка и удаление контейнеров
    cd "$INSTALL_DIR" 2>/dev/null && docker compose down 2>/dev/null || true
    
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^liberty-wg$"; then
        log_info "Остановка контейнера liberty-wg..."
        docker stop liberty-wg 2>/dev/null || true
        docker rm liberty-wg 2>/dev/null || true
        log_success "Контейнер liberty-wg удален"
    fi
    
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^xray-core$"; then
        log_info "Остановка контейнера xray-core..."
        docker stop xray-core 2>/dev/null || true
        docker rm xray-core 2>/dev/null || true
        log_success "Контейнер xray-core удален"
    fi
    
    # Удаление директории установки
    if [ -d "$INSTALL_DIR" ]; then
        log_info "Удаление директории $INSTALL_DIR..."
        rm -rf "$INSTALL_DIR"
        log_success "Директория удалена"
    fi
    
    log_success "Удаление завершено"
    echo ""
    log_info "Примечание: Созданный пользователь и его настройки не были удалены"
    return 0
}

# Переустановка
reinstall() {
    log_step "Переустановка"
    
    echo ""
    log_warning "Будет выполнена полная переустановка с нуля"
    log_info "Все текущие данные будут удалены"
    echo ""
    
    local confirm=""
    while [[ ! "$confirm" =~ ^[yYnN]$ ]]; do
        echo -ne "${BLUE}[?]${NC} Продолжить? (y/n): " >&2
        read confirm < /dev/tty
    done
    
    if [[ ! "$confirm" =~ ^[yY]$ ]]; then
        log_info "Переустановка отменена"
        show_installation_menu
        return 0
    fi
    
    # Удаляем существующую установку (без подтверждения, так как уже подтвердили)
    if ! uninstall "true"; then
        log_error "Не удалось удалить существующую установку"
        exit 1
    fi
    
    # Сбрасываем счетчик шагов для новой установки
    STEP=0
    
    # Продолжаем стандартную установку
    log_info "Начинаем новую установку..."
    echo ""
}

# Изменение IP-адреса и порта сервера
change_server_ip() {
    log_step "Изменение IP-адреса и порта сервера"
    
    # Пытаемся загрузить метаданные или извлекаем из конфигов
    local metadata_loaded=false
    if load_install_info 2>/dev/null; then
        metadata_loaded=true
        log_info "Метаданные загружены из файла"
    else
        log_warning "Файл метаданных не найден, извлекаем информацию из конфигов..."
        
        # Извлекаем порт из серверного конфига
        if [ -f "$WG_CONFIG" ]; then
            WG_PORT=$(grep -E "^[[:space:]]*ListenPort[[:space:]]*=" "$WG_CONFIG" | awk '{print $3}' | head -1)
            if [ -z "$WG_PORT" ]; then
                log_error "Не удалось определить порт из конфига $WG_CONFIG"
                exit 1
            fi
            log_info "Порт извлечен из конфига: $WG_PORT"
        else
            log_error "Не найден серверный конфиг: $WG_CONFIG"
            exit 1
        fi
        
        # Пытаемся определить внешний IP из клиентских конфигов или автоматически
        EXTERNAL_IP=""
        if [ -d "$INSTALL_DIR" ]; then
            # Ищем первый клиентский конфиг с Endpoint
            local first_client_config=$(find "$INSTALL_DIR" -name "*.conf" -type f ! -name "wg0.conf" 2>/dev/null | head -1)
            if [ -n "$first_client_config" ] && [ -f "$first_client_config" ]; then
                local endpoint_line=$(grep -E "^[[:space:]]*Endpoint[[:space:]]*=" "$first_client_config" | head -1)
                if [ -n "$endpoint_line" ]; then
                    EXTERNAL_IP=$(echo "$endpoint_line" | sed -E 's/^[[:space:]]*Endpoint[[:space:]]*=[[:space:]]*//' | cut -d':' -f1)
                    log_info "IP извлечен из клиентского конфига: $EXTERNAL_IP"
                fi
            fi
        fi
        
        # Если не удалось определить IP, пытаемся получить из интерфейса или внешнего сервиса
        if [ -z "$EXTERNAL_IP" ]; then
            log_info "Попытка определить внешний IP автоматически..."
            # Определяем интерфейс по умолчанию
            local default_if=$(get_default_interface)
            if [ -n "$default_if" ]; then
                EXTERNAL_IP=$(ip addr show "$default_if" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1 | head -1)
            fi
            
            # Fallback на внешний сервис
            if [ -z "$EXTERNAL_IP" ]; then
                EXTERNAL_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com 2>/dev/null || echo "")
            fi
            
            if [ -z "$EXTERNAL_IP" ]; then
                log_warning "Не удалось определить текущий внешний IP автоматически. Потребуется ввод вручную."
                EXTERNAL_IP=""
            else
                log_info "Внешний IP определен автоматически: $EXTERNAL_IP"
            fi
        fi
        
        # Загружаем остальные параметры из конфига если возможно
        if [ -f "$WG_CONFIG" ]; then
            WG_NETWORK=""
            EXTERNAL_IF=""
            # Пытаемся извлечь другие параметры если нужно
            OBFS_Jc=$(grep -E "^[[:space:]]*Jc[[:space:]]*=" "$WG_CONFIG" | awk '{print $3}' | head -1)
            OBFS_Jmin=$(grep -E "^[[:space:]]*Jmin[[:space:]]*=" "$WG_CONFIG" | awk '{print $3}' | head -1)
            OBFS_Jmax=$(grep -E "^[[:space:]]*Jmax[[:space:]]*=" "$WG_CONFIG" | awk '{print $3}' | head -1)
            OBFS_S1=$(grep -E "^[[:space:]]*S1[[:space:]]*=" "$WG_CONFIG" | awk '{print $3}' | head -1)
            OBFS_S2=$(grep -E "^[[:space:]]*S2[[:space:]]*=" "$WG_CONFIG" | awk '{print $3}' | head -1)
            OBFS_H1=$(grep -E "^[[:space:]]*H1[[:space:]]*=" "$WG_CONFIG" | awk '{print $3}' | head -1)
            OBFS_H2=$(grep -E "^[[:space:]]*H2[[:space:]]*=" "$WG_CONFIG" | awk '{print $3}' | head -1)
            OBFS_H3=$(grep -E "^[[:space:]]*H3[[:space:]]*=" "$WG_CONFIG" | awk '{print $3}' | head -1)
            OBFS_H4=$(grep -E "^[[:space:]]*H4[[:space:]]*=" "$WG_CONFIG" | awk '{print $3}' | head -1)
            SERVER_PRIVATE_KEY=$(grep -E "^[[:space:]]*PrivateKey[[:space:]]*=" "$WG_CONFIG" | awk '{print $3}' | head -1)
            if [ -n "$SERVER_PRIVATE_KEY" ]; then
                SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | wg pubkey)
            fi
        fi
    fi
    
    # Если Xray установлен — подгружаем порт и SNI из конфига (если не из метаданных)
    if [ -f "$XRAY_CONFIG" ]; then
        if [ -z "$XRAY_PORT" ]; then
            XRAY_PORT=$(grep -E '"port"' "$XRAY_CONFIG" | head -1 | sed -E 's/.*"port"[[:space:]]*:[[:space:]]*([0-9]+).*/\1/')
        fi
        if [ -z "$XRAY_SERVER_NAME" ]; then
            XRAY_SERVER_NAME=$(sed -n '/serverNames/,/]/p' "$XRAY_CONFIG" | grep -oE '"[^"]+"' | head -1 | tr -d '"')
        fi
        [ -z "$XRAY_DEST" ] && XRAY_DEST="${XRAY_SERVER_NAME}:443"
    fi

    echo ""
    log_info "Текущий внешний IP сервера: ${EXTERNAL_IP:-не определен}"
    log_info "Текущий порт WireGuard: $WG_PORT"
    if [ -f "$XRAY_CONFIG" ]; then
        log_info "Текущий порт Xray: ${XRAY_PORT:-—}"
        log_info "Текущий SNI Xray: ${XRAY_SERVER_NAME:-—}"
    fi
    echo ""

    # Запрос нового IP
    local new_ip=""
    local ip_valid=false
    
    while [ "$ip_valid" = false ]; do
        if [ -z "$EXTERNAL_IP" ]; then
            echo -ne "${BLUE}[?]${NC} Введите новый внешний IP-адрес сервера: " >&2
        else
            echo -ne "${BLUE}[?]${NC} Введите новый внешний IP-адрес сервера [по умолчанию: $EXTERNAL_IP]: " >&2
        fi
        read new_ip < /dev/tty
        
        # Использовать текущий IP если ввод пустой и IP определен
        if [ -z "$new_ip" ] && [ -n "$EXTERNAL_IP" ]; then
            new_ip="$EXTERNAL_IP"
        fi
        
        # Если IP не был определен и ввод пустой, требуем ввод
        if [ -z "$new_ip" ]; then
            log_error "IP-адрес обязателен для ввода"
            continue
        fi
        
        # Простая валидация IP
        if [[ "$new_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            local valid_octets=true
            IFS='.' read -r -a octets <<< "$new_ip"
            for octet in "${octets[@]}"; do
                if ! [[ "$octet" =~ ^[0-9]+$ ]] || [ "$octet" -lt 0 ] || [ "$octet" -gt 255 ]; then
                    valid_octets=false
                    break
                fi
            done
            
            if [ "$valid_octets" = true ]; then
                ip_valid=true
            else
                log_error "Неверный формат IP-адреса"
            fi
        else
            log_error "Неверный формат IP-адреса (ожидается формат: x.x.x.x)"
        fi
    done
    
    echo ""
    
    # Запрос нового порта
    local new_port=""
    local port_valid=false
    
    while [ "$port_valid" = false ]; do
        echo -ne "${BLUE}[?]${NC} Введите новый порт WireGuard [по умолчанию: $WG_PORT]: " >&2
        read new_port < /dev/tty
        
        # Использовать текущий порт если ввод пустой
        if [ -z "$new_port" ]; then
            new_port="$WG_PORT"
        fi
        
        # Валидация порта
        if validate_port "$new_port"; then
            port_valid=true
        else
            log_error "Неверный формат порта (должно быть число от 1 до 65535)"
        fi
    done

    # Запрос нового порта и SNI для Xray (если Xray установлен)
    local new_xray_port=""
    local new_xray_sni=""
    if [ -f "$XRAY_CONFIG" ]; then
        echo ""
        log_info "Параметры Xray (порт и SNI)"
        # Порт Xray
        local xray_port_valid=false
        while [ "$xray_port_valid" = false ]; do
            echo -ne "${BLUE}[?]${NC} Введите порт Xray (VLESS) [по умолчанию: ${XRAY_PORT:-443}]: " >&2
            read new_xray_port < /dev/tty
            if [ -z "$new_xray_port" ]; then
                new_xray_port="${XRAY_PORT:-443}"
            fi
            if validate_port "$new_xray_port"; then
                xray_port_valid=true
            else
                log_error "Неверный формат порта (1–65535)"
            fi
        done
        # SNI
        local sni_options=("microsoft.com" "cloudflare.com" "google.com" "apple.com" "amazon.com" "bing.com" "github.com" "netflix.com" "tiktok.com" "wikipedia.org" "bbc.com" "yahoo.com" "spotify.com" "Ввести вручную")
        local sni_count=${#sni_options[@]}
        log_info "Выберите новый SNI для Reality [текущий: ${XRAY_SERVER_NAME:-—}]:"
        local sni_index=1
        for sni_option in "${sni_options[@]}"; do
            echo "  $sni_index) $sni_option" >&2
            sni_index=$((sni_index + 1))
        done
        local sni_choice=""
        while true; do
            echo -ne "${BLUE}[?]${NC} Ваш выбор (1-$sni_count) [Enter — оставить текущий]: " >&2
            read sni_choice < /dev/tty
            if [ -z "$sni_choice" ]; then
                new_xray_sni="$XRAY_SERVER_NAME"
                break
            fi
            if [[ "$sni_choice" =~ ^[0-9]+$ ]] && [ "$sni_choice" -ge 1 ] && [ "$sni_choice" -le "$sni_count" ]; then
                if [ "$sni_choice" = "$sni_count" ]; then
                    echo -ne "${BLUE}[?]${NC} Введите SNI вручную: " >&2
                    read new_xray_sni < /dev/tty
                    [ -z "$new_xray_sni" ] && new_xray_sni="$XRAY_SERVER_NAME"
                else
                    new_xray_sni="${sni_options[$((sni_choice - 1))]}"
                fi
                break
            fi
        done
        new_xray_sni="${new_xray_sni:-$XRAY_SERVER_NAME}"
        [ -z "$new_xray_sni" ] && new_xray_sni="microsoft.com"
    fi

    echo ""
    log_info "Поиск клиентских конфигов..."
    
    # Поиск всех клиентских конфигов (все .conf файлы кроме wg0.conf)
    local client_configs=()
    local updated_count=0
    
    # Ищем в INSTALL_DIR и поддиректориях
    if [ -d "$INSTALL_DIR" ]; then
        while IFS= read -r config_file; do
            if [ -n "$config_file" ] && [ -f "$config_file" ]; then
                local basename_file=$(basename "$config_file")
                if [ "$basename_file" != "wg0.conf" ]; then
                    client_configs+=("$config_file")
                fi
            fi
        done < <(find "$INSTALL_DIR" -name "*.conf" -type f 2>/dev/null)
    fi
    
    if [ ${#client_configs[@]} -eq 0 ]; then
        log_warning "Клиентские конфиги не найдены"
    else
        log_info "Найдено клиентских конфигов: ${#client_configs[@]}"
        echo ""
        
        # Создаем резервные копии и обновляем конфиги
        for config_file in "${client_configs[@]}"; do
            local backup_file="${config_file}.backup.$(date +%Y%m%d_%H%M%S)"
            
            # Создаем резервную копию
            cp "$config_file" "$backup_file"
            chmod 600 "$backup_file"
            
            # Обновляем Endpoint в конфиге
            # Ищем строку вида "Endpoint = IP:PORT" (с любыми пробелами)
            if grep -qE "^[[:space:]]*Endpoint[[:space:]]*=" "$config_file"; then
                # Извлекаем текущий Endpoint для информации
                local current_endpoint=$(grep -E "^[[:space:]]*Endpoint[[:space:]]*=" "$config_file" | sed -E 's/^[[:space:]]*Endpoint[[:space:]]*=[[:space:]]*//')
                
                # Заменяем IP и порт в строке Endpoint на новые значения
                # Паттерн: Endpoint = IP:PORT или Endpoint=IP:PORT
                # Заменяем IP адрес и порт
                sed -i -E "s|^([[:space:]]*Endpoint[[:space:]]*=[[:space:]]*)([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]+)|\1${new_ip}:${new_port}|g" "$config_file"
                
                # Проверяем что замена прошла успешно
                if grep -qE "^[[:space:]]*Endpoint[[:space:]]*=[[:space:]]*${new_ip}:${new_port}" "$config_file"; then
                    log_success "Обновлен: $(basename "$config_file") (было: $current_endpoint, стало: ${new_ip}:${new_port})"
                    updated_count=$((updated_count + 1))
                else
                    log_warning "Не удалось обновить Endpoint в $(basename "$config_file")"
                fi
            else
                log_warning "В файле $(basename "$config_file") не найдено поле Endpoint"
            fi
        done
    fi
    
    # Обновляем серверный конфиг wg0.conf
    if [ -f "$WG_CONFIG" ]; then
        log_info "Обновление серверного конфига wg0.conf..."
        local backup_config="${WG_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$WG_CONFIG" "$backup_config"
        chmod 600 "$backup_config"
        
        # Обновляем ListenPort в серверном конфиге
        if grep -qE "^[[:space:]]*ListenPort[[:space:]]*=" "$WG_CONFIG"; then
            sed -i -E "s|^([[:space:]]*ListenPort[[:space:]]*=[[:space:]]*)[0-9]+|\1${new_port}|g" "$WG_CONFIG"
            log_success "Порт в серверном конфиге обновлен: $new_port"
        else
            log_warning "Не найдено поле ListenPort в серверном конфиге"
        fi
        # Фаервол: закрыть старый порт WG, открыть новый (если порт изменился)
        if [ -n "$WG_PORT" ] && [ "$new_port" != "$WG_PORT" ]; then
            log_info "Обновление правил фаервола для WireGuard: старый порт $WG_PORT → новый $new_port"
            if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
                ufw delete allow "${WG_PORT}/udp" 2>/dev/null || true
                ufw status 2>/dev/null | grep -q "${new_port}/udp" || ufw allow "${new_port}/udp" comment 'WireGuard' 2>/dev/null || true
            else
                iptables -D INPUT -p udp --dport "$WG_PORT" -j ACCEPT 2>/dev/null || true
                iptables -C INPUT -p udp --dport "$new_port" -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport "$new_port" -j ACCEPT 2>/dev/null || true
            fi
            log_success "Правила фаервола для WireGuard обновлены"
        fi
    fi

    # Обновление конфига Xray (порт, SNI, dest) и клиентской ссылки
    if [ -f "$XRAY_CONFIG" ] && [ -n "$new_xray_port" ]; then
        log_info "Обновление конфигурации Xray..."
        local old_xray_port="$XRAY_PORT"
        # Порт в JSON: "port": 443
        sed -i -E "s|(\"port\"[[:space:]]*:[[:space:]]*)[0-9]+|\1${new_xray_port}|g" "$XRAY_CONFIG"
        # serverNames — заменяем только строку со значением (пробелы + "hostname")
        sed -i -E '/"serverNames"/,/]/ { /^[[:space:]]*"[^"]*"[[:space:]]*$/s/^([[:space:]]*)"[^"]*"/\1"'${new_xray_sni}'"/ }' "$XRAY_CONFIG"
        # dest в realitySettings (строка после "dest":)
        sed -i -E "s|(\"dest\"[[:space:]]*:[[:space:]]*\")[^\"]*(\")|\1${new_xray_sni}:443\2|g" "$XRAY_CONFIG"
        XRAY_PORT="$new_xray_port"
        XRAY_SERVER_NAME="$new_xray_sni"
        XRAY_DEST="${new_xray_sni}:443"
        log_success "Конфиг Xray обновлен: порт $XRAY_PORT, SNI $XRAY_SERVER_NAME"
        # Регенерация VLESS-ссылки (нужны UUID, PUBLIC_KEY, SHORT_ID из метаданных или конфига)
        if [ -n "$XRAY_UUID" ] && [ -n "$XRAY_PUBLIC_KEY" ] && [ -n "$XRAY_SHORT_ID" ]; then
            EXTERNAL_IP="$new_ip"
            local vless_url="vless://${XRAY_UUID}@${EXTERNAL_IP}:${XRAY_PORT}?security=reality&encryption=none&pbk=${XRAY_PUBLIC_KEY}&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=${XRAY_SERVER_NAME}&sid=${XRAY_SHORT_ID}#${XRAY_SERVER_NAME}"
            local client_config_file="$CONFIG_DIR/xray/client.txt"
            echo "$vless_url" > "$client_config_file"
            chmod 600 "$client_config_file"
            log_success "Клиентская ссылка обновлена: $client_config_file"
        else
            log_warning "Обновите VLESS-ссылку вручную в $CONFIG_DIR/xray/client.txt (новый IP: $new_ip, порт: $XRAY_PORT, SNI: $XRAY_SERVER_NAME)"
        fi
        # Фаервол: закрыть старый порт Xray, открыть новый (если порт изменился)
        if [ -n "$old_xray_port" ] && [ "$new_xray_port" != "$old_xray_port" ]; then
            log_info "Обновление правил фаервола для Xray: старый порт $old_xray_port → новый $new_xray_port"
            if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
                ufw delete allow "${old_xray_port}/tcp" 2>/dev/null || true
                ufw allow "${new_xray_port}/tcp" comment 'Xray VLESS' 2>/dev/null || true
            else
                iptables -D INPUT -p tcp --dport "$old_xray_port" -j ACCEPT 2>/dev/null || true
                iptables -I INPUT -p tcp --dport "$new_xray_port" -j ACCEPT 2>/dev/null || true
            fi
            log_success "Правила фаервола для Xray обновлены"
        elif [ -z "$old_xray_port" ] || [ "$new_xray_port" = "$old_xray_port" ]; then
            # Порт не менялся — добавляем правило только если его ещё нет
            if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
                ufw status 2>/dev/null | grep -q "${XRAY_PORT}/tcp" || ufw allow "${XRAY_PORT}/tcp" comment 'Xray VLESS' 2>/dev/null || true
            else
                iptables -C INPUT -p tcp --dport "$XRAY_PORT" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$XRAY_PORT" -j ACCEPT 2>/dev/null || true
            fi
        fi
    fi

    # Обновляем метаданные (создаем файл если его не было)
    EXTERNAL_IP="$new_ip"
    WG_PORT="$new_port"
    save_install_info
    
    # Если метаданные не были загружены из файла, создаем файл с текущими значениями
    if [ "$metadata_loaded" = false ]; then
        log_info "Создан файл метаданных для будущих операций"
    fi
    
    echo ""
    log_success "IP-адрес изменен: $EXTERNAL_IP"
    log_success "Порт изменен: $WG_PORT"
    log_info "Обновлено клиентских конфигов: $updated_count"
    
    # Перезапускаем контейнеры
    echo ""
    log_info "Перезапуск контейнеров..."
    cd "$INSTALL_DIR"
    docker compose restart 2>/dev/null || {
        log_warning "Не удалось перезапустить через docker compose, пробуем напрямую..."
        docker restart liberty-wg 2>/dev/null || true
        docker restart xray-core 2>/dev/null || true
    }
    
    sleep 3
    
    echo ""
    log_success "Изменение IP-адреса и порта завершено"
    log_info "Новый IP-адрес: $EXTERNAL_IP"
    log_info "Новый порт WireGuard: $WG_PORT"
    if [ -f "$XRAY_CONFIG" ] && [ -n "$new_xray_port" ]; then
        log_info "Новый порт Xray: $XRAY_PORT"
        log_info "Новый SNI Xray: $XRAY_SERVER_NAME"
    fi
    log_info "Все остальные настройки (ключи, шифрование) остались без изменений"
    echo ""
    
    if [ $updated_count -gt 0 ]; then
        log_info "Обновленные клиентские конфиги:"
        for config_file in "${client_configs[@]}"; do
            if grep -qE "Endpoint[[:space:]]*=[[:space:]]*${new_ip}:${new_port}" "$config_file"; then
                echo "  - $config_file"
            fi
        done
        echo ""
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
    if [ -n "$WG_NETWORK" ]; then
        echo "Конфигурация WireGuard: $WG_CONFIG"
    fi
    if [ "$XRAY_ENABLED" = "true" ]; then
        echo "Конфигурация Xray: $XRAY_CONFIG"
    fi
    echo ""
    echo "Параметры конфигурации:"
    if [ -n "$WG_NETWORK" ]; then
        echo "  WireGuard сеть: $WG_NETWORK"
        echo "  WireGuard IP сервера: $WG_SERVER_IP"
        echo "  WireGuard порт: $WG_PORT"
    fi
    if [ "$XRAY_ENABLED" = "true" ]; then
        echo "  Xray порт: $XRAY_PORT"
        echo "  Xray SNI: $XRAY_SERVER_NAME"
    fi
    echo "  Внешний интерфейс: $EXTERNAL_IF"
    echo ""

    # Вывод публичного ключа сервера WireGuard
    if [ -n "$WG_NETWORK" ] && [ -f "$WG_CONFIG" ]; then
        SERVER_PRIVATE_KEY=$(grep "PrivateKey" "$WG_CONFIG" | awk '{print $3}')
        SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | wg pubkey)
        echo "Публичный ключ WireGuard сервера: $SERVER_PUBLIC_KEY"
        echo ""
    fi

    if [ -n "$WG_NETWORK" ]; then
        echo "WireGuard:"
        echo "  Для просмотра логов: docker logs liberty-wg"
    fi
    
    if [ "$XRAY_ENABLED" = "true" ]; then
        echo "Xray-core:"
        echo "  Для просмотра логов: docker logs xray-core"
        if [ -n "$XRAY_PUBLIC_KEY" ]; then
            echo ""
            echo "Параметры Xray (клиенты добавляются через бота):"
            echo "  Порт: $XRAY_PORT"
            echo "  SNI: $XRAY_SERVER_NAME"
            echo "  Public Key: $XRAY_PUBLIC_KEY"
            echo "  Short ID: $XRAY_SHORT_ID"
        fi
    fi
    
    echo ""
    echo "Для остановки: cd $INSTALL_DIR && docker compose down"
    echo "Для перезапуска: cd $INSTALL_DIR && docker compose restart"
    echo ""
}

# Главная функция
main() {
    echo ""
    echo "=========================================="
    echo "  Liberty"
    echo "=========================================="
    echo ""

    check_root

    # Интерактивное меню в начале: сервер / только бот / сервер и бот / выход
    show_start_menu
    
    # Проверка существующей установки
    if check_existing_installation; then
        log_info "Обнаружена существующая установка"
        show_installation_menu
        # Если мы здесь после reinstall, продолжаем установку
    fi
    
    check_os
    check_utils
    
    # Пытаемся загрузить метаданные, если файл существует (для проверки существующего пользователя)
    # Но сбрасываем XRAY_ENABLED, так как пользователь будет выбирать заново
    if [ -f "$INSTALL_INFO_FILE" ]; then
        load_install_info 2>/dev/null || true
        # Сбрасываем XRAY_ENABLED, чтобы пользователь мог выбрать заново
        XRAY_ENABLED=false
    fi
    
    # Запрос параметров пользователя и SSH (если нужно)
    get_user_params
    
    # Настройка пользователя и SSH (если нужно)
    if [ "$CREATE_USER" = "true" ]; then
        setup_user_and_ssh
    fi
    
    tune_system

    # Запрос параметров конфигурации перед установкой
    get_config_params

    install_docker
    create_directories
    
    # Настройка универсальной блокировки торрентов (применяется один раз для всех)
    setup_torrent_blocking
    open_firewall_wg_port
    open_firewall_xray_port

    # Генерация конфигурации WireGuard (если нужен)
    if [ -n "$WG_NETWORK" ]; then
        generate_config
        create_startup_script
    fi
    
    # Генерация конфигурации Xray (если включен)
    if [ "$XRAY_ENABLED" = "true" ]; then
        generate_xray_params
        generate_xray_config
        create_xray_startup_script
        generate_xray_client_config
    fi
    
    create_docker_compose
    start_container

    # Небольшая задержка перед проверками
    sleep 5

    if check_status; then
        # Сохраняем метаданные после успешной установки
        save_install_info
        # Установка бота: сразу (пункт 3) или по запросу (пункт 1)
        if [ "$INSTALL_BOT_AFTER_SERVER" = "1" ]; then
            install_bot
        else
            echo ""
            local install_bot_choice=""
            while [[ ! "$install_bot_choice" =~ ^[yYnN]$ ]]; do
                echo -ne "${BLUE}[?]${NC} Установить Telegram-бота для управления клиентами? (y/N): " >&2
                read install_bot_choice < /dev/tty
            done
            [[ "$install_bot_choice" =~ ^[yY]$ ]] && install_bot
        fi
        print_summary
        exit 0
    else
        log_error "Установка завершена с ошибками. Проверьте логи выше."
        exit 1
    fi
}

# Запуск главной функции
main

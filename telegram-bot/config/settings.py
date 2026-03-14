"""Configuration settings loaded from environment variables."""
import os
import re
import logging
from typing import List, Dict, Optional
from dotenv import load_dotenv

# Определяем путь к .env файлу относительно корня проекта
env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')

# Загружаем переменные окружения из .env файла
if os.path.exists(env_path):
    load_dotenv(env_path)
else:
    # Пробуем загрузить из текущей директории
    load_dotenv()

logger = logging.getLogger(__name__)

# Токен бота (обязательный)
BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN не установлен в переменных окружения или .env файле")

# ID администраторов (обязательный)
ADMIN_IDS_STR = os.getenv("ADMIN_IDS", "")
if not ADMIN_IDS_STR:
    raise ValueError("ADMIN_IDS не установлен в переменных окружения или .env файле")

try:
    ADMIN_IDS = [int(admin_id.strip()) for admin_id in ADMIN_IDS_STR.split(",")]
except ValueError:
    raise ValueError("ADMIN_IDS должен содержать числовые ID, разделенные запятыми")

# Пути к конфигурации VPN (при наличии .install_info бот использует его для путей и EXTERNAL_IF, WG_INTERFACE, XRAY_*)
DOCKER_COMPOSE_DIR = os.getenv("DOCKER_COMPOSE_DIR", "/opt/liberty")
AWG_CONFIG_DIR = os.getenv("AWG_CONFIG_DIR", os.path.join(DOCKER_COMPOSE_DIR, "config", "wg"))

# SQLite: путь к БД клиентов (источник истины по клиентам)
_project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.getenv("DB_PATH", os.path.join(_project_dir, "clients.db"))

# Префикс имён клиентов (например vpn_); пусто — без префикса
CLIENT_NAME_PREFIX = os.getenv("CLIENT_NAME_PREFIX", "").strip()

# Базовые параметры VPN - читаем из серверного конфига
def _load_vpn_base_params(vpn_config_dir: str) -> Dict[str, any]:
    """Загрузить базовые параметры VPN из wg0.conf или использовать значения по умолчанию."""
    config_path = os.path.join(vpn_config_dir, "wg0.conf")
    
    result = {
        'port': int(os.getenv("WG_PORT", "51820")),
        'base_ip': os.getenv("VPN_BASE_IP", "10.10.1"),
        'subnet': os.getenv("VPN_SUBNET", "10.10.1.0/24")
    }
    
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                content = f.read()
            
            # Читаем ListenPort
            port_match = re.search(r'\[Interface\].*?ListenPort\s*=\s*(\d+)', content, re.DOTALL)
            if port_match:
                result['port'] = int(port_match.group(1))
            
            # Читаем Address сервера для определения базового IP и подсети
            address_match = re.search(r'\[Interface\].*?Address\s*=\s*([\d.]+)/(\d+)', content, re.DOTALL)
            if address_match:
                server_address = address_match.group(1)
                prefix_len = int(address_match.group(2))
                
                # Извлекаем базовый IP (первые 3 октета)
                ip_parts = server_address.split('.')
                if len(ip_parts) >= 3:
                    result['base_ip'] = '.'.join(ip_parts[:3])
                    # Формируем подсеть (обычно /24 для VPN)
                    # Если префикс /32, используем стандартную подсеть /24
                    if prefix_len == 32:
                        result['subnet'] = f"{result['base_ip']}.0/24"
                    elif prefix_len == 24:
                        result['subnet'] = f"{result['base_ip']}.0/24"
                    else:
                        # Для других префиксов используем стандартную подсеть /24
                        result['subnet'] = f"{result['base_ip']}.0/24"
            
            logger.info(f"Базовые параметры VPN загружены из {config_path}: port={result['port']}, base_ip={result['base_ip']}, subnet={result['subnet']}")
        except Exception as e:
            logger.warning(f"Ошибка чтения базовых параметров из {config_path}: {e}")
    else:
        logger.info("Используются базовые параметры VPN по умолчанию")
    
    return result


def _parse_install_info(install_info_path: str) -> Dict[str, str]:
    """Прочитать .install_info Liberty (EXTERNAL_IF, WG_INTERFACE и т.д.)."""
    result: Dict[str, str] = {}
    if not os.path.exists(install_info_path):
        return result
    try:
        with open(install_info_path, "r") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    result[key] = value
    except Exception as e:
        logger.warning("Ошибка чтения .install_info: %s", e)
    return result


_INSTALL_INFO = _parse_install_info(os.path.join(DOCKER_COMPOSE_DIR, ".install_info"))

_VPN_BASE_PARAMS = _load_vpn_base_params(AWG_CONFIG_DIR)
WG_PORT = _VPN_BASE_PARAMS['port']
VPN_BASE_IP = _VPN_BASE_PARAMS['base_ip']
VPN_SUBNET = _VPN_BASE_PARAMS['subnet']

# Начальный IP адрес для клиентов (последний октет, обычно 2, так как 1 занят сервером)
VPN_CLIENT_START_IP = int(os.getenv("VPN_CLIENT_START_IP", "2"))

# DNS серверы для клиентов (через запятую, например "1.1.1.1,8.8.8.8")
DNS_SERVERS_STR = os.getenv("DNS_SERVERS", "1.1.1.1,8.8.8.8")
DNS_SERVERS = [dns.strip() for dns in DNS_SERVERS_STR.split(",") if dns.strip()]
# Форматируем для использования в конфиге (через запятую)
DNS_SERVERS_FORMATTED = ", ".join(DNS_SERVERS)

# Параметры AmneziaVPN (obfuscation) - читаем из серверного конфига
def _load_amnezia_params(vpn_config_dir: str) -> Dict[str, int]:
    """Загрузить параметры AmneziaVPN из wg0.conf или использовать значения по умолчанию."""
    config_path = os.path.join(vpn_config_dir, "wg0.conf")
    
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                content = f.read()
            
            params = {}
            param_names = ['Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'H1', 'H2', 'H3', 'H4']
            
            for param_name in param_names:
                # Ищем параметр в секции [Interface]
                pattern = rf'\[Interface\].*?{param_name}\s*=\s*(\d+)'
                match = re.search(pattern, content, re.DOTALL)
                if match:
                    try:
                        params[param_name] = int(match.group(1))
                    except ValueError:
                        pass
            
            # Если все параметры найдены, используем их
            if len(params) == len(param_names):
                logger.info(f"Параметры AmneziaVPN загружены из {config_path}")
                return params
        except Exception as e:
            logger.warning(f"Ошибка чтения параметров из {config_path}: {e}")
    
    # Fallback на значения по умолчанию или из env
    logger.info("Используются параметры AmneziaVPN по умолчанию")
    return {
        'Jc': int(os.getenv("AMNEZIA_JC", "2")),
        'Jmin': int(os.getenv("AMNEZIA_JMIN", "10")),
        'Jmax': int(os.getenv("AMNEZIA_JMAX", "50")),
        'S1': int(os.getenv("AMNEZIA_S1", "42")),
        'S2': int(os.getenv("AMNEZIA_S2", "94")),
        'H1': int(os.getenv("AMNEZIA_H1", "2128364304")),
        'H2': int(os.getenv("AMNEZIA_H2", "1938340076")),
        'H3': int(os.getenv("AMNEZIA_H3", "1419736917")),
        'H4': int(os.getenv("AMNEZIA_H4", "478726153"))
    }

_AMNEZIA_PARAMS = _load_amnezia_params(AWG_CONFIG_DIR)
AMNEZIA_JC = _AMNEZIA_PARAMS['Jc']
AMNEZIA_JMIN = _AMNEZIA_PARAMS['Jmin']
AMNEZIA_JMAX = _AMNEZIA_PARAMS['Jmax']
AMNEZIA_S1 = _AMNEZIA_PARAMS['S1']
AMNEZIA_S2 = _AMNEZIA_PARAMS['S2']
AMNEZIA_H1 = _AMNEZIA_PARAMS['H1']
AMNEZIA_H2 = _AMNEZIA_PARAMS['H2']
AMNEZIA_H3 = _AMNEZIA_PARAMS['H3']
AMNEZIA_H4 = _AMNEZIA_PARAMS['H4']

# Имя интерфейса WireGuard (обычно wg0)
# Из .install_info при работе бота (в .env не храним)
WG_INTERFACE = _INSTALL_INFO.get("WG_INTERFACE") or os.getenv("WG_INTERFACE", "wg0")
EXTERNAL_IF = _INSTALL_INFO.get("EXTERNAL_IF") or os.getenv("EXTERNAL_IF", "eth0")

# Xray: путь и метаданные из .install_info (в .env не храним)
XRAY_CONFIG_DIR = os.path.join(DOCKER_COMPOSE_DIR, "config", "xray")


def _load_xray_metadata() -> dict:
    """Xray-метаданные из .install_info (при отсутствии — из env)."""
    result = {}
    install_info_path = os.path.join(DOCKER_COMPOSE_DIR, ".install_info")
    if os.path.exists(install_info_path):
        try:
            with open(install_info_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if "=" in line and line.startswith("XRAY_"):
                        key, _, value = line.partition("=")
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")
                        if key == "XRAY_PUBLIC_KEY":
                            result["public_key"] = value
                        elif key == "XRAY_PORT":
                            result["port"] = value
                        elif key == "XRAY_SERVER_NAME":
                            result["server_name"] = value
                        elif key == "XRAY_SHORT_ID":
                            result["short_id"] = value
        except Exception as e:
            logger.warning("Ошибка чтения .install_info: %s", e)
    # Fallback на env, если в .install_info нет
    result.setdefault("public_key", os.getenv("XRAY_PUBLIC_KEY", ""))
    result.setdefault("port", os.getenv("XRAY_PORT", ""))
    result.setdefault("server_name", os.getenv("XRAY_SERVER_NAME", ""))
    result.setdefault("short_id", os.getenv("XRAY_SHORT_ID", ""))
    return result


_XRAY_META = _load_xray_metadata()
XRAY_PUBLIC_KEY = _XRAY_META.get("public_key") or None
XRAY_PORT = _XRAY_META.get("port") or None
XRAY_SERVER_NAME = _XRAY_META.get("server_name") or None
XRAY_SHORT_ID = _XRAY_META.get("short_id") or None
XRAY_ENABLED = bool(
    os.path.exists(os.path.join(XRAY_CONFIG_DIR, "config.json"))
    and XRAY_PUBLIC_KEY
    and XRAY_PORT
    and XRAY_SERVER_NAME
    and XRAY_SHORT_ID
)

# Hysteria2: путь и метаданные из .install_info (при отсутствии — порт из hysteria.yaml, server — внешний IP в рантайме)
HYSTERIA_CONFIG_DIR = os.path.join(DOCKER_COMPOSE_DIR, "config", "hysteria")
HYSTERIA_YAML_PATH = os.path.join(HYSTERIA_CONFIG_DIR, "hysteria.yaml")


def _load_hysteria_metadata() -> dict:
    """Hysteria2-метаданные из .install_info (при отсутствии — из env, порт из yaml)."""
    result = {}
    install_info_path = os.path.join(DOCKER_COMPOSE_DIR, ".install_info")
    if os.path.exists(install_info_path):
        try:
            with open(install_info_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if "=" in line and line.startswith("HYSTERIA_"):
                        key, _, value = line.partition("=")
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")
                        if key == "HYSTERIA_PORT":
                            result["port"] = value
                        elif key == "HYSTERIA_SERVER":
                            result["server"] = value
                        elif key == "HYSTERIA_SNI":
                            result["sni"] = value
        except Exception as e:
            logger.warning("Ошибка чтения .install_info (Hysteria): %s", e)
    result.setdefault("port", os.getenv("HYSTERIA_PORT", ""))
    result.setdefault("server", os.getenv("HYSTERIA_SERVER", ""))
    result.setdefault("sni", os.getenv("HYSTERIA_SNI", ""))
    # Если порта нет в .install_info — пробуем взять из hysteria.yaml (listen: :443)
    if not result.get("port") and os.path.exists(HYSTERIA_YAML_PATH):
        try:
            import yaml
            with open(HYSTERIA_YAML_PATH, "r") as f:
                cfg = yaml.safe_load(f)
            listen = (cfg or {}).get("listen", "")
            if isinstance(listen, str) and listen.startswith(":"):
                result["port"] = listen[1:].strip()
        except Exception as e:
            logger.debug("Не удалось прочитать порт из hysteria.yaml: %s", e)
    return result


_HYSTERIA_META = _load_hysteria_metadata()
HYSTERIA_PORT = _HYSTERIA_META.get("port") or None
HYSTERIA_SERVER = _HYSTERIA_META.get("server") or None
HYSTERIA_SNI = _HYSTERIA_META.get("sni") or None
# Включён, если есть конфиг и порт (server может быть None — подставится get_external_ip() в менеджере)
HYSTERIA_ENABLED = bool(
    os.path.exists(HYSTERIA_YAML_PATH) and HYSTERIA_PORT
)


def is_admin(user_id: int) -> bool:
    """Проверка, является ли пользователь администратором."""
    return user_id in ADMIN_IDS

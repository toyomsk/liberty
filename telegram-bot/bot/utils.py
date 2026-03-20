"""Utility functions for VPN bot."""
import os
import re
import subprocess
import qrcode
import io
import logging
from typing import Optional, Tuple, Dict
from config.settings import VPN_BASE_IP, VPN_CLIENT_START_IP, AWG_CONFIG_DIR, WG_INTERFACE, DOCKER_COMPOSE_DIR, EXTERNAL_IF

logger = logging.getLogger(__name__)

def escape_markdown_v2(text: str) -> str:
    """Экранирование специальных символов для Markdown V2."""
    special_chars = ['_', '*', '[', ']', '(', ')', '~', '`', '<', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']
    for char in special_chars:
        text = text.replace(char, f'\\{char}')
    return text

def get_external_ip() -> str:
    """Получить внешний IPv4 адрес сервера из сетевого интерфейса."""
    try:
        # Получаем IPv4 адрес из сетевого интерфейса
        result = subprocess.run(
            ['ip', 'addr', 'show', EXTERNAL_IF],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            # Ищем строку с 'inet ' и извлекаем IP адрес
            for line in result.stdout.split('\n'):
                if 'inet ' in line:
                    # Формат: inet 192.168.1.1/24 ...
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        ip_with_prefix = parts[1]
                        # Убираем префикс /24
                        ip = ip_with_prefix.split('/')[0]
                        # Проверяем, что это IPv4 (содержит точки)
                        if '.' in ip:
                            return ip
    except Exception as e:
        logger.error(f"Ошибка получения внешнего IP из интерфейса {EXTERNAL_IF}: {e}")
    
    # Fallback на curl если не удалось получить из интерфейса
    try:
        result = subprocess.run(
            ['curl', '-4', '-s', 'ifconfig.me'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception as e:
        logger.error(f"Ошибка получения внешнего IP через curl: {e}")
    
    return "UNKNOWN_IP"

def get_amnezia_params(vpn_config_dir: str) -> Optional[Dict[str, int]]:
    """Получить параметры AmneziaVPN из серверного конфига."""
    try:
        config_path = os.path.join(vpn_config_dir, "wg0.conf")
        if not os.path.exists(config_path):
            logger.warning(f"Конфиг не найден: {config_path}")
            return None
        
        with open(config_path, 'r') as f:
            content = f.read()
        
        # Ищем секцию [Interface] и извлекаем параметры
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
                    logger.warning(f"Не удалось преобразовать {param_name} в число")
        
        # Проверяем, что все параметры найдены
        if len(params) == len(param_names):
            logger.info(f"Параметры AmneziaVPN загружены из конфига: {params}")
            return params
        else:
            missing = set(param_names) - set(params.keys())
            logger.warning(f"Не найдены параметры AmneziaVPN: {missing}")
            return None
            
    except Exception as e:
        logger.error(f"Ошибка чтения параметров AmneziaVPN: {e}")
        return None

def get_server_public_key(vpn_config_dir: str) -> Optional[str]:
    """Получить публичный ключ сервера из конфига."""
    try:
        config_path = os.path.join(vpn_config_dir, "wg0.conf")
        if not os.path.exists(config_path):
            logger.error(f"Файл конфигурации не найден: {config_path}")
            return None
        
        with open(config_path, 'r') as f:
            content = f.read()
        
        # Ищем секцию [Interface] и извлекаем PrivateKey
        interface_match = re.search(
            r'\[Interface\].*?PrivateKey\s*=\s*([^\s]+)',
            content,
            re.DOTALL
        )
        
        if not interface_match:
            logger.error("Не найден PrivateKey сервера в конфиге")
            return None
        
        private_key = interface_match.group(1).strip()
        
        # Генерируем публичный ключ из приватного
        result = subprocess.run(
            ['wg', 'pubkey'],
            input=private_key,
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            logger.error(f"Ошибка генерации публичного ключа: {result.stderr}")
            return None
            
    except Exception as e:
        logger.error(f"Ошибка получения публичного ключа сервера: {e}")
        return None

def get_next_client_ip(vpn_config_dir: str) -> int:
    """Найти следующий доступный IP для клиента."""
    try:
        config_path = os.path.join(vpn_config_dir, "wg0.conf")
        if not os.path.exists(config_path):
            # Если конфига нет, начинаем с начального IP
            return VPN_CLIENT_START_IP
        
        with open(config_path, 'r') as f:
            content = f.read()
        
        # Находим все использованные IP адреса клиентов
        # Экранируем точку в базовом IP для regex
        base_ip_escaped = VPN_BASE_IP.replace('.', r'\.')
        ips = re.findall(rf'AllowedIPs\s*=\s*{base_ip_escaped}\.(\d+)/32', content)
        
        if ips:
            max_ip = max([int(ip) for ip in ips])
            return max_ip + 1
        else:
            # Начинаем с начального IP
            return VPN_CLIENT_START_IP
            
    except Exception as e:
        logger.error(f"Ошибка определения следующего IP: {e}")
        return VPN_CLIENT_START_IP

def generate_keys() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Генерация ключей WireGuard."""
    try:
        # Private key
        result = subprocess.run(
            ['wg', 'genkey'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode != 0:
            logger.error(f"Ошибка генерации приватного ключа: {result.stderr}")
            return None, None, None
        
        private_key = result.stdout.strip()
        
        # Public key
        result = subprocess.run(
            ['wg', 'pubkey'],
            input=private_key,
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode != 0:
            logger.error(f"Ошибка генерации публичного ключа: {result.stderr}")
            return None, None, None
        
        public_key = result.stdout.strip()
        
        # PSK
        result = subprocess.run(
            ['wg', 'genpsk'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode != 0:
            logger.error(f"Ошибка генерации PSK: {result.stderr}")
            return None, None, None
        
        psk = result.stdout.strip()
        
        return private_key, public_key, psk
        
    except Exception as e:
        logger.error(f"Ошибка генерации ключей: {e}")
        return None, None, None

def generate_qr_code(config_text: str) -> Optional[io.BytesIO]:
    """Генерация QR-кода для конфига."""
    try:
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(config_text)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Сохранить в BytesIO
        bio = io.BytesIO()
        img.save(bio, 'PNG')
        bio.seek(0)
        return bio
    except Exception as e:
        logger.error(f"Ошибка генерации QR-кода: {e}")
        return None

def get_server_status(docker_compose_dir: str, vpn_config_dir: str) -> str:
    """Получить статус сервера."""
    try:
        # Статус контейнера
        docker_status = "Контейнер не найден"
        try:
            result = subprocess.run(
                ['docker', 'ps', '--filter', 'name=liberty-wg', '--format', 'table {{.Names}}\t{{.Status}}'],
                capture_output=True,
                text=True,
                cwd=docker_compose_dir,
                timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                out = result.stdout.strip()
                if "liberty-wg" in out:
                    docker_status = out
                else:
                    docker_status = "Контейнер не запущен"
        except Exception as e:
            logger.error(f"Ошибка проверки статуса Docker: {e}")

        # Статус Xray (таблица как у WG)
        xray_docker_status = "Контейнер не запущен"
        try:
            result = subprocess.run(
                ['docker', 'ps', '--filter', 'name=xray-core', '--format', 'table {{.Names}}\t{{.Status}}'],
                capture_output=True,
                text=True,
                cwd=docker_compose_dir,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                out = result.stdout.strip()
                if "xray-core" in out:
                    xray_docker_status = out
        except Exception as e:
            logger.error("Ошибка проверки статуса Xray: %s", e)

        # Статус Hysteria2
        hysteria_docker_status = "Контейнер не запущен"
        try:
            result = subprocess.run(
                ['docker', 'ps', '--filter', 'name=hysteria', '--format', 'table {{.Names}}\t{{.Status}}'],
                capture_output=True,
                text=True,
                cwd=docker_compose_dir,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                out = result.stdout.strip()
                if "hysteria" in out:
                    hysteria_docker_status = out
        except Exception as e:
            logger.error("Ошибка проверки статуса Hysteria: %s", e)

        # Статус MTProxy-контейнеров (mtproto-proxy-*)
        mtproxy_docker_status = "Контейнеры не запущены"
        mtproxy_running_count = 0
        try:
            result = subprocess.run(
                ['docker', 'ps', '--filter', 'name=mtproto-proxy-', '--format', 'table {{.Names}}\t{{.Status}}'],
                capture_output=True,
                text=True,
                cwd=docker_compose_dir,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                out = result.stdout.strip()
                lines = out.splitlines()
                # table output includes header when there are matches
                if len(lines) > 1:
                    mtproxy_running_count = len(lines) - 1
                    mtproxy_docker_status = out
        except Exception as e:
            logger.error("Ошибка проверки статуса MTProxy: %s", e)
        
        # WireGuard статус (только в контейнере)
        wg_info = "WireGuard интерфейс не активен"
        try:
            container_name = _get_container_name()
            if container_name:
                result = _run_wg_in_container(['wg', 'show', WG_INTERFACE], container_name)
                if result.returncode == 0 and result.stdout.strip():
                    wg_output = result.stdout.strip()
                    active_connections = len(re.findall(r'latest handshake:', wg_output))
                    peer_count = len(re.findall(r'peer:\s*([A-Za-z0-9+/=]{44})', wg_output))
                    if active_connections > 0:
                        wg_info = f"Активных подключений: {active_connections} из {peer_count}"
                    elif peer_count > 0:
                        wg_info = f"Пиров настроено: {peer_count} (нет активных подключений)"
                    else:
                        wg_info = "Интерфейс активен, но пиры не настроены"
        except Exception as e:
            logger.error(f"Ошибка проверки статуса WireGuard: {e}")
        
        external_ip = get_external_ip()
        
        escaped_wg_info = escape_markdown_v2(wg_info)
        escaped_external_ip = escape_markdown_v2(external_ip)
        escaped_docker_status = escape_markdown_v2(docker_status)
        escaped_xray_status = escape_markdown_v2(xray_docker_status)
        escaped_hysteria_status = escape_markdown_v2(hysteria_docker_status)
        escaped_mtproxy_status = escape_markdown_v2(mtproxy_docker_status)
        escaped_mtproxy_count = escape_markdown_v2(str(mtproxy_running_count))
        status = f"""🖥 *Статус сервера:*

📦 *Docker \\(WG\\):*
```
{escaped_docker_status}

{escaped_wg_info}
```

📦 *Docker \\(Xray\\):*
```
{escaped_xray_status}
```

📦 *Docker \\(Hysteria2\\):*
```
{escaped_hysteria_status}
```

📦 *Docker \\(MTProxy\\):* \\(запущено: `{escaped_mtproxy_count}`\\)
```
{escaped_mtproxy_status}
```

🌐 *Внешний IP:* `{escaped_external_ip}`
"""
        return status
        
    except Exception as e:
        logger.error(f"Ошибка при получении статуса: {e}")
        return escape_markdown_v2(f"❌ Ошибка при получении статуса: {e}")

def _get_container_name() -> Optional[str]:
    """Получить имя контейнера WG (liberty-wg)."""
    try:
        result = subprocess.run(
            ['docker', 'ps', '--filter', 'name=liberty-wg', '--format', '{{.Names}}'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            container_name = result.stdout.strip().split('\n')[0]
            logger.info("Найден контейнер: %s", container_name)
            return container_name
    except Exception as e:
        logger.warning("Не удалось найти контейнер: %s", e)
    return None

def _run_wg_in_container(cmd: list, container_name: Optional[str] = None) -> subprocess.CompletedProcess:
    """Выполнить команду wg внутри Docker контейнера."""
    if container_name is None:
        container_name = _get_container_name()
    
    if container_name:
        docker_cmd = ['docker', 'exec', container_name] + cmd
        return subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
    # Контейнер не найден — не выполняем на хосте
    return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='Контейнер не найден')

def reload_wg_config(vpn_config_dir: str) -> Tuple[bool, str]:
    """Применить конфигурацию WireGuard через wg-quick down/up."""
    try:
        config_path = os.path.join(vpn_config_dir, "wg0.conf")
        if not os.path.exists(config_path):
            return False, "Конфиг не найден"
        
        container_name = _get_container_name()
        
        if not container_name:
            return False, "Контейнер не найден"
        
        # Выполняем wg-quick down и up для применения конфигурации
        cmd = f"wg-quick down /opt/amnezia/awg/wg0.conf && wg-quick up /opt/amnezia/awg/wg0.conf"
        result = subprocess.run(
            ['docker', 'exec', container_name, 'bash', '-c', cmd],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            logger.info(f"Конфигурация WireGuard применена через wg-quick down/up")
            
            # Проверяем, что пиры действительно применены
            try:
                check_result = _run_wg_in_container(['wg', 'show', WG_INTERFACE], container_name)
                if check_result.returncode == 0:
                    peer_count = len(re.findall(r'peer:\s*([A-Za-z0-9+/=]{44})', check_result.stdout))
                    logger.info(f"Проверка: в интерфейсе {peer_count} пиров")
            except Exception as e:
                logger.warning(f"Не удалось проверить статус интерфейса: {e}")
            
            return True, "✅ Конфигурация применена"
        else:
            error_msg = result.stderr if result.stderr else result.stdout
            logger.warning(f"Ошибка wg-quick: {error_msg}")
            return False, f"Ошибка wg-quick: {error_msg}"
            
    except FileNotFoundError:
        logger.error("Команда wg-quick не найдена")
        return False, "wg-quick команда недоступна"
    except Exception as e:
        logger.error(f"Ошибка применения конфигурации: {e}")
        return False, f"Ошибка: {e}"

def restart_vpn(docker_compose_dir: str, vpn_config_dir: str = None) -> Tuple[bool, str]:
    """Применить изменения конфигурации VPN через wg-quick down/up."""
    if vpn_config_dir is None:
        vpn_config_dir = AWG_CONFIG_DIR
    
    return reload_wg_config(vpn_config_dir)

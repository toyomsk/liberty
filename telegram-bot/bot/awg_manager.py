"""AmneziaWG (WireGuard) client management functions."""
import os
import re
import logging
import subprocess
from typing import Tuple, Optional, List, Dict
from bot.utils import (
    get_external_ip,
    get_server_public_key,
    get_next_client_ip,
    generate_keys,
    escape_markdown_v2
)
from config.settings import (
    VPN_BASE_IP,
    DNS_SERVERS_FORMATTED,
    AMNEZIA_JC,
    AMNEZIA_JMIN,
    AMNEZIA_JMAX,
    AMNEZIA_S1,
    AMNEZIA_S2,
    AMNEZIA_H1,
    AMNEZIA_H2,
    AMNEZIA_H3,
    AMNEZIA_H4
)

logger = logging.getLogger(__name__)

def create_client(
    client_name: str,
    vpn_config_dir: str,
    docker_compose_dir: str,
    wg_port: int
) -> Tuple[bool, str]:
    """Создать нового клиента."""
    try:
        # Проверка существования клиента
        client_config_path = os.path.join(vpn_config_dir, f"{client_name}.conf")
        if os.path.exists(client_config_path):
            return False, f"Клиент `{client_name}` уже существует"
        
        # Проверка существования серверного конфига
        server_config_path = os.path.join(vpn_config_dir, "wg0.conf")
        if not os.path.exists(server_config_path):
            return False, f"Серверный конфиг не найден: {server_config_path}"
        
        # Генерация параметров
        external_ip = get_external_ip()
        server_public_key = get_server_public_key(vpn_config_dir)
        client_ip = get_next_client_ip(vpn_config_dir)
        private_key, public_key, psk = generate_keys()
        
        if not all([private_key, public_key, psk, server_public_key]):
            return False, "Ошибка генерации ключей или получения публичного ключа сервера"
        
        # Добавление пира в конфиг сервера
        peer_config = f"""
[Peer]
PublicKey = {public_key}
PresharedKey = {psk}
AllowedIPs = {VPN_BASE_IP}.{client_ip}/32
"""
        
        # Добавляем пира в конец файла
        with open(server_config_path, 'a') as f:
            f.write(peer_config)
        
        logger.info(f"Добавлен пир {client_name} в серверный конфиг")
        
        # Создание клиентского конфига (без параметров AmneziaVPN для совместимости)
        client_config_basic = f"""[Interface]
PrivateKey = {private_key}
Address = {VPN_BASE_IP}.{client_ip}/32
DNS = {DNS_SERVERS_FORMATTED}

[Peer]
PublicKey = {server_public_key}
PresharedKey = {psk}
Endpoint = {external_ip}:{wg_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25"""
        
        # Полный конфиг с параметрами AmneziaVPN для возврата
        client_config_full = f"""[Interface]
PrivateKey = {private_key}
Address = {VPN_BASE_IP}.{client_ip}/32
DNS = {DNS_SERVERS_FORMATTED}
Jc = {AMNEZIA_JC}
Jmin = {AMNEZIA_JMIN}
Jmax = {AMNEZIA_JMAX}
S1 = {AMNEZIA_S1}
S2 = {AMNEZIA_S2}
H1 = {AMNEZIA_H1}
H2 = {AMNEZIA_H2}
H3 = {AMNEZIA_H3}
H4 = {AMNEZIA_H4}

[Peer]
PublicKey = {server_public_key}
PresharedKey = {psk}
Endpoint = {external_ip}:{wg_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25"""
        
        # Сохранить клиентский конфиг без параметров AmneziaVPN
        with open(client_config_path, 'w') as f:
            f.write(client_config_basic)
        
        logger.info(f"Создан клиент {client_name} с IP {VPN_BASE_IP}.{client_ip}")
        return True, client_config_full
    
    except Exception as e:
        logger.error(f"Ошибка создания клиента {client_name}: {e}")
        return False, f"Ошибка: {e}"

def delete_client(
    client_name: str,
    vpn_config_dir: str,
    docker_compose_dir: str
) -> Tuple[bool, str]:
    """Удалить клиента."""
    try:
        client_config_path = os.path.join(vpn_config_dir, f"{client_name}.conf")
        server_config_path = os.path.join(vpn_config_dir, "wg0.conf")
        
        # Проверка существования клиентского конфига
        if not os.path.exists(client_config_path):
            return False, f"Клиент `{client_name}` не найден"
        
        # Читаем клиентский конфиг, чтобы получить приватный ключ клиента
        with open(client_config_path, 'r') as f:
            client_config = f.read()
        
        # Извлекаем приватный ключ клиента из секции [Interface]
        interface_match = re.search(
            r'\[Interface\].*?PrivateKey\s*=\s*([^\s]+)',
            client_config,
            re.DOTALL
        )
        
        if not interface_match:
            # Если не нашли приватный ключ, пробуем найти публичный ключ в [Peer] (старый формат)
            peer_match = re.search(
                r'\[Peer\].*?PublicKey\s*=\s*([^\s]+)',
                client_config,
                re.DOTALL
            )
            if not peer_match:
                os.remove(client_config_path)
                return True, f"Файл конфига удален, но не удалось найти ключ для удаления из серверного конфига"
            client_public_key = peer_match.group(1).strip()
        else:
            # Генерируем публичный ключ из приватного
            client_private_key = interface_match.group(1).strip()
            try:
                result = subprocess.run(
                    ['wg', 'pubkey'],
                    input=client_private_key,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode != 0:
                    logger.error(f"Ошибка генерации публичного ключа: {result.stderr}")
                    os.remove(client_config_path)
                    return False, f"Ошибка генерации публичного ключа из приватного"
                client_public_key = result.stdout.strip()
            except Exception as e:
                logger.error(f"Ошибка генерации публичного ключа: {e}")
                os.remove(client_config_path)
                return False, f"Ошибка генерации публичного ключа: {e}"
        
        logger.info(f"Ищем пир с публичным ключом клиента: {client_public_key[:20]}...")
        
        # Удаляем пира из серверного конфига
        if os.path.exists(server_config_path):
            with open(server_config_path, 'r') as f:
                lines = f.readlines()
            
            new_lines = []
            skip_current_peer = False
            peer_found = False
            
            for line in lines:
                stripped = line.strip()
                
                if stripped == '[Peer]':
                    # Начало новой секции [Peer]
                    skip_current_peer = False
                    new_lines.append(line)
                    
                elif stripped.startswith('PublicKey'):
                    # Проверяем ключ
                    key_match = re.search(r'PublicKey\s*=\s*([^\s]+)', line)
                    if key_match:
                        found_key = key_match.group(1).strip()
                        logger.debug(f"Найден ключ в серверном конфиге: {found_key[:20]}...")
                        if found_key == client_public_key:
                            peer_found = True
                            # Это нужный пир - удаляем всю предыдущую секцию [Peer]
                            # Находим последний [Peer] в new_lines
                            last_peer_idx = None
                            for i in range(len(new_lines) - 1, -1, -1):
                                if new_lines[i].strip() == '[Peer]':
                                    last_peer_idx = i
                                    break
                            
                            if last_peer_idx is not None:
                                # Удаляем все строки от [Peer] включительно
                                new_lines = new_lines[:last_peer_idx]
                                logger.info(f"Удалена секция [Peer] с ключом {client_public_key[:20]}...")
                            else:
                                logger.warning(f"Не найден [Peer] перед ключом {client_public_key[:20]}...")
                            
                            skip_current_peer = True
                            # Не добавляем эту строку и пропускаем остальные до следующей секции
                            continue
                        else:
                            # Это не нужный пир, добавляем строку
                            new_lines.append(line)
                    else:
                        new_lines.append(line)
                        
                elif stripped.startswith('['):
                    # Другая секция (например, [Interface]) - сбрасываем флаг пропуска
                    skip_current_peer = False
                    new_lines.append(line)
                    
                else:
                    # Обычная строка секции
                    if not skip_current_peer:
                        new_lines.append(line)
                    # Если skip_current_peer = True, просто пропускаем строку
            
            # Сохраняем обновленный конфиг
            with open(server_config_path, 'w') as f:
                f.writelines(new_lines)
            
            if peer_found:
                logger.info(f"Удален пир {client_name} из серверного конфига")
            else:
                logger.warning(f"Пир с ключом {client_public_key[:20]}... не найден в серверном конфиге")
        
        # Удаляем файл конфига клиента
        os.remove(client_config_path)
        
        logger.info(f"Клиент {client_name} успешно удален")
        return True, f"Клиент `{client_name}` успешно удален"
    
    except Exception as e:
        logger.error(f"Ошибка удаления клиента {client_name}: {e}")
        return False, f"Ошибка удаления: {e}"

def list_clients(vpn_config_dir: str, docker_compose_dir: str = None) -> str:
    """Получить список клиентов (по конфигам WG). Используется для миграции; основной список — из БД."""
    try:
        server_config_path = os.path.join(vpn_config_dir, "wg0.conf")
        
        if not os.path.exists(server_config_path):
            return "❌ Серверный конфиг не найден"
        
        with open(server_config_path, 'r') as f:
            content = f.read()
        
        # Найти всех пиров с их IP адресами
        base_ip_escaped = VPN_BASE_IP.replace('.', r'\.')
        peer_pattern = rf'\[Peer\]\s*\nPublicKey\s*=\s*([^\s]+)\s*\n(?:PresharedKey\s*=\s*[^\s]+\s*\n)?AllowedIPs\s*=\s*{base_ip_escaped}\.(\d+)/32'
        peers = re.findall(peer_pattern, content)
        
        if not peers:
            return "👥 Клиенты не найдены"
        
        ip_to_name = {}
        if os.path.exists(vpn_config_dir):
            for file in os.listdir(vpn_config_dir):
                if file.endswith('.conf') and file != 'wg0.conf':
                    try:
                        file_path = os.path.join(vpn_config_dir, file)
                        with open(file_path, 'r') as f:
                            file_content = f.read()
                            ip_match = re.search(rf'Address\s*=\s*{base_ip_escaped}\.(\d+)/32', file_content)
                            if ip_match:
                                ip = ip_match.group(1)
                                client_name = file.replace('.conf', '')
                                ip_to_name[ip] = client_name
                    except Exception as e:
                        logger.error(f"Ошибка чтения файла {file}: {e}")
                        continue
        
        total_clients = len(peers)
        escaped_total = escape_markdown_v2(str(total_clients))
        result = f"👥 *Список клиентов* \\(всего: {escaped_total}\\)\n\n"
        
        for i, (pub_key, ip) in enumerate(peers, 1):
            client_name = ip_to_name.get(ip, f"client_{ip}")
            escaped_name = escape_markdown_v2(client_name)
            escaped_ip = escape_markdown_v2(f"{VPN_BASE_IP}.{ip}")
            escaped_i = escape_markdown_v2(str(i))
            result += f"*{escaped_i}\\.* *{escaped_name}*\n"
            result += f"   `{escaped_ip}`\n"
            if i < total_clients:
                result += "\n"
        
        return result
    
    except Exception as e:
        logger.error(f"Ошибка получения списка клиентов: {e}")
        return f"❌ Ошибка при получении списка: {e}"

def get_client_config(client_name: str, vpn_config_dir: str) -> Optional[str]:
    """Получить конфиг клиента с параметрами AmneziaVPN."""
    try:
        config_path = os.path.join(vpn_config_dir, f"{client_name}.conf")
        
        if not os.path.exists(config_path):
            return None
        
        with open(config_path, 'r') as f:
            config_content = f.read()
        
        if 'Jc =' in config_content:
            return config_content
        
        peer_pos = config_content.find('[Peer]')
        if peer_pos == -1:
            return config_content
        
        amnezia_params = f"""Jc = {AMNEZIA_JC}
Jmin = {AMNEZIA_JMIN}
Jmax = {AMNEZIA_JMAX}
S1 = {AMNEZIA_S1}
S2 = {AMNEZIA_S2}
H1 = {AMNEZIA_H1}
H2 = {AMNEZIA_H2}
H3 = {AMNEZIA_H3}
H4 = {AMNEZIA_H4}

"""
        
        config_with_params = config_content[:peer_pos] + amnezia_params + config_content[peer_pos:]
        return config_with_params
    
    except Exception as e:
        logger.error(f"Ошибка чтения конфига клиента {client_name}: {e}")
        return None

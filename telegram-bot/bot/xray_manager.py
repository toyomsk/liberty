"""Xray (VLESS Reality) client management; identify clients by client_id in email field."""
import json
import os
import logging
import subprocess
import tempfile
from typing import Tuple, Optional

from bot.utils import get_external_ip
from config.settings import (
    XRAY_CONFIG_DIR,
    XRAY_PUBLIC_KEY,
    XRAY_PORT,
    XRAY_SERVER_NAME,
    XRAY_SHORT_ID,
)

logger = logging.getLogger(__name__)

CONFIG_JSON = "config.json"


def _config_path() -> str:
    return os.path.join(XRAY_CONFIG_DIR, CONFIG_JSON)


def _reload_xray() -> bool:
    """Send SIGHUP to xray (soft reload). Try pgrep on host, then docker exec."""
    try:
        r = subprocess.run(
            ["sh", "-c", "pgrep -x xray"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r.returncode == 0 and r.stdout.strip():
            pid = r.stdout.strip().split("\n")[0]
            subprocess.run(
                ["kill", "-SIGHUP", pid],
                capture_output=True,
                timeout=5,
            )
            logger.info("Xray reloaded via SIGHUP (host)")
            return True
    except Exception as e:
        logger.debug("pgrep xray failed: %s", e)
    try:
        subprocess.run(
            ["docker", "exec", "xray-core", "kill", "-SIGHUP", "1"],
            capture_output=True,
            timeout=10,
        )
        logger.info("Xray reloaded via docker exec SIGHUP 1")
        return True
    except Exception as e:
        logger.warning("docker exec xray-core kill -SIGHUP 1 failed: %s", e)
        return False


def _load_config() -> Optional[dict]:
    path = _config_path()
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        return json.load(f)


def _save_config(data: dict) -> None:
    path = _config_path()
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix="config.", suffix=".json")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _get_clients(data: dict) -> list:
    try:
        inbounds = data.get("inbounds") or []
        if not inbounds:
            return []
        settings = inbounds[0].get("settings") or {}
        return settings.get("clients") or []
    except (IndexError, KeyError, TypeError):
        return []


def _set_clients(data: dict, clients: list) -> None:
    if not data.get("inbounds"):
        raise ValueError("No inbounds in config")
    if "settings" not in data["inbounds"][0]:
        data["inbounds"][0]["settings"] = {}
    data["inbounds"][0]["settings"]["clients"] = clients


def create_client(client_id: str) -> Tuple[bool, str]:
    """
    Add Xray client with email=client_id. Generate VLESS uuid, save config, SIGHUP.
    Returns (success, vless_link_or_error).
    """
    if not all([XRAY_PUBLIC_KEY, XRAY_PORT, XRAY_SERVER_NAME, XRAY_SHORT_ID]):
        return False, "Xray не настроен: нет метаданных (public_key, port, sni, short_id)"
    path = _config_path()
    if not os.path.exists(path):
        return False, "Xray не настроен: config.json не найден"
    # Generate VLESS uuid via docker
    try:
        r = subprocess.run(
            [
                "docker", "run", "--rm", "--entrypoint", "",
                "teddysun/xray:latest", "/usr/bin/xray", "uuid",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if r.returncode != 0 or not r.stdout.strip():
            return False, "Не удалось сгенерировать UUID для Xray"
        vless_uuid = r.stdout.strip().replace("\r", "").replace("\n", "")
    except Exception as e:
        logger.exception("xray uuid: %s", e)
        return False, f"Ошибка генерации UUID: {e}"
    data = _load_config()
    if data is None:
        return False, "Ошибка чтения config.json"
    clients = _get_clients(data)
    for c in clients:
        if c.get("email") == client_id:
            return False, "Клиент с таким ID уже есть в Xray"
    clients.append({
        "id": vless_uuid,
        "flow": "xtls-rprx-vision",
        "email": client_id,
    })
    _set_clients(data, clients)
    try:
        _save_config(data)
    except Exception as e:
        return False, f"Ошибка записи config.json: {e}"
    _reload_xray()
    # Build VLESS link
    external_ip = get_external_ip()
    link = (
        f"vless://{vless_uuid}@{external_ip}:{XRAY_PORT}"
        f"?security=reality&encryption=none&pbk={XRAY_PUBLIC_KEY}"
        f"&fp=chrome&type=tcp&flow=xtls-rprx-vision"
        f"&sni={XRAY_SERVER_NAME}&sid={XRAY_SHORT_ID}#{client_id}"
    )
    return True, link


def delete_client(client_id: str) -> Tuple[bool, str]:
    """Remove client with email==client_id; save config, SIGHUP."""
    if not os.path.exists(_config_path()):
        return False, "Xray не настроен"
    data = _load_config()
    if data is None:
        return False, "Ошибка чтения config.json"
    clients = _get_clients(data)
    new_clients = [c for c in clients if c.get("email") != client_id]
    if len(new_clients) == len(clients):
        return False, "Клиент не найден в Xray"
    _set_clients(data, new_clients)
    try:
        _save_config(data)
    except Exception as e:
        return False, f"Ошибка записи config.json: {e}"
    _reload_xray()
    return True, "OK"


def get_client_config(client_id: str) -> Optional[str]:
    """Get VLESS link for client with email==client_id; None if not found or Xray not configured."""
    if not all([XRAY_PUBLIC_KEY, XRAY_PORT, XRAY_SERVER_NAME, XRAY_SHORT_ID]):
        return None
    path = _config_path()
    if not os.path.exists(path):
        return None
    data = _load_config()
    if data is None:
        return None
    clients = _get_clients(data)
    for c in clients:
        if c.get("email") == client_id:
            vless_uuid = c.get("id")
            if not vless_uuid:
                return None
            external_ip = get_external_ip()
            return (
                f"vless://{vless_uuid}@{external_ip}:{XRAY_PORT}"
                f"?security=reality&encryption=none&pbk={XRAY_PUBLIC_KEY}"
                f"&fp=chrome&type=tcp&flow=xtls-rprx-vision"
                f"&sni={XRAY_SERVER_NAME}&sid={XRAY_SHORT_ID}#{client_id}"
            )
    return None

"""Hysteria2 client management; auth via userpass (client_id -> password)."""
import logging
import os
import secrets
import subprocess
import tempfile
from urllib.parse import quote
from typing import Tuple, Optional

import yaml

from bot.utils import get_external_ip
from config.settings import (
    DOCKER_COMPOSE_DIR,
    HYSTERIA_CONFIG_DIR,
    HYSTERIA_PORT,
    HYSTERIA_SERVER,
    HYSTERIA_SNI,
)

logger = logging.getLogger(__name__)

CONFIG_FILENAME = "hysteria.yaml"


def _config_path() -> str:
    return os.path.join(HYSTERIA_CONFIG_DIR, CONFIG_FILENAME)


def _reload_hysteria() -> bool:
    """
    Подхватить изменения hysteria.yaml: у Hysteria2 нет мягкого reload конфига
    (в отличие от Xray + SIGHUP); userpass меняется только после рестарта процесса.
    См. https://github.com/apernet/hysteria/issues/1350 — hot reload не планируют.
    """
    compose_file = os.path.join(DOCKER_COMPOSE_DIR, "docker-compose.yml")
    attempts = [
        (["docker", "restart", "hysteria"], None, "docker restart hysteria"),
        (
            ["docker", "compose", "-f", compose_file, "restart", "hysteria"],
            DOCKER_COMPOSE_DIR,
            "docker compose restart hysteria",
        ),
    ]
    for cmd, cwd, label in attempts:
        if cmd[0] == "docker" and "compose" in cmd and not os.path.isfile(compose_file):
            continue
        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=cwd,
            )
            if r.returncode == 0:
                logger.info("Hysteria: %s", label)
                return True
            err = (r.stderr or r.stdout or "").strip()
            logger.debug("%s failed rc=%s: %s", label, r.returncode, err[:500])
        except Exception as e:
            logger.debug("%s: %s", label, e)
    logger.warning("Hysteria: не удалось перезапустить контейнер (docker restart и compose)")
    return False


def _load_config() -> Optional[dict]:
    path = _config_path()
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        return yaml.safe_load(f)


def _save_config(data: dict) -> None:
    path = _config_path()
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix="hysteria.", suffix=".yaml")
    try:
        with os.fdopen(fd, "w") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _get_userpass(data: dict) -> dict:
    try:
        auth = data.get("auth") or {}
        if auth.get("type") != "userpass":
            return {}
        return auth.get("userpass") or {}
    except (KeyError, TypeError):
        return {}


def _set_userpass(data: dict, userpass: dict) -> None:
    if "auth" not in data:
        data["auth"] = {}
    data["auth"]["type"] = "userpass"
    data["auth"]["userpass"] = userpass


def create_client(client_id: str, remark: Optional[str] = None) -> Tuple[bool, str]:
    """
    Add Hysteria2 userpass entry (user=client_id, password=random).
    Returns (success, hysteria2_uri_or_error).
    """
    if not HYSTERIA_PORT:
        return False, "Hysteria2 не настроен: нет порта (добавьте HYSTERIA_PORT в .install_info или в hysteria.yaml listen)"
    path = _config_path()
    if not os.path.exists(path):
        return False, "Hysteria2 не настроен: hysteria.yaml не найден"
    data = _load_config()
    if data is None:
        return False, "Ошибка чтения hysteria.yaml"
    userpass = _get_userpass(data)
    if client_id in userpass:
        return False, "Клиент с таким ID уже есть в Hysteria2"
    password = secrets.token_urlsafe(16)
    userpass[client_id] = password
    _set_userpass(data, userpass)
    try:
        _save_config(data)
    except Exception as e:
        return False, f"Ошибка записи hysteria.yaml: {e}"
    _reload_hysteria()
    # hysteria2://user:password@host:port/?params#fragment (порт всегда явно — дефолт 8443)
    server = HYSTERIA_SERVER or get_external_ip()
    port = HYSTERIA_PORT or "8443"
    host_port = f"{server}:{port}"
    auth_enc = quote(f"{client_id}:{password}", safe="")
    link = f"hysteria2://{auth_enc}@{host_port}/"
    params = []
    if HYSTERIA_SNI:
        params.append(f"sni={quote(HYSTERIA_SNI, safe='')}")
    if params:
        link += "?" + "&".join(params)
    if remark:
        link += f"#{quote(remark, safe='')}"
    return True, link


def delete_client(client_id: str) -> Tuple[bool, str]:
    """Remove userpass entry for client_id; save config, restart."""
    if not os.path.exists(_config_path()):
        return False, "Hysteria2 не настроен"
    data = _load_config()
    if data is None:
        return False, "Ошибка чтения hysteria.yaml"
    userpass = _get_userpass(data)
    if client_id not in userpass:
        return False, "Клиент не найден в Hysteria2"
    del userpass[client_id]
    _set_userpass(data, userpass)
    try:
        _save_config(data)
    except Exception as e:
        return False, f"Ошибка записи hysteria.yaml: {e}"
    _reload_hysteria()
    return True, "OK"


def get_client_config(client_id: str, remark: Optional[str] = None) -> Optional[str]:
    """Return hysteria2:// URI for client_id or None. Если клиента ещё нет в Hysteria (добавили протокол позже) — добавляем на лету и возвращаем ссылку."""
    if not HYSTERIA_PORT:
        return None
    path = _config_path()
    if not os.path.exists(path):
        return None
    data = _load_config()
    if data is None:
        return None
    userpass = _get_userpass(data)
    password = userpass.get(client_id)
    if not password:
        # Существующий пользователь (создан до добавления Hysteria) — добавляем в userpass при первом запросе конфига
        ok, link_or_err = create_client(client_id, remark=remark)
        return link_or_err if ok else None
    server = HYSTERIA_SERVER or get_external_ip()
    port = HYSTERIA_PORT or "8443"
    host_port = f"{server}:{port}"
    auth_enc = quote(f"{client_id}:{password}", safe="")
    link = f"hysteria2://{auth_enc}@{host_port}/"
    params = []
    if HYSTERIA_SNI:
        params.append(f"sni={quote(HYSTERIA_SNI, safe='')}")
    if params:
        link += "?" + "&".join(params)
    if remark:
        link += f"#{quote(remark, safe='')}"
    return link

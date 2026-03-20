"""Интеграция с mtproxy-admin.sh: один MTProto-прокси на client_id (slug)."""
from __future__ import annotations

import logging
import os
import re
import subprocess
from typing import Optional, Tuple

from config.settings import (
    MTPROXY_DATA_DIR,
    MTPROXY_FAKE_DOMAIN,
    MTPROXY_SCRIPT,
    MTPROXY_USE_SUDO,
)

logger = logging.getLogger(__name__)

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _build_cmd(args: list[str]) -> list[str]:
    cmd: list[str] = []
    if MTPROXY_USE_SUDO:
        cmd.extend(["sudo", "-n"])
    cmd.append(MTPROXY_SCRIPT)
    cmd.extend(args)
    return cmd


def _run(args: list[str], timeout: int = 180) -> Tuple[int, str, str]:
    env = os.environ.copy()
    env["MTPROXY_DATA_DIR"] = MTPROXY_DATA_DIR
    cmd = _build_cmd(args)
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    out = (r.stdout or "") + (r.stderr or "")
    return r.returncode, out, out


def _extract_tg_proxy_url(text: str) -> Optional[str]:
    for line in text.splitlines():
        line = _ANSI_RE.sub("", line).strip()
        if line.startswith("tg://proxy?"):
            return line
    m = re.search(r"tg://proxy\?[^\s\x1b]+", text)
    if m:
        return _ANSI_RE.sub("", m.group(0))
    return None


def slug_for_client_id(client_id: str) -> bool:
    """client_id из БД бота (12 hex) — валидный slug для mtproxy-admin."""
    return bool(re.fullmatch(r"[a-f0-9]{12}", client_id))


def create_for_client(client_id: str) -> Tuple[bool, str]:
    """
    add <client_id> --domain ...
    Возвращает (True, tg_url) или (False, сообщение_об_ошибке).
    """
    if not slug_for_client_id(client_id):
        return False, "некорректный client_id для mtproxy slug"
    code, combined, _ = _run(
        ["add", client_id, "--domain", MTPROXY_FAKE_DOMAIN],
        timeout=240,
    )
    if code != 0:
        logger.error("mtproxy add failed (%s): %s", code, combined[:2000])
        return False, combined.strip() or f"exit {code}"

    url = _extract_tg_proxy_url(combined)
    if url:
        return True, url

    ok, link_or_err = get_link_plain(client_id)
    if ok:
        return True, link_or_err
    return False, link_or_err or "нет tg:// ссылки в выводе add"


def get_link_plain(client_id: str) -> Tuple[bool, str]:
    """link --plain <client_id> → одна строка tg://..."""
    if not slug_for_client_id(client_id):
        return False, "некорректный client_id"
    code, out, _ = _run(["link", "--plain", client_id], timeout=60)
    text = _ANSI_RE.sub("", (out or "").strip())
    if code != 0:
        return False, text or f"exit {code}"
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("tg://proxy?"):
            return True, line
    return False, text or "пустой вывод link"


def remove_for_client(client_id: str) -> None:
    """Идемпотентно: если пользователя mtproxy нет — не падаем."""
    if not slug_for_client_id(client_id):
        return
    user_dir = os.path.join(MTPROXY_DATA_DIR, "users", client_id)
    if not os.path.isdir(user_dir):
        return
    code, out, _ = _run(["remove", client_id], timeout=120)
    if code != 0:
        logger.warning("mtproxy remove %s: %s", client_id, (out or "")[:1000])


def disable_for_client(client_id: str) -> None:
    """Disable mtproxy client without deleting its user directory."""
    if not slug_for_client_id(client_id):
        return
    user_dir = os.path.join(MTPROXY_DATA_DIR, "users", client_id)
    if not os.path.isdir(user_dir):
        return
    code, out, _ = _run(["disable", client_id], timeout=120)
    if code != 0:
        logger.warning("mtproxy disable %s: %s", client_id, (out or "")[:1000])


def enable_for_client(client_id: str) -> Tuple[bool, str]:
    """Enable previously disabled mtproxy client."""
    if not slug_for_client_id(client_id):
        return False, "некорректный client_id для mtproxy slug"
    user_dir = os.path.join(MTPROXY_DATA_DIR, "users", client_id)
    if not os.path.isdir(user_dir):
        return False, "mtproxy user directory не найден"

    code, combined, _ = _run(["enable", client_id], timeout=240)
    if code != 0:
        logger.error("mtproxy enable failed (%s): %s", code, combined[:2000])
        return False, combined.strip() or f"exit {code}"

    ok, link_or_err = get_link_plain(client_id)
    if ok:
        return True, link_or_err
    return False, link_or_err or "нет tg:// ссылки после enable"


def has_mtproxy_user(client_id: str) -> bool:
    if not slug_for_client_id(client_id):
        return False
    meta = os.path.join(MTPROXY_DATA_DIR, "users", client_id, "meta.json")
    cfg = os.path.join(MTPROXY_DATA_DIR, "users", client_id, "config.toml")
    return os.path.isfile(meta) and os.path.isfile(cfg)

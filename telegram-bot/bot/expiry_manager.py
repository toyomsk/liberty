import logging
import time
from datetime import datetime
from typing import List, Optional, Tuple
from zoneinfo import ZoneInfo
from urllib.parse import unquote

from config.settings import (
    ADMIN_IDS,
    AWG_CONFIG_DIR,
    DOCKER_COMPOSE_DIR,
    DB_PATH,
    HYSTERIA_ENABLED,
    MTPROXY_READY,
    XRAY_ENABLED,
)

from bot import hysteria_manager, mtproxy_manager, xray_manager
from bot.awg_manager import delete_client as awg_delete_client, enable_client_peer as awg_enable_client_peer
from bot.db import (
    get_expired_clients,
    get_clients_expiring_within_window,
    get_client_details_by_id,
    set_expiry_notice_sent_at,
    set_disabled_at,
    set_hysteria_password,
    set_xray_uuid,
)
from bot.utils import restart_vpn

logger = logging.getLogger(__name__)

MSK_TZ = ZoneInfo("Europe/Moscow")


def _parse_vless_uuid(vless_link: str) -> Optional[str]:
    # vless://<uuid>@<ip>:<port>...
    if not vless_link.startswith("vless://"):
        return None
    rest = vless_link[len("vless://") :]
    if "@" not in rest:
        return None
    return rest.split("@", 1)[0] or None


def _parse_hysteria_password(hysteria_link: str, client_id: str) -> Optional[str]:
    # hysteria2://<auth>@<host_port>...
    if not hysteria_link.startswith("hysteria2://"):
        return None
    rest = hysteria_link[len("hysteria2://") :]
    if "@" not in rest:
        return None
    auth_enc = rest.split("@", 1)[0]
    try:
        auth = unquote(auth_enc)
        # auth is "<client_id>:<password>"
        if ":" not in auth:
            return None
        prefix, password = auth.split(":", 1)
        if prefix != client_id:
            # Link is inconsistent with this client_id
            return None
        return password or None
    except Exception:
        return None


def disable_client_everywhere(
    client_id: str,
    client_name: str,
    now_ts: Optional[int] = None,
    restart: bool = False,
) -> None:
    """
    Disable access for the client, keeping all local configs/credentials.
    """
    if now_ts is None:
        now_ts = int(time.time())

    # If DB doesn't have stored credentials yet, extract them from current configs
    # before deleting the entries. That allows true "no-regeneration" re-enable.
    details = None
    try:
        details = get_client_details_by_id(client_id, DB_PATH)
    except Exception:
        details = None

    stored_xray_uuid = details[3] if details else None
    stored_hysteria_password = details[4] if details else None

    if XRAY_ENABLED and not stored_xray_uuid:
        try:
            vless_link = xray_manager.get_client_config(client_id, remark=client_name)
            parsed_uuid = _parse_vless_uuid(vless_link) if vless_link else None
            if parsed_uuid:
                set_xray_uuid(client_id, parsed_uuid, DB_PATH)
        except Exception:
            logger.exception("Failed to extract xray uuid before disable for %s", client_id)

    if HYSTERIA_ENABLED and not stored_hysteria_password:
        try:
            hysteria_link = hysteria_manager.get_client_config(client_id, remark=client_name)
            parsed_password = _parse_hysteria_password(hysteria_link, client_id) if hysteria_link else None
            if parsed_password:
                set_hysteria_password(client_id, parsed_password, DB_PATH)
        except Exception:
            logger.exception("Failed to extract hysteria password before disable for %s", client_id)

    # WireGuard: remove peer from wg0.conf but keep `<client_name>.conf`
    try:
        awg_delete_client(
            client_name,
            AWG_CONFIG_DIR,
            DOCKER_COMPOSE_DIR,
            remove_client_config=False,
        )
    except Exception as e:
        logger.exception("AWG disable failed for %s (%s): %s", client_id, client_name, e)

    if XRAY_ENABLED:
        try:
            ok, msg = xray_manager.delete_client(client_id)
            if not ok:
                logger.warning("Xray disable failed for %s: %s", client_id, msg)
        except Exception as e:
            logger.exception("Xray disable exception for %s: %s", client_id, e)

    if HYSTERIA_ENABLED:
        try:
            ok, msg = hysteria_manager.delete_client(client_id)
            if not ok:
                logger.warning("Hysteria disable failed for %s: %s", client_id, msg)
        except Exception as e:
            logger.exception("Hysteria disable exception for %s: %s", client_id, e)

    if MTPROXY_READY:
        try:
            mtproxy_manager.disable_for_client(client_id)
        except Exception as e:
            logger.exception("MTProxy remove exception for %s: %s", client_id, e)

    try:
        set_disabled_at(client_id, now_ts, DB_PATH)
    except Exception as e:
        logger.exception("DB set disabled_at failed for %s: %s", client_id, e)

    if restart:
        restart_vpn(DOCKER_COMPOSE_DIR, AWG_CONFIG_DIR)


def enable_client_everywhere(
    client_id: str,
    client_name: str,
) -> None:
    """
    Enable access for a disabled client using stored credentials (or regenerate if missing).
    """
    # Need stored secrets for "no-regeneration" behavior.
    details = get_client_details_by_id(client_id, DB_PATH)
    if not details:
        logger.warning("enable_client_everywhere: client not found in DB: %s", client_id)
        return

    _name, expires_at, disabled_at, xray_uuid, hysteria_password = details
    now_ts = int(time.time())

    # If still expired, don't enable.
    if expires_at is not None and expires_at <= now_ts:
        logger.info("enable_client_everywhere: skip expired client %s", client_id)
        return

    # WireGuard peer enable
    try:
        awg_enable_client_peer(client_name, AWG_CONFIG_DIR)
    except Exception as e:
        logger.exception("AWG enable failed for %s (%s): %s", client_id, client_name, e)

    # Xray enable (without uuid regeneration if possible)
    if XRAY_ENABLED:
        try:
            if xray_uuid:
                ok, msg = xray_manager.enable_client_with_uuid(client_id, xray_uuid, remark=client_name)
                if not ok:
                    logger.warning("Xray enable failed for %s: %s", client_id, msg)
            else:
                ok, link_or_err = xray_manager.create_client(client_id, remark=client_name)
                if ok:
                    uuid_parsed = _parse_vless_uuid(link_or_err)
                    if uuid_parsed:
                        set_xray_uuid(client_id, uuid_parsed, DB_PATH)
                else:
                    logger.warning("Xray create fallback failed for %s: %s", client_id, link_or_err)
        except Exception as e:
            logger.exception("Xray enable exception for %s: %s", client_id, e)

    # Hysteria enable (without password regeneration if possible)
    if HYSTERIA_ENABLED:
        try:
            if hysteria_password:
                ok, _ = hysteria_manager.enable_client_with_password(
                    client_id, hysteria_password, remark=client_name
                )
                if not ok:
                    logger.warning("Hysteria enable failed for %s", client_id)
            else:
                ok, link_or_err = hysteria_manager.create_client(client_id, remark=client_name)
                if ok:
                    password_parsed = _parse_hysteria_password(link_or_err, client_id)
                    if password_parsed:
                        set_hysteria_password(client_id, password_parsed, DB_PATH)
                else:
                    logger.warning("Hysteria create fallback failed for %s: %s", client_id, link_or_err)
        except Exception as e:
            logger.exception("Hysteria enable exception for %s: %s", client_id, e)

    # MTProxy enable (re-create if needed)
    if MTPROXY_READY:
        try:
            ok, msg = mtproxy_manager.enable_for_client(client_id)
            if not ok:
                # Fallback: if user dir missing or broken, create from scratch.
                mt_ok, mt_link = mtproxy_manager.create_for_client(client_id)
                if not mt_ok:
                    logger.warning("MTProxy create fallback failed for %s: %s", client_id, mt_link)
        except Exception as e:
            logger.exception("MTProxy create exception for %s: %s", client_id, e)

    try:
        set_disabled_at(client_id, None, DB_PATH)
    except Exception as e:
        logger.exception("DB clear disabled_at failed for %s: %s", client_id, e)

    restart_vpn(DOCKER_COMPOSE_DIR, AWG_CONFIG_DIR)


def expire_clients_now(now_ts: Optional[int] = None) -> int:
    """
    Disable all expired (not yet disabled) clients right away.

    Returns number of disabled clients.
    """
    if now_ts is None:
        now_ts = int(time.time())

    expired: List[Tuple[str, str]] = get_expired_clients(now_ts, DB_PATH)
    if not expired:
        return 0

    for client_id, client_name in expired:
        disable_client_everywhere(client_id, client_name, now_ts=now_ts, restart=False)

    # Apply WG config once after disabling a batch.
    restart_vpn(DOCKER_COMPOSE_DIR, AWG_CONFIG_DIR)
    return len(expired)


async def expiry_job(_context) -> None:
    """Periodic job for PTB JobQueue."""
    try:
        expire_clients_now()
        await notify_expiring_clients(_context)
    except Exception as e:
        logger.exception("expiry_job failed: %s", e)


async def notify_expiring_clients(context) -> None:
    """
    Notify admins once, 24h before client expiry.
    """
    now_ts = int(time.time())
    until_ts = now_ts + 24 * 60 * 60
    rows = get_clients_expiring_within_window(now_ts, until_ts, DB_PATH)
    if not rows:
        return

    for client_id, client_name, expires_at in rows:
        # Keep message plain and robust.
        text = (
            f"⏰ Клиент истечет через < 24ч\n"
            f"ID: <code>{client_id}</code>\n"
            f"Имя: <code>{client_name}</code>\n"
            f"Истекает (MSK): <code>{datetime.fromtimestamp(expires_at, tz=MSK_TZ).strftime('%d.%m.%Y %H:%M:%S')}</code>"
        )

        sent_ok = False
        for admin_id in ADMIN_IDS:
            try:
                await context.bot.send_message(
                    chat_id=admin_id,
                    text=text,
                    parse_mode="HTML",
                )
                sent_ok = True
            except Exception as e:
                logger.warning("Failed sending expiry warning to admin %s: %s", admin_id, e)

        if sent_ok:
            set_expiry_notice_sent_at(client_id, now_ts, DB_PATH)


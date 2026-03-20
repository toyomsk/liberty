"""Telegram bot command handlers. DB = source of truth; client_id for delete/get_config."""
import os
import re
import io
import uuid
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Optional
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

# Состояния интерактивного ввода (context.user_data["state"])
STATE_ADD_CLIENT_NAME = "add_client_name"
STATE_ADD_CLIENT_EXPIRY = "add_client_expiry"
STATE_SET_EXPIRY_CLIENT = "set_expiry_client"
STATE_SET_EXPIRY_VALUE = "set_expiry_value"
STATE_DISABLE_CLIENT_TARGET = "disable_client_target"
STATE_ENABLE_CLIENT_TARGET = "enable_client_target"
STATE_GET_CONFIG_ARG = "get_config_arg"
STATE_DELETE_CLIENT_ID = "delete_client_id"

CANCEL_WORDS = ("отмена", "cancel")

from config.settings import (
    is_admin,
    AWG_CONFIG_DIR,
    DOCKER_COMPOSE_DIR,
    WG_PORT,
    DB_PATH,
    CLIENT_NAME_PREFIX,
    XRAY_ENABLED,
    HYSTERIA_ENABLED,
    MTPROXY_READY,
    AMNEZIA_JC,
    AMNEZIA_JMIN,
    AMNEZIA_JMAX,
    AMNEZIA_S1,
    AMNEZIA_S2,
    AMNEZIA_H1,
    AMNEZIA_H2,
    AMNEZIA_H3,
    AMNEZIA_H4,
)
from bot.awg_manager import (
    create_client as awg_create_client,
    delete_client as awg_delete_client,
    get_client_config as awg_get_client_config,
)
from bot.db import (
    add_client as db_add_client,
    get_name_by_id as db_get_name_by_id,
    get_id_by_name as db_get_id_by_name,
    get_client_details_by_id as db_get_client_details_by_id,
    list_clients as db_list_clients,
    delete_client as db_delete_client,
    set_expires_at_and_disabled_at as db_set_expires_at_and_disabled_at,
    set_xray_uuid as db_set_xray_uuid,
    set_hysteria_password as db_set_hysteria_password,
)
from bot.expiry_manager import (
    disable_client_everywhere,
    enable_client_everywhere,
)
from bot.utils import (
    generate_qr_code,
    get_server_status,
    restart_vpn,
    escape_markdown_v2,
)
from bot import xray_manager, hysteria_manager, mtproxy_manager

logger = logging.getLogger(__name__)


def _escape_html(text: str) -> str:
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


def _escape_html_attr(text: str) -> str:
    return _escape_html(text).replace('"', "&quot;")


def _display_name(internal_name: str) -> str:
    """Strip CLIENT_NAME_PREFIX for display."""
    if CLIENT_NAME_PREFIX and internal_name.startswith(CLIENT_NAME_PREFIX):
        return internal_name[len(CLIENT_NAME_PREFIX):]
    return internal_name


def generate_keenetic_command() -> str:
    """Генерация команды для роутеров Keenetic."""
    return f"interface <INTERFACE> wireguard asc {AMNEZIA_JC} {AMNEZIA_JMIN} {AMNEZIA_JMAX} {AMNEZIA_S1} {AMNEZIA_S2} {AMNEZIA_H1} {AMNEZIA_H2} {AMNEZIA_H3} {AMNEZIA_H4}"


async def start_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Команда /start."""
    user_id = update.effective_user.id

    if not is_admin(user_id):
        await update.message.reply_text("❌ У вас нет прав доступа к этому боту.")
        return

    welcome_text = """🎛 <b>Liberty Bot</b>

Доступные команды (интерактивный ввод, отмена: /cancel):
/add_client — Создать клиента (далее ввод имени + срок действия)
/list_clients — Список клиентов (ID и имя)
/get_config — Получить конфиг (далее ID или имя)
/delete_client — Удалить клиента (далее ID из списка)
/set_expiry — Изменить срок действия клиента (далее ID/имя + новый срок)
/disable_client — Отключить клиента без изменения срока (далее ID/имя)
/enable_client — Включить клиента без изменения срока (далее ID/имя)
/status — Статус сервера
/restart — Перезапуск VPN-сервера
/cancel — Выход из режима ввода
/help — Эта справка"""
    if MTPROXY_READY:
        welcome_text += "\n\n<i>При создании клиента также поднимается отдельный MTProto-прокси (mtg), ссылка приходит вместе с конфигом.</i>"

    await update.message.reply_text(welcome_text, parse_mode=ParseMode.HTML)


async def help_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Команда /help."""
    await start_handler(update, context)


async def cancel_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Выход из интерактивного режима."""
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("❌ Недостаточно прав")
        return
    context.user_data.pop("state", None)
    context.user_data.pop("pending_add_client", None)
    context.user_data.pop("pending_set_expiry", None)
    await update.message.reply_text("✅ Режим отменён.")

def _format_expires_at(expires_at: Optional[int]) -> str:
    if expires_at is None:
        return "∞"
    dt = datetime.fromtimestamp(expires_at, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d")


def _parse_expiry_input(text: str) -> Optional[int]:
    """
    expiry input formats:
      - `none` / `∞` / `never` => no expiry
      - `30d`, `12h`, `15m`, `90s`, `2w`, `1y`
      - `YYYY-MM-DD` (UTC, expires at 23:59:59)
      - ISO8601 datetime: `2026-03-20T10:00:00Z`
      - unix timestamp: `@1700000000` or `1700000000` (seconds/ms)
      - digits only: treated as days
    Returns unix epoch seconds (UTC) or None.
    """
    raw = (text or "").strip()
    if not raw:
        raise ValueError("Пустой срок")

    t = raw.lower()
    if t in ("none", "∞", "never", "/none", "бессрочно", "без срока"):
        return None

    now = datetime.now(timezone.utc)

    # Unix timestamp (seconds or ms)
    if re.fullmatch(r"@?\d{10,13}", raw):
        n = int(raw.lstrip("@"))
        if len(str(n)) == 13:
            n //= 1000
        return n

    # Date only
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
        dt = datetime.strptime(raw, "%Y-%m-%d").replace(
            tzinfo=timezone.utc, hour=23, minute=59, second=59
        )
        return int(dt.timestamp())

    # ISO datetime
    iso_candidate = raw
    if iso_candidate.endswith("Z"):
        iso_candidate = iso_candidate[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(iso_candidate)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.astimezone(timezone.utc).timestamp())
    except ValueError:
        pass

    # Durations like 30d / 12h / 15m / 90s / 2w / 1y
    m = re.fullmatch(r"(\d+)\s*([smhdwy])", t)
    if m:
        qty = int(m.group(1))
        unit = m.group(2)
        if unit == "s":
            dt = now + timedelta(seconds=qty)
        elif unit == "m":
            dt = now + timedelta(minutes=qty)
        elif unit == "h":
            dt = now + timedelta(hours=qty)
        elif unit == "d":
            dt = now + timedelta(days=qty)
        elif unit == "w":
            dt = now + timedelta(weeks=qty)
        elif unit == "y":
            dt = now + timedelta(days=365 * qty)
        else:
            raise ValueError("Неизвестный unit")
        return int(dt.timestamp())

    # Digits only => days
    if re.fullmatch(r"\d+", raw):
        days = int(raw)
        dt = now + timedelta(days=days)
        return int(dt.timestamp())

    raise ValueError("Не удалось распознать формат срока")


def _parse_vless_uuid(vless_link: str) -> Optional[str]:
    # vless://<uuid>@<ip>:<port>...
    if not vless_link.startswith("vless://"):
        return None
    rest = vless_link[len("vless://") :]
    if "@" not in rest:
        return None
    return rest.split("@", 1)[0] or None


def _parse_hysteria_password(hysteria_link: str, client_id: str) -> Optional[str]:
    # hysteria2://<auth>@<host_port>/...
    if not hysteria_link.startswith("hysteria2://"):
        return None
    rest = hysteria_link[len("hysteria2://") :]
    if "@" not in rest:
        return None
    auth_enc = rest.split("@", 1)[0]
    try:
        from urllib.parse import unquote

        auth = unquote(auth_enc)
        # auth is "<client_id>:<password>"
        if ":" not in auth:
            return None
        prefix, password = auth.split(":", 1)
        if prefix != client_id:
            return None
        return password or None
    except Exception:
        return None


async def _do_add_client(update: Update, context: ContextTypes.DEFAULT_TYPE, display_name_arg: str) -> None:
    """Step 1 of /add_client: validate name, generate client_id, ask expiry."""
    if not re.match(r"^[a-zA-Z0-9_-]+$", display_name_arg):
        await update.message.reply_text(
            "❌ Имя может содержать только буквы, цифры, _ и -"
        )
        return

    internal_name = (CLIENT_NAME_PREFIX + display_name_arg) if CLIENT_NAME_PREFIX else display_name_arg
    if db_get_id_by_name(internal_name, DB_PATH):
        await update.message.reply_text("❌ Клиент с таким именем уже существует")
        return

    client_id = uuid.uuid4().hex[:12]
    context.user_data["pending_add_client"] = {
        "client_id": client_id,
        "internal_name": internal_name,
        "display_name_arg": display_name_arg,
    }
    context.user_data["state"] = STATE_ADD_CLIENT_EXPIRY

    await update.message.reply_text(
        "🗓 Введите срок действия клиента.\n"
        "Примеры: <code>30d</code>, <code>12h</code>, <code>2026-03-20</code> (UTC), <code>@1700000000</code>, или <code>none</code>.\n"
        "Если срок уже истёк — бот попросит ввести новый.",
        parse_mode=ParseMode.HTML,
    )


async def _do_finalize_add_client(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    expiry_text: str,
) -> None:
    """Step 2 of /add_client: parse expiry, create client everywhere."""
    pending = context.user_data.get("pending_add_client") or {}
    client_id = pending.get("client_id")
    internal_name = pending.get("internal_name")
    display_name_arg = pending.get("display_name_arg")

    if not client_id or not internal_name or not display_name_arg:
        context.user_data.pop("pending_add_client", None)
        context.user_data.pop("state", None)
        await update.message.reply_text("❌ Ошибка: нет данных добавления. Повторите /add_client.")
        return

    try:
        expires_at = _parse_expiry_input(expiry_text)
    except ValueError as e:
        await update.message.reply_text(
            f"❌ {e}\nФорматы: <code>30d</code>, <code>12h</code>, <code>2026-03-20</code>, <code>@1700000000</code>, или <code>none</code>.",
            parse_mode=ParseMode.HTML,
        )
        return

    now_ts = int(time.time())
    if expires_at is not None and expires_at <= now_ts:
        await update.message.reply_text(
            "❌ Срок уже истёк. Введите дату/длительность в будущем или <code>none</code>.",
            parse_mode=ParseMode.HTML,
        )
        return

    await update.message.reply_text(
        f"🔄 Создаю клиента `{escape_markdown_v2(display_name_arg)}`\\.\\.\\.",
        parse_mode=ParseMode.MARKDOWN_V2,
    )

    try:
        db_add_client(client_id, internal_name, DB_PATH, expires_at=expires_at)
    except Exception as e:
        await update.message.reply_text(f"❌ Ошибка БД: {e}")
        context.user_data.pop("pending_add_client", None)
        context.user_data.pop("state", None)
        return

    try:
        success, config_or_error = awg_create_client(
            internal_name,
            AWG_CONFIG_DIR,
            DOCKER_COMPOSE_DIR,
            WG_PORT,
        )
    except Exception as e:
        db_delete_client(client_id, DB_PATH)
        context.user_data.pop("pending_add_client", None)
        context.user_data.pop("state", None)
        await update.message.reply_text(f"❌ Ошибка создания клиента AWG: {e}")
        return

    if not success:
        db_delete_client(client_id, DB_PATH)
        await update.message.reply_text(f"❌ Ошибка создания клиента AWG: {config_or_error}")
        context.user_data.pop("pending_add_client", None)
        context.user_data.pop("state", None)
        return

    vless_link = None
    xray_uuid = None
    if XRAY_ENABLED:
        ok, vless_or_err = xray_manager.create_client(client_id, remark=internal_name)
        if ok:
            vless_link = vless_or_err
            xray_uuid = _parse_vless_uuid(vless_link)
            if xray_uuid:
                db_set_xray_uuid(client_id, xray_uuid, DB_PATH)
        else:
            logger.warning("Xray create_client: %s", vless_or_err)

    hysteria_link = None
    hysteria_password = None
    if HYSTERIA_ENABLED:
        ok, hy_or_err = hysteria_manager.create_client(client_id, remark=internal_name)
        if ok:
            hysteria_link = hy_or_err
            hysteria_password = _parse_hysteria_password(hysteria_link, client_id)
            if hysteria_password:
                db_set_hysteria_password(client_id, hysteria_password, DB_PATH)
        else:
            logger.warning("Hysteria create_client: %s", hy_or_err)

    mtproxy_link = None
    if MTPROXY_READY:
        mt_ok, mt_or_err = mtproxy_manager.create_for_client(client_id)
        if mt_ok:
            mtproxy_link = mt_or_err
        else:
            logger.warning("MTProxy create_for_client: %s", mt_or_err)

    restart_success, restart_msg = restart_vpn(DOCKER_COMPOSE_DIR, AWG_CONFIG_DIR)

    status_msg = "✅ Клиент создан успешно\\!\n"
    status_msg += f"🆔 *ID для удаления:* `{escape_markdown_v2(client_id)}`\n"
    if expires_at is not None:
        status_msg += f"⏳ *Истекает:* `{escape_markdown_v2(_format_expires_at(expires_at))}`\\n"
    if restart_success:
        status_msg += f"🔄 {escape_markdown_v2(restart_msg)}\n"
    else:
        status_msg += f"⚠️ {escape_markdown_v2(restart_msg)}\n"

    await update.message.reply_text(status_msg, parse_mode=ParseMode.MARKDOWN_V2)

    context.user_data.pop("pending_add_client", None)
    context.user_data.pop("state", None)

    config_content = config_or_error
    try:
        config_file = io.BytesIO(config_content.encode("utf-8"))
        config_file.name = f"{internal_name}.conf"
        qr_image = generate_qr_code(config_content)
        keenetic_cmd = generate_keenetic_command()

        if qr_image:
            await update.message.reply_photo(
                photo=qr_image,
                caption=f"📱 QR\\-код WG для `{escape_markdown_v2(display_name_arg)}`",
                parse_mode=ParseMode.MARKDOWN_V2,
            )
        await update.message.reply_document(
            document=config_file,
            caption=f"📋 Конфиг WG для `{escape_markdown_v2(display_name_arg)}`",
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        keenetic_info = f"""🔧 *Команда для роутера Keenetic:*

`{escape_markdown_v2(keenetic_cmd)}`

ℹ️ Для нового интерфейса: `{escape_markdown_v2('show interface')}`, сохранить: `{escape_markdown_v2('system configuration save')}`
"""
        await update.message.reply_text(keenetic_info, parse_mode=ParseMode.MARKDOWN_V2)

        if vless_link:
            await update.message.reply_text(
                f"🔗 *VLESS \\(Xray\\):* `{escape_markdown_v2(internal_name)}`\n`{escape_markdown_v2(vless_link)}`",
                parse_mode=ParseMode.MARKDOWN_V2,
            )
            vless_qr = generate_qr_code(vless_link)
            if vless_qr:
                await update.message.reply_photo(
                    photo=vless_qr,
                    caption=f"📱 QR\\-код VLESS для `{escape_markdown_v2(internal_name)}`",
                    parse_mode=ParseMode.MARKDOWN_V2,
                )
        if hysteria_link:
            await update.message.reply_text(
                f"🔗 *Hysteria2:* `{escape_markdown_v2(internal_name)}`\n`{escape_markdown_v2(hysteria_link)}`",
                parse_mode=ParseMode.MARKDOWN_V2,
            )
            hy_qr = generate_qr_code(hysteria_link)
            if hy_qr:
                await update.message.reply_photo(
                    photo=hy_qr,
                    caption=f"📱 QR\\-код Hysteria2 для `{escape_markdown_v2(internal_name)}`",
                    parse_mode=ParseMode.MARKDOWN_V2,
                )
        if mtproxy_link:
            html_href = _escape_html_attr(mtproxy_link)
            await update.message.reply_text(
                f"🔗 <b>MTProto (mtg):</b> <code>{_escape_html(internal_name)}</code>\n"
                f'<a href="{html_href}">Добавить MTProxy в Telegram</a>',
                parse_mode=ParseMode.HTML,
            )
            mt_qr = generate_qr_code(mtproxy_link)
            if mt_qr:
                await update.message.reply_photo(
                    photo=mt_qr,
                    caption=f"📱 QR MTProto для `{escape_markdown_v2(internal_name)}`",
                    parse_mode=ParseMode.MARKDOWN_V2,
                )
        elif MTPROXY_READY:
            await update.message.reply_text(
                "⚠️ MTProto \\(mtg\\) для этого клиента не создан — см\\. логи бота",
                parse_mode=ParseMode.MARKDOWN_V2,
            )
    except Exception as e:
        logger.error("Ошибка отправки конфига: %s", e)
        await update.message.reply_text(f"❌ Ошибка отправки конфига: {e}")


async def add_client_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Добавление клиента: входим в режим ввода имени."""
    user_id = update.effective_user.id
    if not is_admin(user_id):
        await update.message.reply_text("❌ Недостаточно прав")
        return
    context.user_data["state"] = STATE_ADD_CLIENT_NAME
    context.user_data.pop("pending_add_client", None)
    await update.message.reply_text(
        "📝 Введите имя клиента (латиница, цифры, _ и -). Для отмены: /cancel"
    )


async def _do_get_config(update: Update, context: ContextTypes.DEFAULT_TYPE, arg: str) -> None:
    """Общая логика получения конфига по ID или имени."""
    name = db_get_name_by_id(arg, DB_PATH)
    client_id = arg if name else None
    if not name:
        internal_name = (CLIENT_NAME_PREFIX + arg) if CLIENT_NAME_PREFIX else arg
        client_id = db_get_id_by_name(internal_name, DB_PATH)
        if client_id:
            name = db_get_name_by_id(client_id, DB_PATH)

    if not name:
        await update.message.reply_text(
            f"❌ Клиент не найден: `{escape_markdown_v2(arg)}`",
            parse_mode=ParseMode.MARKDOWN_V2
        )
        return

    client_details = db_get_client_details_by_id(client_id, DB_PATH) if client_id else None
    if client_details:
        _name, expires_at, disabled_at, _xray_uuid, _hysteria_password = client_details
        if disabled_at is not None:
            await update.message.reply_text(
                "❌ Клиент отключен (доступ заблокирован).",
                parse_mode=ParseMode.HTML,
            )
            return

        if expires_at is not None and expires_at <= int(time.time()):
            # Если срок истёк — отказываем и (опционально) сразу отключаем доступ.
            try:
                disable_client_everywhere(
                    client_id,
                    name,
                    now_ts=int(time.time()),
                    restart=True,
                )
            except Exception:
                logger.exception("Auto-disable for expired client failed: %s", client_id)
            await update.message.reply_text(
                f"❌ Клиент заблокирован: срок истёк \\({escape_markdown_v2(_format_expires_at(expires_at))} UTC\\)",
                parse_mode=ParseMode.MARKDOWN_V2,
            )
            return

    config_content = awg_get_client_config(name, AWG_CONFIG_DIR)
    if not config_content:
        await update.message.reply_text(
            f"❌ Конфиг WG не найден для клиента `{escape_markdown_v2(name)}`",
            parse_mode=ParseMode.MARKDOWN_V2
        )
        return

    try:
        config_file = io.BytesIO(config_content.encode("utf-8"))
        config_file.name = f"{name}.conf"
        qr_image = generate_qr_code(config_content)
        keenetic_cmd = generate_keenetic_command()

        if qr_image:
            await update.message.reply_photo(
                photo=qr_image,
                caption=f"📱 QR\\-код WG",
                parse_mode=ParseMode.MARKDOWN_V2,
            )
        await update.message.reply_document(
            document=config_file,
            caption=f"📋 Конфиг WG",
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        keenetic_info = f"""🔧 *Keenetic:* `{escape_markdown_v2(keenetic_cmd)}`
ℹ️ `{escape_markdown_v2('show interface')}` \\| `{escape_markdown_v2('system configuration save')}`
"""
        await update.message.reply_text(keenetic_info, parse_mode=ParseMode.MARKDOWN_V2)

        if XRAY_ENABLED and client_id:
            vless_link = xray_manager.get_client_config(client_id, remark=name)
            if vless_link:
                await update.message.reply_text(
                    f"🔗 *VLESS:* `{escape_markdown_v2(name)}`\n`{escape_markdown_v2(vless_link)}`",
                    parse_mode=ParseMode.MARKDOWN_V2,
                )
                vless_qr = generate_qr_code(vless_link)
                if vless_qr:
                    await update.message.reply_photo(
                        photo=vless_qr,
                        caption=f"📱 QR\\-код VLESS для `{escape_markdown_v2(name)}`",
                        parse_mode=ParseMode.MARKDOWN_V2,
                    )
        if HYSTERIA_ENABLED and client_id:
            hy_link = hysteria_manager.get_client_config(client_id, remark=name)
            if hy_link:
                await update.message.reply_text(
                    f"🔗 *Hysteria2:* `{escape_markdown_v2(name)}`\n`{escape_markdown_v2(hy_link)}`",
                    parse_mode=ParseMode.MARKDOWN_V2,
                )
                hy_qr = generate_qr_code(hy_link)
                if hy_qr:
                    await update.message.reply_photo(
                        photo=hy_qr,
                        caption=f"📱 QR\\-код Hysteria2 для `{escape_markdown_v2(name)}`",
                        parse_mode=ParseMode.MARKDOWN_V2,
                    )
        if MTPROXY_READY and client_id:
            if mtproxy_manager.has_mtproxy_user(client_id):
                ok_mt, mt_link = mtproxy_manager.get_link_plain(client_id)
                if ok_mt:
                    html_href = _escape_html_attr(mt_link)
                    await update.message.reply_text(
                        f"🔗 <b>MTProto (mtg):</b> <code>{_escape_html(name)}</code>\n"
                        f'<a href="{html_href}">Добавить MTProxy в Telegram</a>',
                        parse_mode=ParseMode.HTML,
                    )
                    mt_qr = generate_qr_code(mt_link)
                    if mt_qr:
                        await update.message.reply_photo(
                            photo=mt_qr,
                            caption=f"📱 QR MTProto для `{escape_markdown_v2(name)}`",
                            parse_mode=ParseMode.MARKDOWN_V2,
                        )
            else:
                # Клиент мог существовать до включения MTProto.
                # Делаем on-demand создание mtg-контейнера и выдаём ссылку.
                mt_ok, mt_or_err = mtproxy_manager.create_for_client(client_id)
                if mt_ok:
                    html_href = _escape_html_attr(mt_or_err)
                    await update.message.reply_text(
                        f"🔗 <b>MTProto (mtg):</b> <code>{_escape_html(name)}</code>\n"
                        f'<a href="{html_href}">Добавить MTProxy в Telegram</a>',
                        parse_mode=ParseMode.HTML,
                    )
                    mt_qr = generate_qr_code(mt_or_err)
                    if mt_qr:
                        await update.message.reply_photo(
                            photo=mt_qr,
                            caption=f"📱 QR MTProto для `{escape_markdown_v2(name)}`",
                            parse_mode=ParseMode.MARKDOWN_V2,
                        )
                else:
                    logger.warning("MTProto auto-create failed for %s: %s", client_id, mt_or_err)
                    await update.message.reply_text(
                        "⚠️ MTProto \\(mtg\\) для этого клиента не создан — см\\. логи бота",
                        parse_mode=ParseMode.MARKDOWN_V2,
                    )
    except Exception as e:
        logger.error("Ошибка отправки конфига: %s", e)
        await update.message.reply_text(f"❌ Ошибка отправки конфига: {e}")


async def get_config_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Получение конфига: входим в режим ввода ID или имени."""
    user_id = update.effective_user.id
    if not is_admin(user_id):
        await update.message.reply_text("❌ Недостаточно прав")
        return
    context.user_data["state"] = STATE_GET_CONFIG_ARG
    await update.message.reply_text(
        "📝 Введите ID или имя клиента. Для отмены: /cancel"
    )


async def set_expiry_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Изменить срок действия клиента (и при необходимости включить/выключить)."""
    user_id = update.effective_user.id
    if not is_admin(user_id):
        await update.message.reply_text("❌ Недостаточно прав")
        return
    context.user_data["state"] = STATE_SET_EXPIRY_CLIENT
    context.user_data.pop("pending_set_expiry", None)
    await update.message.reply_text(
        "📝 Введите ID или имя клиента. Для отмены: /cancel"
    )


async def list_clients_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Список клиентов из БД: ID и отображаемое имя."""
    user_id = update.effective_user.id

    if not is_admin(user_id):
        await update.message.reply_text("❌ Недостаточно прав")
        return

    rows = db_list_clients(DB_PATH)
    if not rows:
        await update.message.reply_text("👥 Клиенты не найдены")
        return

    total = len(rows)
    escaped_total = escape_markdown_v2(str(total))
    result = f"👥 *Список клиентов* \\(всего: {escaped_total}\\)\n\n"
    for i, (cid, internal_name, expires_at) in enumerate(rows, 1):
        display = _display_name(internal_name)
        result += (
            f"*{escape_markdown_v2(str(i))}\\.* `{escape_markdown_v2(cid)}` — "
            f"*{escape_markdown_v2(display)}*"
        )
        if expires_at is not None:
            result += f" \\(до *{escape_markdown_v2(_format_expires_at(expires_at))}*\\)"
        else:
            result += " \\(∞\\)"
        result += "\n"
        if i < total:
            result += "\n"

    await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN_V2)


async def status_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Статус сервера."""
    user_id = update.effective_user.id

    if not is_admin(user_id):
        await update.message.reply_text("❌ Недостаточно прав")
        return

    status = get_server_status(DOCKER_COMPOSE_DIR, AWG_CONFIG_DIR)
    await update.message.reply_text(status, parse_mode=ParseMode.MARKDOWN_V2)


async def restart_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Перезапуск VPN."""
    user_id = update.effective_user.id

    if not is_admin(user_id):
        await update.message.reply_text("❌ Недостаточно прав")
        return

    await update.message.reply_text(
        "🔄 Применяю изменения конфигурации VPN\\.\\.\\.",
        parse_mode=ParseMode.MARKDOWN_V2,
    )
    success, message = restart_vpn(DOCKER_COMPOSE_DIR, AWG_CONFIG_DIR)
    await update.message.reply_text(message)


async def _do_delete_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE, client_id: str) -> None:
    """Показать подтверждение удаления по client_id."""
    name = db_get_name_by_id(client_id, DB_PATH)
    if not name:
        await update.message.reply_text(
            f"❌ Клиент с ID `{escape_markdown_v2(client_id)}` не найден",
            parse_mode=ParseMode.MARKDOWN_V2
        )
        return
    display = _display_name(name)
    keyboard = [
        [InlineKeyboardButton("✅ Да, удалить", callback_data=f"delete_yes_{client_id}")],
        [InlineKeyboardButton("❌ Отмена", callback_data="delete_no")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        f"⚠️ Удалить клиента *{escape_markdown_v2(display)}* \\(ID: `{escape_markdown_v2(client_id)}`\\)\\?\nНеобратимо\\!",
        reply_markup=reply_markup,
        parse_mode=ParseMode.MARKDOWN_V2,
    )


async def delete_client_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Удаление клиента: входим в режим ввода ID."""
    user_id = update.effective_user.id
    if not is_admin(user_id):
        await update.message.reply_text("❌ Недостаточно прав")
        return
    context.user_data["state"] = STATE_DELETE_CLIENT_ID
    await update.message.reply_text(
        "📝 Введите ID клиента (см. /list_clients). Для отмены: /cancel"
    )


async def disable_client_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Отключить клиента без изменения expires_at."""
    user_id = update.effective_user.id
    if not is_admin(user_id):
        await update.message.reply_text("❌ Недостаточно прав")
        return
    context.user_data["state"] = STATE_DISABLE_CLIENT_TARGET
    await update.message.reply_text(
        "📝 Введите ID или имя клиента. Для отмены: /cancel"
    )


async def enable_client_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Включить клиента без изменения expires_at."""
    user_id = update.effective_user.id
    if not is_admin(user_id):
        await update.message.reply_text("❌ Недостаточно прав")
        return
    context.user_data["state"] = STATE_ENABLE_CLIENT_TARGET
    await update.message.reply_text(
        "📝 Введите ID или имя клиента. Для отмены: /cancel"
    )


async def _do_set_expiry_client(update: Update, context: ContextTypes.DEFAULT_TYPE, arg: str) -> None:
    """Resolve client by ID or name, then ask for the new expiry."""
    name = db_get_name_by_id(arg, DB_PATH)
    client_id = arg if name else None
    internal_name = None
    if not name:
        internal_name = (CLIENT_NAME_PREFIX + arg) if CLIENT_NAME_PREFIX else arg
        client_id = db_get_id_by_name(internal_name, DB_PATH)
        if client_id:
            name = db_get_name_by_id(client_id, DB_PATH)

    if not name or not client_id:
        await update.message.reply_text(
            f"❌ Клиент не найден: `{escape_markdown_v2(arg)}`",
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        return

    pending = {
        "client_id": client_id,
        "internal_name": name,
    }
    context.user_data["pending_set_expiry"] = pending
    context.user_data["state"] = STATE_SET_EXPIRY_VALUE

    display = _display_name(name)
    await update.message.reply_text(
        f"🗓 Новый срок для <b>{_escape_html(display)}</b> (ID: <code>{_escape_html(client_id)}</code>):\n"
        "Примеры: <code>30d</code>, <code>12h</code>, <code>2026-03-20</code> (UTC), <code>@1700000000</code>, или <code>none</code>.",
        parse_mode=ParseMode.HTML,
    )


async def _do_set_expiry_value(update: Update, context: ContextTypes.DEFAULT_TYPE, expiry_text: str) -> None:
    pending = context.user_data.get("pending_set_expiry") or {}
    client_id = pending.get("client_id")
    internal_name = pending.get("internal_name")
    if not client_id or not internal_name:
        context.user_data.pop("pending_set_expiry", None)
        context.user_data.pop("state", None)
        await update.message.reply_text("❌ Ошибка: нет данных. Повторите /set_expiry.")
        return

    try:
        expires_at = _parse_expiry_input(expiry_text)
    except ValueError as e:
        await update.message.reply_text(
            f"❌ {e}\nФорматы: <code>30d</code>, <code>12h</code>, <code>2026-03-20</code>, <code>@1700000000</code>, или <code>none</code>.",
            parse_mode=ParseMode.HTML,
        )
        return

    now_ts = int(time.time())
    display = _display_name(internal_name)

    if expires_at is None:
        # Бессрочно => enabled
        db_set_expires_at_and_disabled_at(client_id, None, None, DB_PATH)
        try:
            enable_client_everywhere(client_id, internal_name)
        except Exception:
            logger.exception("enable_client_everywhere failed for %s", client_id)
        await update.message.reply_text(
            f"✅ Срок обновлён для *{escape_markdown_v2(display)}*: ∞",
            parse_mode=ParseMode.MARKDOWN_V2,
        )
    else:
        if expires_at <= now_ts:
            # Уже истек => disabled immediately
            db_set_expires_at_and_disabled_at(client_id, expires_at, now_ts, DB_PATH)
            try:
                disable_client_everywhere(
                    client_id,
                    internal_name,
                    now_ts=now_ts,
                    restart=True,
                )
            except Exception:
                logger.exception("disable_client_everywhere failed for %s", client_id)
            await update.message.reply_text(
                f"✅ Срок обновлён для *{escape_markdown_v2(display)}*: истёк (считаем отключенным)",
                parse_mode=ParseMode.MARKDOWN_V2,
            )
        else:
            # В будущем => enabled
            db_set_expires_at_and_disabled_at(client_id, expires_at, None, DB_PATH)
            try:
                enable_client_everywhere(client_id, internal_name)
            except Exception:
                logger.exception("enable_client_everywhere failed for %s", client_id)
            await update.message.reply_text(
                f"✅ Срок обновлён для *{escape_markdown_v2(display)}*: до \\({escape_markdown_v2(_format_expires_at(expires_at))} UTC\\)",
                parse_mode=ParseMode.MARKDOWN_V2,
            )

    context.user_data.pop("pending_set_expiry", None)
    context.user_data.pop("state", None)


async def _do_disable_client_target(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    arg: str,
) -> None:
    name = db_get_name_by_id(arg, DB_PATH)
    client_id = arg if name else None
    internal_name = None
    if not name:
        internal_name = (CLIENT_NAME_PREFIX + arg) if CLIENT_NAME_PREFIX else arg
        client_id = db_get_id_by_name(internal_name, DB_PATH)
        if client_id:
            name = db_get_name_by_id(client_id, DB_PATH)

    if not name or not client_id:
        await update.message.reply_text(
            f"❌ Клиент не найден: `{escape_markdown_v2(arg)}`",
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        return

    now_ts = int(time.time())
    try:
        disable_client_everywhere(
            client_id,
            name,
            now_ts=now_ts,
            restart=True,
        )
    except Exception:
        logger.exception("disable_client_everywhere failed for %s", client_id)
        await update.message.reply_text("❌ Ошибка при отключении клиента.")
        return

    display = _display_name(name)
    await update.message.reply_text(
        f"✅ Клиент отключен: *{escape_markdown_v2(display)}*",
        parse_mode=ParseMode.MARKDOWN_V2,
    )


async def _do_enable_client_target(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    arg: str,
) -> None:
    name = db_get_name_by_id(arg, DB_PATH)
    client_id = arg if name else None
    internal_name = None
    if not name:
        internal_name = (CLIENT_NAME_PREFIX + arg) if CLIENT_NAME_PREFIX else arg
        client_id = db_get_id_by_name(internal_name, DB_PATH)
        if client_id:
            name = db_get_name_by_id(client_id, DB_PATH)

    if not name or not client_id:
        await update.message.reply_text(
            f"❌ Клиент не найден: `{escape_markdown_v2(arg)}`",
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        return

    details = db_get_client_details_by_id(client_id, DB_PATH)
    if not details:
        await update.message.reply_text("❌ Клиент не найден в БД.")
        return

    _name, expires_at, disabled_at, _xray_uuid, _hysteria_password = details
    now_ts = int(time.time())
    if expires_at is not None and expires_at <= now_ts:
        await update.message.reply_text(
            f"❌ Нельзя включить: срок истёк ({_format_expires_at(expires_at)} UTC). "
            "Сначала продлите срок командой <code>/set_expiry</code>.",
            parse_mode=ParseMode.HTML,
        )
        return

    try:
        enable_client_everywhere(client_id, name)
    except Exception:
        logger.exception("enable_client_everywhere failed for %s", client_id)
        await update.message.reply_text("❌ Ошибка при включении клиента.")
        return

    display = _display_name(name)
    await update.message.reply_text(
        f"✅ Клиент включен: *{escape_markdown_v2(display)}*",
        parse_mode=ParseMode.MARKDOWN_V2,
    )


async def interactive_message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обработка текстового ввода в интерактивном режиме (имя, ID и т.д.). Отмена: отмена / cancel."""
    if not update.message or not update.message.text:
        return
    user_id = update.effective_user.id
    if not is_admin(user_id):
        return
    text = update.message.text.strip()
    if not text:
        return

    state = context.user_data.get("state")
    # Текст "отмена" или "cancel" в любом режиме — выход
    if text.lower() in CANCEL_WORDS:
        context.user_data.pop("state", None)
        context.user_data.pop("pending_add_client", None)
        context.user_data.pop("pending_set_expiry", None)
        await update.message.reply_text("✅ Режим отменён.")
        return
    if not state:
        return

    context.user_data.pop("state", None)
    if state == STATE_ADD_CLIENT_NAME:
        await _do_add_client(update, context, text)
    elif state == STATE_ADD_CLIENT_EXPIRY:
        await _do_finalize_add_client(update, context, text)
    elif state == STATE_SET_EXPIRY_CLIENT:
        await _do_set_expiry_client(update, context, text)
    elif state == STATE_SET_EXPIRY_VALUE:
        await _do_set_expiry_value(update, context, text)
    elif state == STATE_DISABLE_CLIENT_TARGET:
        await _do_disable_client_target(update, context, text)
    elif state == STATE_ENABLE_CLIENT_TARGET:
        await _do_enable_client_target(update, context, text)
    elif state == STATE_GET_CONFIG_ARG:
        await _do_get_config(update, context, text)
    elif state == STATE_DELETE_CLIENT_ID:
        await _do_delete_confirm(update, context, text)


async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обработчик кнопок: подтверждение удаления по client_id."""
    query = update.callback_query
    await query.answer()

    user_id = query.from_user.id
    if not is_admin(user_id):
        await query.edit_message_text("❌ Недостаточно прав")
        return

    if query.data.startswith("delete_yes_"):
        client_id = query.data.replace("delete_yes_", "")
        name = db_get_name_by_id(client_id, DB_PATH)
        if not name:
            await query.edit_message_text("❌ Клиент не найден")
            return

        awg_delete_client(name, AWG_CONFIG_DIR, DOCKER_COMPOSE_DIR)
        if XRAY_ENABLED:
            xray_manager.delete_client(client_id)
        if HYSTERIA_ENABLED:
            hysteria_manager.delete_client(client_id)
        if MTPROXY_READY:
            mtproxy_manager.remove_for_client(client_id)
        db_delete_client(client_id, DB_PATH)
        restart_success, restart_msg = restart_vpn(DOCKER_COMPOSE_DIR, AWG_CONFIG_DIR)

        status_msg = f"✅ Клиент удалён\n"
        if restart_success:
            status_msg += f"🔄 {escape_markdown_v2(restart_msg)}"
        else:
            status_msg += f"⚠️ {escape_markdown_v2(restart_msg)}"
        await query.edit_message_text(status_msg, parse_mode=ParseMode.MARKDOWN_V2)

    elif query.data == "delete_no":
        await query.edit_message_text("❌ Удаление отменено")

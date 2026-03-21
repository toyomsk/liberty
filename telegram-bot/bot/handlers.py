"""Telegram bot command handlers. DB = source of truth; client_id for delete/get_config."""
import os
import re
import io
import uuid
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Optional
from telegram import (
    Update,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    ReplyKeyboardMarkup,
)
from telegram.ext import ContextTypes
from telegram.constants import ParseMode, ChatAction
from telegram.error import BadRequest

# Состояния интерактивного ввода (context.user_data["state"])
STATE_ADD_CLIENT_NAME = "add_client_name"
STATE_ADD_CLIENT_EXPIRY = "add_client_expiry"
STATE_SET_EXPIRY_CLIENT = "set_expiry_client"
STATE_SET_EXPIRY_VALUE = "set_expiry_value"
STATE_DISABLE_CLIENT_TARGET = "disable_client_target"
STATE_ENABLE_CLIENT_TARGET = "enable_client_target"
STATE_GET_CONFIG_ARG = "get_config_arg"
STATE_DELETE_CLIENT_ID = "delete_client_id"
STATE_LIST_SEARCH = "client_list_search"

# Активный фильтр списка клиентов (подстрока ID/имени); None = все
CLIENT_LIST_FILTER_KEY = "client_list_filter"

CANCEL_WORDS = ("отмена", "cancel")

# ReplyKeyboard: подписи должны совпадать с текстом кнопки символ в символ.
BTN_LIST_CLIENTS = "Список клиентов"
BTN_ADD_CLIENT = "Создать клиента"
BTN_GET_CONFIG = "Получить конфиг"
BTN_SET_EXPIRY = "Изменить срок"
BTN_DISABLE = "Отключить клиента"
BTN_ENABLE = "Включить клиента"
BTN_DELETE = "Удалить клиента"
BTN_STATUS = "Статус сервера"
BTN_RESTART = "Перезапуск VPN"


def main_reply_keyboard() -> ReplyKeyboardMarkup:
    """Постоянная клавиатура внизу чата (как ReplyKeyboardMarkup)."""
    return ReplyKeyboardMarkup(
        [
            [BTN_LIST_CLIENTS, BTN_ADD_CLIENT, BTN_GET_CONFIG],
            [BTN_SET_EXPIRY, BTN_DISABLE, BTN_ENABLE],
            [BTN_DELETE, BTN_STATUS, BTN_RESTART],
        ],
        resize_keyboard=True,
    )

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
    count_clients as db_count_clients,
    list_clients_page as db_list_clients_page,
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


async def _send_typing(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send Telegram typing action to current chat."""
    try:
        chat = update.effective_chat
        if chat and context and context.bot:
            await context.bot.send_chat_action(chat_id=chat.id, action=ChatAction.TYPING)
    except Exception:
        # Non-critical UX helper: ignore transient Telegram/API errors.
        pass


async def start_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Команда /start."""
    user_id = update.effective_user.id

    if not is_admin(user_id):
        await update.message.reply_text("❌ У вас нет прав доступа к этому боту.")
        return

    welcome_text = """🎛 <b>Liberty Bot</b>

Команды доступны кнопками внизу или через slash (интерактивный ввод, отмена: /cancel или текст «отмена» / «cancel»):
/add_client — Создать клиента (далее ввод имени + срок действия)
/list_clients — Список клиентов (ID, имя, активен/неактивен, срок)
/get_config — Получить конфиг (далее ID или имя)
/delete_client — Удалить клиента (далее ID из списка)
/set_expiry — Изменить срок действия клиента (далее ID/имя + новый срок)
/disable_client — Отключить клиента без изменения срока (далее ID/имя)
/enable_client — Включить клиента без изменения срока (далее ID/имя)
/status — Статус сервера
/restart — Перезапуск VPN (с подтверждением)
/cancel — Выход из режима ввода
/help — Эта справка"""
    if MTPROXY_READY:
        welcome_text += "\n\n<i>При создании клиента также поднимается отдельный MTProto-прокси (mtg), ссылка приходит вместе с конфигом.</i>"

    await update.message.reply_text(
        welcome_text,
        parse_mode=ParseMode.HTML,
        reply_markup=main_reply_keyboard(),
    )


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
    await update.message.reply_text(
        "✅ Режим отменён.",
        reply_markup=main_reply_keyboard(),
    )

def _format_expires_at(expires_at: Optional[int]) -> str:
    if expires_at is None:
        return "∞"
    dt = datetime.fromtimestamp(expires_at, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d")


def _client_is_active(
    expires_at: Optional[int],
    disabled_at: Optional[int],
    now_ts: Optional[int] = None,
) -> bool:
    """Клиент считается активным, если не отключён вручную и срок не истёк."""
    if now_ts is None:
        now_ts = int(time.time())
    if disabled_at is not None:
        return False
    if expires_at is not None and expires_at <= now_ts:
        return False
    return True


def _client_list_status_label(
    expires_at: Optional[int],
    disabled_at: Optional[int],
    now_ts: int,
) -> str:
    """Краткая строка для списка: активен / отключён / истёк срок."""
    if _client_is_active(expires_at, disabled_at, now_ts):
        return "✅ активен"
    if disabled_at is not None:
        return "⏸ неактивен · отключён"
    return "⌛ неактивен · срок истёк"


# Ограничиваем размер страницы, чтобы не упираться в лимит 4096 символов и Markdown V2.
CLIENT_LIST_PAGE_SIZE = 15


def _normalize_list_search(search: Optional[str]) -> Optional[str]:
    if search is None:
        return None
    s = str(search).strip()
    return s if s else None


def _client_list_inline_keyboard(
    page: int,
    total_pages: int,
    filter_active: bool,
) -> InlineKeyboardMarkup:
    """Навигация по страницам + поиск + сброс фильтра."""
    rows: list[list[InlineKeyboardButton]] = []
    if total_pages > 1:
        nav: list[InlineKeyboardButton] = []
        if page > 0:
            nav.append(
                InlineKeyboardButton("« Назад", callback_data=f"list_page_{page - 1}")
            )
        if page < total_pages - 1:
            nav.append(
                InlineKeyboardButton("Вперёд »", callback_data=f"list_page_{page + 1}")
            )
        rows.append(nav)
    row2 = [InlineKeyboardButton("🔍 Поиск", callback_data="list_search")]
    if filter_active:
        row2.append(InlineKeyboardButton("✖ Сброс", callback_data="list_filter_clear"))
    rows.append(row2)
    return InlineKeyboardMarkup(rows)


def _client_list_build_page(
    page: int,
    search: Optional[str],
) -> tuple[str, InlineKeyboardMarkup]:
    """Одна страница из SQL: count + LIMIT/OFFSET; search — подстрока ID или имени."""
    sq = _normalize_list_search(search)
    total = db_count_clients(DB_PATH, sq)

    if total == 0:
        if sq:
            result = (
                "🔎 *По запросу* "
                f"`{escape_markdown_v2(sq)}`"
                " *ничего не найдено\\.*"
            )
        else:
            result = "👥 *Клиенты не найдены*"
        return result, _client_list_inline_keyboard(0, 1, bool(sq))

    page_size = CLIENT_LIST_PAGE_SIZE
    total_pages = (total + page_size - 1) // page_size
    page = max(0, min(page, total_pages - 1))
    offset = page * page_size
    chunk = db_list_clients_page(DB_PATH, offset, page_size, sq)

    escaped_total = escape_markdown_v2(str(total))
    ep = escape_markdown_v2(str(page + 1))
    etp = escape_markdown_v2(str(total_pages))
    result = f"👥 *Список клиентов* \\(всего: {escaped_total}\\)\n"
    if sq:
        result += f"🔎 *Фильтр:* `{escape_markdown_v2(sq)}`\n"
    result += f"📄 Стр\\. *{ep}* из *{etp}*\n"
    result += "ℹ️ *✅* активен · *⏸* отключён · *⌛* истёк срок\n\n"

    now_ts = int(time.time())
    for j, (cid, internal_name, expires_at, disabled_at) in enumerate(chunk):
        idx = offset + j + 1
        display = _display_name(internal_name)
        status_txt = _client_list_status_label(expires_at, disabled_at, now_ts)
        result += (
            f"*{escape_markdown_v2(str(idx))}\\.* `{escape_markdown_v2(cid)}` — "
            f"*{escape_markdown_v2(display)}* — *{escape_markdown_v2(status_txt)}*"
        )
        if expires_at is not None:
            result += f" \\(до *{escape_markdown_v2(_format_expires_at(expires_at))}*\\)"
        else:
            result += " \\(∞\\)"
        result += "\n"
        if j < len(chunk) - 1:
            result += "\n"

    return result, _client_list_inline_keyboard(page, total_pages, bool(sq))


async def _reply_client_list_page(
    update: Update,
    page: int,
    search: Optional[str],
) -> None:
    text, kb = _client_list_build_page(page, search)
    await update.message.reply_text(
        text,
        parse_mode=ParseMode.MARKDOWN_V2,
        reply_markup=kb,
    )


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
    await _send_typing(update, context)
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
    await _send_typing(update, context)
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
        "📝 Введите имя клиента (латиница, цифры, _ и -). Для отмены: /cancel",
        reply_markup=main_reply_keyboard(),
    )


async def _do_get_config(update: Update, context: ContextTypes.DEFAULT_TYPE, arg: str) -> None:
    """Общая логика получения конфига по ID или имени."""
    await _send_typing(update, context)
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
        "📝 Введите ID или имя клиента. Для отмены: /cancel",
        reply_markup=main_reply_keyboard(),
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
        "📝 Введите ID или имя клиента. Для отмены: /cancel",
        reply_markup=main_reply_keyboard(),
    )


async def list_clients_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Список клиентов из БД: ID и отображаемое имя (SQL, страницы, поиск)."""
    user_id = update.effective_user.id

    if not is_admin(user_id):
        await update.message.reply_text("❌ Недостаточно прав")
        return
    await _send_typing(update, context)

    context.user_data.pop(CLIENT_LIST_FILTER_KEY, None)
    await _reply_client_list_page(update, 0, None)


async def status_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Статус сервера."""
    user_id = update.effective_user.id

    if not is_admin(user_id):
        await update.message.reply_text("❌ Недостаточно прав")
        return
    await _send_typing(update, context)

    status = get_server_status(DOCKER_COMPOSE_DIR, AWG_CONFIG_DIR)
    await update.message.reply_text(
        status,
        parse_mode=ParseMode.MARKDOWN_V2,
        reply_markup=main_reply_keyboard(),
    )


async def restart_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Перезапуск VPN — только после подтверждения по inline-кнопке."""
    user_id = update.effective_user.id

    if not is_admin(user_id):
        await update.message.reply_text("❌ Недостаточно прав")
        return
    await _send_typing(update, context)

    keyboard = [
        [InlineKeyboardButton("✅ Да, перезапустить", callback_data="restart_yes")],
        [InlineKeyboardButton("❌ Отмена", callback_data="restart_no")],
    ]
    await update.message.reply_text(
        "⚠️ Перезапустить VPN-сервер?",
        reply_markup=InlineKeyboardMarkup(keyboard),
    )


async def _do_delete_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE, client_id: str) -> None:
    """Показать подтверждение удаления по client_id."""
    await _send_typing(update, context)
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
        "📝 Введите ID клиента (см. /list_clients). Для отмены: /cancel",
        reply_markup=main_reply_keyboard(),
    )


async def disable_client_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Отключить клиента без изменения expires_at."""
    user_id = update.effective_user.id
    if not is_admin(user_id):
        await update.message.reply_text("❌ Недостаточно прав")
        return
    context.user_data["state"] = STATE_DISABLE_CLIENT_TARGET
    await update.message.reply_text(
        "📝 Введите ID или имя клиента. Для отмены: /cancel",
        reply_markup=main_reply_keyboard(),
    )


async def enable_client_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Включить клиента без изменения expires_at."""
    user_id = update.effective_user.id
    if not is_admin(user_id):
        await update.message.reply_text("❌ Недостаточно прав")
        return
    context.user_data["state"] = STATE_ENABLE_CLIENT_TARGET
    await update.message.reply_text(
        "📝 Введите ID или имя клиента. Для отмены: /cancel",
        reply_markup=main_reply_keyboard(),
    )


async def _do_set_expiry_client(update: Update, context: ContextTypes.DEFAULT_TYPE, arg: str) -> None:
    """Resolve client by ID or name, then ask for the new expiry."""
    await _send_typing(update, context)
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
    await _send_typing(update, context)
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
    await _send_typing(update, context)
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
    await _send_typing(update, context)
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


# Текст кнопок ReplyKeyboard → тот же обработчик, что и у slash-команды
REPLY_KEYBOARD_MENU_HANDLERS = {
    BTN_LIST_CLIENTS: list_clients_handler,
    BTN_ADD_CLIENT: add_client_handler,
    BTN_GET_CONFIG: get_config_handler,
    BTN_SET_EXPIRY: set_expiry_handler,
    BTN_DISABLE: disable_client_handler,
    BTN_ENABLE: enable_client_handler,
    BTN_DELETE: delete_client_handler,
    BTN_STATUS: status_handler,
    BTN_RESTART: restart_handler,
}


async def interactive_message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обработка текстового ввода в интерактивном режиме (имя, ID и т.д.). Отмена: отмена / cancel."""
    if not update.message or not update.message.text:
        return
    user_id = update.effective_user.id
    if not is_admin(user_id):
        return
    st0 = context.user_data.get("state")
    text = (update.message.text or "").strip()
    if not text and st0 != STATE_LIST_SEARCH:
        return

    menu_handler = REPLY_KEYBOARD_MENU_HANDLERS.get(text)
    if menu_handler is not None:
        # Переключение по меню сбрасывает незавершённый ввод (как выход из режима + новая команда)
        context.user_data.pop("state", None)
        context.user_data.pop("pending_add_client", None)
        context.user_data.pop("pending_set_expiry", None)
        if text != BTN_LIST_CLIENTS:
            context.user_data.pop(CLIENT_LIST_FILTER_KEY, None)
        await menu_handler(update, context)
        return

    state = context.user_data.get("state")
    # Текст "отмена" или "cancel" в любом режиме — выход
    if text.lower() in CANCEL_WORDS:
        context.user_data.pop("state", None)
        context.user_data.pop("pending_add_client", None)
        context.user_data.pop("pending_set_expiry", None)
        await update.message.reply_text(
            "✅ Режим отменён.",
            reply_markup=main_reply_keyboard(),
        )
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
    elif state == STATE_LIST_SEARCH:
        q = _normalize_list_search(text)
        if q is None:
            context.user_data.pop(CLIENT_LIST_FILTER_KEY, None)
        else:
            context.user_data[CLIENT_LIST_FILTER_KEY] = q
        await _reply_client_list_page(update, 0, q)
        return


async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обработчик inline-кнопок: список клиентов (страницы), удаление, перезапуск VPN."""
    query = update.callback_query
    await query.answer()

    user_id = query.from_user.id
    if not is_admin(user_id):
        await query.edit_message_text("❌ Недостаточно прав")
        return

    if query.data.startswith("list_page_"):
        try:
            page = int(query.data[len("list_page_") :])
        except ValueError:
            await query.edit_message_text("❌ Неверная страница")
            return
        search = context.user_data.get(CLIENT_LIST_FILTER_KEY)
        text, inline_kb = _client_list_build_page(page, search)
        try:
            await query.edit_message_text(
                text,
                parse_mode=ParseMode.MARKDOWN_V2,
                reply_markup=inline_kb,
            )
        except BadRequest as e:
            if "message is not modified" in str(e).lower():
                return
            raise
        return

    if query.data == "list_search":
        context.user_data["state"] = STATE_LIST_SEARCH
        await query.message.reply_text(
            "🔍 Введите подстроку для поиска по ID или имени клиента в БД.\n"
            "Пустое сообщение — показать всех записей. Отмена: отмена / cancel",
            reply_markup=main_reply_keyboard(),
        )
        return

    if query.data == "list_filter_clear":
        context.user_data.pop(CLIENT_LIST_FILTER_KEY, None)
        text, inline_kb = _client_list_build_page(0, None)
        try:
            await query.edit_message_text(
                text,
                parse_mode=ParseMode.MARKDOWN_V2,
                reply_markup=inline_kb,
            )
        except BadRequest as e:
            if "message is not modified" in str(e).lower():
                return
            raise
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

    elif query.data == "restart_yes":
        await query.edit_message_text("🔄 Применяю изменения конфигурации VPN…")
        success, message = restart_vpn(DOCKER_COMPOSE_DIR, AWG_CONFIG_DIR)
        if success:
            await query.edit_message_text(f"✅ {message}")
        else:
            await query.edit_message_text(f"⚠️ {message}")

    elif query.data == "restart_no":
        await query.edit_message_text("❌ Перезапуск отменён")

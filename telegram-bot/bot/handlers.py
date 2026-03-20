"""Telegram bot command handlers. DB = source of truth; client_id for delete/get_config."""
import os
import re
import io
import uuid
import logging
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

# Состояния интерактивного ввода (context.user_data["state"])
STATE_ADD_CLIENT_NAME = "add_client_name"
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
    list_clients as db_list_clients,
    delete_client as db_delete_client,
)
from bot.utils import (
    generate_qr_code,
    get_server_status,
    restart_vpn,
    escape_markdown_v2,
)
from bot import xray_manager, hysteria_manager, mtproxy_manager

logger = logging.getLogger(__name__)


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
/add_client — Создать клиента (далее ввод имени)
/list_clients — Список клиентов (ID и имя)
/get_config — Получить конфиг (далее ID или имя)
/delete_client — Удалить клиента (далее ID из списка)
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
    await update.message.reply_text("✅ Режим отменён.")


async def _do_add_client(update: Update, context: ContextTypes.DEFAULT_TYPE, display_name_arg: str) -> None:
    """Общая логика добавления клиента по имени (вызов из add_client или message_handler)."""
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

    await update.message.reply_text(
        f"🔄 Создаю клиента `{escape_markdown_v2(display_name_arg)}`\\.\\.\\.",
        parse_mode=ParseMode.MARKDOWN_V2
    )

    try:
        db_add_client(client_id, internal_name, DB_PATH)
    except Exception as e:
        await update.message.reply_text(f"❌ Ошибка БД: {e}")
        return

    success, config_or_error = awg_create_client(
        internal_name,
        AWG_CONFIG_DIR,
        DOCKER_COMPOSE_DIR,
        WG_PORT,
    )

    if not success:
        db_delete_client(client_id, DB_PATH)
        await update.message.reply_text(f"❌ Ошибка создания клиента AWG: {config_or_error}")
        return

    vless_link = None
    if XRAY_ENABLED:
        ok, vless_or_err = xray_manager.create_client(client_id, remark=internal_name)
        if ok:
            vless_link = vless_or_err
        else:
            logger.warning("Xray create_client: %s", vless_or_err)

    hysteria_link = None
    if HYSTERIA_ENABLED:
        ok, hy_or_err = hysteria_manager.create_client(client_id, remark=internal_name)
        if ok:
            hysteria_link = hy_or_err
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
    if restart_success:
        status_msg += f"🔄 {escape_markdown_v2(restart_msg)}\n"
    else:
        status_msg += f"⚠️ {escape_markdown_v2(restart_msg)}\n"

    await update.message.reply_text(status_msg, parse_mode=ParseMode.MARKDOWN_V2)

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
            await update.message.reply_text(
                f"🔗 *MTProto \\(mtg\\):* `{escape_markdown_v2(internal_name)}`\n`{escape_markdown_v2(mtproxy_link)}`",
                parse_mode=ParseMode.MARKDOWN_V2,
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
                    await update.message.reply_text(
                        f"🔗 *MTProto \\(mtg\\):* `{escape_markdown_v2(name)}`\n`{escape_markdown_v2(mt_link)}`",
                        parse_mode=ParseMode.MARKDOWN_V2,
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
                    await update.message.reply_text(
                        f"🔗 *MTProto \\(mtg\\):* `{escape_markdown_v2(name)}`\n`{escape_markdown_v2(mt_or_err)}`",
                        parse_mode=ParseMode.MARKDOWN_V2,
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
    for i, (cid, internal_name) in enumerate(rows, 1):
        display = _display_name(internal_name)
        result += f"*{escape_markdown_v2(str(i))}\\.* `{escape_markdown_v2(cid)}` — *{escape_markdown_v2(display)}*\n"
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
        await update.message.reply_text("✅ Режим отменён.")
        return
    if not state:
        return

    context.user_data.pop("state", None)
    if state == STATE_ADD_CLIENT_NAME:
        await _do_add_client(update, context, text)
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

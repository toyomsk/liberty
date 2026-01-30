"""Telegram bot command handlers. DB = source of truth; client_id for delete/get_config."""
import os
import re
import io
import uuid
import logging
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

from config.settings import (
    is_admin,
    VPN_CONFIG_DIR,
    DOCKER_COMPOSE_DIR,
    WG_PORT,
    DB_PATH,
    CLIENT_NAME_PREFIX,
    XRAY_ENABLED,
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
from bot import xray_manager

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

    welcome_text = """🎛 *VPN Manager Bot*

Доступные команды:
/add\\_client `\\<имя\\>` \\- Создать клиента \\(AWG \\+ Xray при наличии\\)
/list\\_clients \\- Список клиентов \\(ID и имя\\)
/get\\_config `\\<ID или имя\\>` \\- Получить конфиг
/delete\\_client `\\<ID\\>` \\- Удалить клиента \\(по ID из списка\\)
/status \\- Статус сервера
/restart \\- Перезапуск VPN
/help \\- Эта справка"""

    await update.message.reply_text(welcome_text, parse_mode=ParseMode.MARKDOWN_V2)


async def help_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Команда /help."""
    await start_handler(update, context)


async def add_client_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Добавление клиента: БД + AWG + Xray (по client_id)."""
    user_id = update.effective_user.id

    if not is_admin(user_id):
        await update.message.reply_text("❌ Недостаточно прав")
        return

    if not context.args:
        await update.message.reply_text(
            "❌ Укажите имя клиента: `/add\\_client имя`",
            parse_mode=ParseMode.MARKDOWN_V2
        )
        return

    display_name_arg = context.args[0]
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
        VPN_CONFIG_DIR,
        DOCKER_COMPOSE_DIR,
        WG_PORT,
    )

    if not success:
        db_delete_client(client_id, DB_PATH)
        await update.message.reply_text(f"❌ Ошибка создания клиента AWG: {config_or_error}")
        return

    vless_link = None
    if XRAY_ENABLED:
        ok, vless_or_err = xray_manager.create_client(client_id)
        if ok:
            vless_link = vless_or_err
        else:
            logger.warning("Xray create_client: %s", vless_or_err)

    restart_success, restart_msg = restart_vpn(DOCKER_COMPOSE_DIR, VPN_CONFIG_DIR)

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
                f"🔗 *VLESS \\(Xray\\):*\n`{escape_markdown_v2(vless_link)}`",
                parse_mode=ParseMode.MARKDOWN_V2,
            )
            vless_qr = generate_qr_code(vless_link)
            if vless_qr:
                await update.message.reply_photo(
                    photo=vless_qr,
                    caption="📱 QR\\-код VLESS",
                    parse_mode=ParseMode.MARKDOWN_V2,
                )
    except Exception as e:
        logger.error("Ошибка отправки конфига: %s", e)
        await update.message.reply_text(f"❌ Ошибка отправки конфига: {e}")


async def get_config_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Получение конфига по ID или отображаемому имени."""
    user_id = update.effective_user.id

    if not is_admin(user_id):
        await update.message.reply_text("❌ Недостаточно прав")
        return

    if not context.args:
        await update.message.reply_text(
            "❌ Укажите ID или имя: `/get\\_config \\<ID или имя\\>`",
            parse_mode=ParseMode.MARKDOWN_V2
        )
        return

    arg = context.args[0]
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

    config_content = awg_get_client_config(name, VPN_CONFIG_DIR)
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
            vless_link = xray_manager.get_client_config(client_id)
            if vless_link:
                await update.message.reply_text(
                    f"🔗 *VLESS:*\n`{escape_markdown_v2(vless_link)}`",
                    parse_mode=ParseMode.MARKDOWN_V2,
                )
                vless_qr = generate_qr_code(vless_link)
                if vless_qr:
                    await update.message.reply_photo(
                        photo=vless_qr,
                        caption="📱 QR\\-код VLESS",
                        parse_mode=ParseMode.MARKDOWN_V2,
                    )
    except Exception as e:
        logger.error("Ошибка отправки конфига: %s", e)
        await update.message.reply_text(f"❌ Ошибка отправки конфига: {e}")


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
        result += f"*{escape_markdown_v2(str(i))}\\.* `{escape_markdown_v2(cid)}` \\— *{escape_markdown_v2(display)}*\n"
        if i < total:
            result += "\n"

    await update.message.reply_text(result, parse_mode=ParseMode.MARKDOWN_V2)


async def status_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Статус сервера."""
    user_id = update.effective_user.id

    if not is_admin(user_id):
        await update.message.reply_text("❌ Недостаточно прав")
        return

    status = get_server_status(DOCKER_COMPOSE_DIR, VPN_CONFIG_DIR)
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
    success, message = restart_vpn(DOCKER_COMPOSE_DIR, VPN_CONFIG_DIR)
    await update.message.reply_text(message)


async def delete_client_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Удаление клиента по ID."""
    user_id = update.effective_user.id

    if not is_admin(user_id):
        await update.message.reply_text("❌ Недостаточно прав")
        return

    if not context.args:
        await update.message.reply_text(
            "❌ Укажите ID клиента: `/delete\\_client \\<ID\\>` \\(ID из списка\\)",
            parse_mode=ParseMode.MARKDOWN_V2
        )
        return

    client_id = context.args[0]
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

        awg_delete_client(name, VPN_CONFIG_DIR, DOCKER_COMPOSE_DIR)
        if XRAY_ENABLED:
            xray_manager.delete_client(client_id)
        db_delete_client(client_id, DB_PATH)
        restart_success, restart_msg = restart_vpn(DOCKER_COMPOSE_DIR, VPN_CONFIG_DIR)

        status_msg = f"✅ Клиент удалён\n"
        if restart_success:
            status_msg += f"🔄 {escape_markdown_v2(restart_msg)}"
        else:
            status_msg += f"⚠️ {escape_markdown_v2(restart_msg)}"
        await query.edit_message_text(status_msg, parse_mode=ParseMode.MARKDOWN_V2)

    elif query.data == "delete_no":
        await query.edit_message_text("❌ Удаление отменено")

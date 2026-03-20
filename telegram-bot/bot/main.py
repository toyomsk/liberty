#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Main entry point for the VPN Telegram bot."""
import sys
import os
import logging

# Добавляем корневую директорию проекта в sys.path
# Это нужно для того, чтобы Python мог найти модули config и bot
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters

# Настройка логирования до импорта модулей
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

def main() -> None:
    """Запуск бота."""
    try:
        # Проверка наличия .env файла
        env_path = os.path.join(project_root, '.env')
        if not os.path.exists(env_path):
            logger.error(f"Файл .env не найден: {env_path}")
            logger.error("Создайте .env файл на основе .env.example")
            sys.exit(1)
        
        # Импорт настроек и инициализация БД
        try:
            from config.settings import BOT_TOKEN, DB_PATH
            from bot.db import init_db
            init_db(DB_PATH)
        except ValueError as e:
            logger.error(f"Ошибка загрузки настроек: {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Неожиданная ошибка при загрузке настроек: {e}", exc_info=True)
            sys.exit(1)
        
        if not BOT_TOKEN or BOT_TOKEN == "your_bot_token_here":
            logger.error("BOT_TOKEN не установлен или имеет значение по умолчанию")
            logger.error("Установите правильный BOT_TOKEN в файле .env")
            sys.exit(1)
        
        # Импорт обработчиков
        try:
            from bot.handlers import (
                start_handler,
                help_handler,
                cancel_handler,
                add_client_handler,
                get_config_handler,
                list_clients_handler,
                set_expiry_handler,
                status_handler,
                restart_handler,
                delete_client_handler,
                disable_client_handler,
                enable_client_handler,
                interactive_message_handler,
                button_handler
            )
        except Exception as e:
            logger.error(f"Ошибка импорта обработчиков: {e}", exc_info=True)
            sys.exit(1)
        
        # Создание приложения
        try:
            application = Application.builder().token(BOT_TOKEN).build()
        except Exception as e:
            logger.error(f"Ошибка создания приложения Telegram: {e}")
            logger.error("Проверьте правильность BOT_TOKEN")
            sys.exit(1)
        
        # Периодическая авто-блокировка истёкших клиентов
        try:
            from bot.expiry_manager import expiry_job

            # Проверяем часто, чтобы блокировка была максимально "в моменте".
            application.job_queue.run_repeating(
                expiry_job,
                interval=60,
                first=10,
                name="expiry_job",
            )
        except Exception as e:
            logger.error(f"Ошибка запуска expiry_job: {e}", exc_info=True)
            sys.exit(1)
        
        # Регистрация обработчиков команд
        application.add_handler(CommandHandler("start", start_handler))
        application.add_handler(CommandHandler("help", help_handler))
        application.add_handler(CommandHandler("cancel", cancel_handler))
        application.add_handler(CommandHandler("add_client", add_client_handler))
        application.add_handler(CommandHandler("get_config", get_config_handler))
        application.add_handler(CommandHandler("list_clients", list_clients_handler))
        application.add_handler(CommandHandler("set_expiry", set_expiry_handler))
        application.add_handler(CommandHandler("status", status_handler))
        application.add_handler(CommandHandler("restart", restart_handler))
        application.add_handler(CommandHandler("delete_client", delete_client_handler))
        application.add_handler(CommandHandler("disable_client", disable_client_handler))
        application.add_handler(CommandHandler("enable_client", enable_client_handler))
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, interactive_message_handler))
        application.add_handler(CallbackQueryHandler(button_handler))
        
        # Запуск бота
        logger.info("🤖 Бот запущен!")
        application.run_polling()
        
    except KeyboardInterrupt:
        logger.info("Бот остановлен пользователем")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()

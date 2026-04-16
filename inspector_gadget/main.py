"""
inspector_gadget - main.py
Entry point. Initializes all components and runs the ingester daemon
alongside the Telegram bot in a single async event loop.
"""

import os
import sys
import asyncio
import signal
import logging
import threading

import config
from database import Database
from ingester import Ingester
from analyser import Analyser
from reporter import Reporter
from bot import InspectorBot


def setup_logging():
    """Configure logging for the application."""
    log_dir = os.path.dirname(config.LOG_FILE)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL.upper(), logging.INFO),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        handlers=[
            logging.FileHandler(config.LOG_FILE),
            logging.StreamHandler(sys.stdout),
        ],
    )


def validate_config():
    """Ensure required configuration is set."""
    errors = []

    if not config.TELEGRAM_TOKEN:
        errors.append("IG_TELEGRAM_TOKEN not set")

    if not config.TELEGRAM_CHAT_ID:
        errors.append("IG_TELEGRAM_CHAT_ID not set")

    if not os.path.isdir(config.COWRIE_LOG_DIR):
        errors.append(f"Cowrie log directory not found: {config.COWRIE_LOG_DIR}")

    if errors:
        for e in errors:
            print(f"[ERROR] {e}")
        print("\nSet environment variables or edit config.py.")
        print("Required: IG_TELEGRAM_TOKEN, IG_TELEGRAM_CHAT_ID")
        sys.exit(1)


def run_ingester_loop(ingester: Ingester, analyser: Analyser):
    """
    Run the ingester in a background thread.
    After each ingestion cycle, attempt to match new sessions to clusters.
    """
    logger = logging.getLogger("inspector_gadget.main")
    logger.info("Ingester thread started")

    while True:
        try:
            new_lines = ingester.run_once()
            if new_lines > 0:
                # Match new sessions against existing clusters
                analyser.match_new_sessions()
        except Exception:
            logger.exception("Error in ingester loop")

        import time
        time.sleep(config.INGEST_INTERVAL)


async def async_main():
    """Main async entry point."""
    logger = logging.getLogger("inspector_gadget.main")

    # Ensure DB directory exists
    db_dir = os.path.dirname(config.DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    # Initialize components
    db = Database()
    ingester = Ingester(db)
    analyser = Analyser(db)
    reporter = Reporter(db)
    bot = InspectorBot(db, analyser, reporter, ingester)

    # Start ingester in background thread
    ingester_thread = threading.Thread(
        target=run_ingester_loop,
        args=(ingester, analyser),
        daemon=True,
        name="ingester",
    )
    ingester_thread.start()

    # Start Telegram bot
    await bot.start()

    logger.info("Inspector Gadget is running. Press Ctrl+C to stop.")

    # Wait for shutdown signal
    stop_event = asyncio.Event()

    def signal_handler():
        logger.info("Shutdown signal received")
        stop_event.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, signal_handler)

    await stop_event.wait()

    # Cleanup
    logger.info("Shutting down...")
    await bot.stop()
    logger.info("Inspector Gadget stopped.")


def main():
    """Synchronous entry point."""
    setup_logging()
    validate_config()

    logger = logging.getLogger("inspector_gadget.main")
    logger.info("Inspector Gadget starting up...")
    logger.info("DB: %s", config.DB_PATH)
    logger.info("Logs: %s", config.COWRIE_LOG_DIR)

    asyncio.run(async_main())


if __name__ == "__main__":
    main()

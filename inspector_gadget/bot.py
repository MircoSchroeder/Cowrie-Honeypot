"""
inspector_gadget - bot.py (v3)
Telegram bot with section-filtered reports and pagination.
"""

import logging
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
)

import config
from database import Database
from analyser import Analyser, SEED_TYPES
from reporter import Reporter
from ingester import Ingester

logger = logging.getLogger("inspector_gadget.bot")


class InspectorBot:
    """Telegram bot for controlling and querying Inspector Gadget."""

    def __init__(self, db: Database, analyser: Analyser,
                 reporter: Reporter, ingester: Ingester):
        self.db = db
        self.analyser = analyser
        self.reporter = reporter
        self.ingester = ingester
        self.app: Application | None = None

    async def start(self):
        """Build and start the Telegram bot."""
        self.app = (
            Application.builder()
            .token(config.TELEGRAM_TOKEN)
            .build()
        )

        handlers = [
            ("start", self._cmd_start),
            ("help", self._cmd_help),
            ("seed", self._cmd_seed),
            ("addseed", self._cmd_addseed),
            ("recluster", self._cmd_recluster),
            ("report", self._cmd_report),
            ("clusters", self._cmd_clusters),
            ("unknown", self._cmd_unknown),
            ("weekly", self._cmd_weekly),
            ("status", self._cmd_status),
            ("ingest", self._cmd_ingest),
            ("delete", self._cmd_delete),
            ("inspect", self._cmd_inspect),
            ("search", self._cmd_search),
            ("topseed", self._cmd_topseed),
        ]

        for name, handler in handlers:
            self.app.add_handler(CommandHandler(name, handler))

        # Schedule weekly report
        self.app.job_queue.run_daily(
            self._scheduled_weekly_report,
            time=_weekly_time(),
            days=(config.WEEKLY_REPORT_DAY,),
            name="weekly_report",
        )

        logger.info("Telegram bot starting...")
        await self.app.initialize()
        await self.app.start()
        await self.app.updater.start_polling(drop_pending_updates=True)

    async def stop(self):
        if self.app:
            await self.app.updater.stop()
            await self.app.stop()
            await self.app.shutdown()

    def _authorized(self, update: Update) -> bool:
        chat_id = str(update.effective_chat.id)
        if chat_id != config.TELEGRAM_CHAT_ID:
            logger.warning("Unauthorized access from chat %s", chat_id)
            return False
        return True

    # ------------------------------------------------------------------
    # Core commands
    # ------------------------------------------------------------------

    async def _cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return
        await update.message.reply_text(
            "\U0001f50d Inspector Gadget v3 online.\n"
            "Use /help for commands."
        )

    async def _cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return
        await update.message.reply_text(
            "\U0001f50d Inspector Gadget\n"
            "\u2501" * 20 + "\n"
            "\n"
            "\U0001f4c1 Clusters:\n"
            "/seed <name> <type> <value>\n"
            f"  Types: {', '.join(sorted(SEED_TYPES))}\n"
            "/addseed <name> <type> <value>\n"
            "/recluster <name>\n"
            "/delete <name>\n"
            "\n"
            "\U0001f4ca Reports:\n"
            "/report <name> [section] [page]\n"
            "  Sections: ips, passwords, keys,\n"
            "  downloads, commands\n"
            "/clusters\n"
            "/unknown\n"
            "/weekly\n"
            "/status\n"
            "\n"
            "\U0001f50e Discovery:\n"
            "/inspect <ip>\n"
            "/search <text>\n"
            "/topseed\n"
            "\n"
            "\u2699\ufe0f System:\n"
            "/ingest\n"
        )

    async def _cmd_seed(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return

        args = context.args
        if not args or len(args) < 3:
            await update.message.reply_text(
                "Usage: /seed <name> <type> <value>\n"
                f"Types: {', '.join(sorted(SEED_TYPES))}\n"
                "\n"
                "Examples:\n"
                "  /seed mdrfckr command_text mdrfckr\n"
                "  /seed redtail sha256 a8460f...\n"
                "  /seed scanner1 fingerprint SHA256:..."
            )
            return

        name = args[0]
        seed_type = args[1].lower()
        seed_value = " ".join(args[2:])

        await update.message.reply_text(
            f"\u23f3 Creating cluster '{name}'..."
        )

        result = self.analyser.seed_cluster(name, seed_type, seed_value)

        if "error" in result:
            await update.message.reply_text(f"\u274c {result['error']}")
        else:
            await update.message.reply_text(
                f"\u2705 Cluster '{name}' created\n"
                f"\U0001f331 Seed: {seed_type} = {_trunc(seed_value, 40)}\n"
                f"\U0001f4ca Sessions found: {result['sessions_found']}\n"
                f"\n"
                f"Use /report {name} for details"
            )

    async def _cmd_addseed(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return

        args = context.args
        if not args or len(args) < 3:
            await update.message.reply_text("Usage: /addseed <name> <type> <value>")
            return

        name = args[0]
        seed_type = args[1].lower()
        seed_value = " ".join(args[2:])

        await update.message.reply_text("\u23f3 Adding seed...")

        result = self.analyser.add_seed_to_cluster(name, seed_type, seed_value)

        if "error" in result:
            await update.message.reply_text(f"\u274c {result['error']}")
        else:
            await update.message.reply_text(
                f"\u2705 Seed added to '{name}'\n"
                f"\U0001f331 {result['new_seed']}\n"
                f"\U0001f4ca Total sessions: {result['total_sessions']}"
            )

    async def _cmd_recluster(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return

        args = context.args
        if not args:
            await update.message.reply_text("Usage: /recluster <name>")
            return

        name = args[0]
        await update.message.reply_text(f"\u23f3 Re-clustering '{name}'...")

        result = self.analyser.recluster(name)

        if "error" in result:
            await update.message.reply_text(f"\u274c {result['error']}")
        else:
            await update.message.reply_text(
                f"\u2705 '{name}' reclustered\n"
                f"\U0001f4ca {result['previous_sessions']} \u2192 "
                f"{result['current_sessions']} sessions"
            )

    async def _cmd_report(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """
        /report <name>                  - overview
        /report <name> ips [page]       - all IPs, paginated
        /report <name> passwords [page] - all passwords, paginated
        /report <name> keys             - all SSH keys
        /report <name> downloads        - all downloads
        /report <name> commands [page]  - all commands, paginated
        """
        if not self._authorized(update):
            return

        args = context.args
        if not args:
            await update.message.reply_text(
                "Usage: /report <name> [section] [page]\n"
                "Sections: ips, passwords, keys, downloads, commands"
            )
            return

        name = args[0]
        section = args[1] if len(args) > 1 else None
        page = 0
        if len(args) > 2:
            try:
                page = int(args[2])
            except ValueError:
                page = 0

        report = self.reporter.cluster_report(name, section=section, page=page)
        await update.message.reply_text(report)

    async def _cmd_clusters(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return
        await update.message.reply_text(self.reporter.clusters_overview())

    async def _cmd_unknown(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return
        await update.message.reply_text(self.reporter.unknown_report())

    async def _cmd_weekly(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return
        await update.message.reply_text(self.reporter.weekly_report())

    async def _cmd_status(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return
        status = self.ingester.get_ingestion_status()
        await update.message.reply_text(self.reporter.status_report(status))

    async def _cmd_ingest(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return

        await update.message.reply_text("\u23f3 Ingesting...")
        new_lines = self.ingester.run_once()
        match_result = self.analyser.match_new_sessions()

        msg = f"\u2705 Ingested {new_lines} new lines\n"
        msg += f"\U0001f517 Matched {match_result['matched']} to clusters"

        if match_result.get("per_cluster"):
            for name, count in match_result["per_cluster"].items():
                msg += f"\n  \u2022 {name}: +{count}"

        await update.message.reply_text(msg)

    async def _cmd_delete(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return

        args = context.args
        if not args:
            await update.message.reply_text("Usage: /delete <name>")
            return

        name = args[0]
        cluster = self.db.get_cluster_by_name(name)

        if not cluster:
            await update.message.reply_text(f"\u274c '{name}' not found.")
            return

        count = self.db.get_cluster_session_count(cluster["id"])
        self.db.delete_cluster(cluster["id"])

        await update.message.reply_text(
            f"\U0001f5d1\ufe0f '{name}' deleted.\n"
            f"\U0001f4ca {count} sessions freed."
        )

    # ------------------------------------------------------------------
    # Discovery commands
    # ------------------------------------------------------------------

    async def _cmd_inspect(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return

        args = context.args
        if not args:
            await update.message.reply_text("Usage: /inspect <ip>")
            return

        await update.message.reply_text(f"\u23f3 Inspecting {args[0]}...")
        data = self.analyser.inspect_ip(args[0])
        await update.message.reply_text(self.reporter.inspect_report(data))

    async def _cmd_search(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return

        args = context.args
        if not args:
            await update.message.reply_text("Usage: /search <text>")
            return

        search_text = " ".join(args)
        await update.message.reply_text(f"\u23f3 Searching '{search_text}'...")

        data = self.analyser.search_all(search_text)
        await update.message.reply_text(
            self.reporter.search_report(search_text, data)
        )

    async def _cmd_topseed(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self._authorized(update):
            return

        await update.message.reply_text("\u23f3 Analyzing pool...")
        data = self.analyser.suggest_seeds()
        await update.message.reply_text(self.reporter.topseed_report(data))

    # ------------------------------------------------------------------
    # Scheduled
    # ------------------------------------------------------------------

    async def _scheduled_weekly_report(self, context: ContextTypes.DEFAULT_TYPE):
        logger.info("Sending scheduled weekly report")
        report = self.reporter.weekly_report()
        await context.bot.send_message(
            chat_id=config.TELEGRAM_CHAT_ID,
            text=report,
        )


def _trunc(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."


def _weekly_time():
    from datetime import time as dt_time
    return dt_time(hour=config.WEEKLY_REPORT_HOUR, minute=0, second=0)

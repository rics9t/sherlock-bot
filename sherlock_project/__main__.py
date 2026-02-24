#! /usr/bin/env python3

"""
Sherlock Telegram Bot: Find Usernames Across Social Networks via Telegram

This module wraps Sherlock's username search functionality into a Telegram bot.
"""

import sys
import os
import asyncio
import logging
from io import StringIO
from datetime import datetime

# Check Python version
if sys.version_info < (3, 9):
    python_version = sys.version.split()[0]
    print(
        f"Sherlock requires Python 3.9+\n"
        f"You are using Python {python_version}, which is not supported."
    )
    sys.exit(1)

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters,
    ConversationHandler,
)
from telegram.constants import ParseMode, ChatAction

# Sherlock imports
from sherlock_project.sherlock import sherlock as sherlock_search
from sherlock_project.sites import SitesInformation
from sherlock_project.result import QueryStatus
from sherlock_project.notify import QueryNotify

# ─── Configuration ───────────────────────────────────────────────────────────

BOT_TOKEN = os.environ.get("SHERLOCK_BOT_TOKEN", "YOUR_BOT_TOKEN_HERE")
MAX_USERNAMES_PER_REQUEST = 5
MAX_USERNAME_LENGTH = 64

# Logging setup
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# Conversation states
WAITING_USERNAME = 0


# ─── Custom Query Notifier for Telegram ──────────────────────────────────────

class TelegramQueryNotify(QueryNotify):
    """
    Custom notifier that collects Sherlock results for Telegram output.
    """

    def __init__(self):
        super().__init__()
        self.found_sites = []
        self.not_found_count = 0
        self.error_count = 0
        self.total_count = 0

    def start(self, message=None):
        self.found_sites = []
        self.not_found_count = 0
        self.error_count = 0
        self.total_count = 0

    def update(self, result):
        self.total_count += 1
        if result.status == QueryStatus.CLAIMED:
            self.found_sites.append({
                "site_name": result.site_name,
                "url": result.site_url_user,
            })
        elif result.status == QueryStatus.AVAILABLE:
            self.not_found_count += 1
        else:
            self.error_count += 1

    def finish(self, message=None):
        pass

    def __str__(self):
        return "TelegramQueryNotify"


# ─── Helper Functions ────────────────────────────────────────────────────────

def sanitize_username(username: str) -> str:
    """Sanitize and validate a username."""
    username = username.strip().lstrip("@")
    # Remove potentially dangerous characters
    username = "".join(c for c in username if c.isalnum() or c in "._-")
    return username


def build_results_message(username: str, notifier: TelegramQueryNotify) -> str:
    """Build a formatted results message for Telegram."""
    lines = []
    lines.append(f"🔍 <b>Sherlock Results for:</b> <code>{username}</code>")
    lines.append(f"{'─' * 35}")

    if notifier.found_sites:
        lines.append(f"\n✅ <b>Found on {len(notifier.found_sites)} site(s):</b>\n")

        # Group by categories (if we want, or just list them)
        for i, site in enumerate(notifier.found_sites, 1):
            site_name = site["site_name"]
            url = site["url"]
            lines.append(f"  {i}. <b>{site_name}</b>")
            lines.append(f"     🔗 <a href=\"{url}\">{url}</a>")
            lines.append("")
    else:
        lines.append("\n❌ <b>No accounts found for this username.</b>")

    lines.append(f"{'─' * 35}")
    lines.append(
        f"📊 <b>Summary:</b> "
        f"{len(notifier.found_sites)} found | "
        f"{notifier.not_found_count} not found | "
        f"{notifier.error_count} errors | "
        f"{notifier.total_count} total sites checked"
    )

    return "\n".join(lines)


def split_message(text: str, max_length: int = 4096) -> list[str]:
    """Split a long message into chunks that fit Telegram's message limit."""
    if len(text) <= max_length:
        return [text]

    chunks = []
    lines = text.split("\n")
    current_chunk = ""

    for line in lines:
        if len(current_chunk) + len(line) + 1 > max_length:
            if current_chunk:
                chunks.append(current_chunk)
            current_chunk = line
        else:
            current_chunk += ("\n" if current_chunk else "") + line

    if current_chunk:
        chunks.append(current_chunk)

    return chunks


async def run_sherlock_search(username: str, site_list: list[str] | None = None):
    """
    Run Sherlock search in a thread pool to avoid blocking the bot.
    Returns the notifier with results.
    """
    def _search():
        notifier = TelegramQueryNotify()
        sites = SitesInformation(
            SitesInformation(data_file_path=None).site_data
        )

        # Filter sites if specific sites requested
        site_data = sites.site_data

        if site_list:
            site_data = {
                k: v for k, v in site_data.items()
                if k.lower() in [s.lower() for s in site_list]
            }

        if not site_data:
            site_data = sites.site_data

        # Build the sites information object
        sites_info = SitesInformation(site_data)

        # Run the actual search
        results = sherlock_search(
            username=username,
            site_data=sites_info.site_data,
            query_notify=notifier,
            tor=False,
            unique_tor=False,
            timeout=15,
        )

        return notifier, results

    loop = asyncio.get_event_loop()
    notifier, results = await loop.run_in_executor(None, _search)
    return notifier, results


def generate_txt_report(username: str, notifier: TelegramQueryNotify) -> str:
    """Generate a plain text report."""
    lines = []
    lines.append(f"Sherlock Username Search Report")
    lines.append(f"Username: {username}")
    lines.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f"{'=' * 50}")
    lines.append("")

    if notifier.found_sites:
        lines.append(f"Found on {len(notifier.found_sites)} site(s):")
        lines.append("")
        for site in notifier.found_sites:
            lines.append(f"  [{site['site_name']}] {site['url']}")
    else:
        lines.append("No accounts found.")

    lines.append("")
    lines.append(f"{'=' * 50}")
    lines.append(
        f"Summary: {len(notifier.found_sites)} found, "
        f"{notifier.not_found_count} not found, "
        f"{notifier.error_count} errors, "
        f"{notifier.total_count} total"
    )

    return "\n".join(lines)


# ─── Bot Command Handlers ────────────────────────────────────────────────────

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command."""
    welcome_message = (
        "🕵️ <b>Welcome to Sherlock Bot!</b>\n\n"
        "I can search for usernames across <b>400+</b> social networks "
        "and websites.\n\n"
        "<b>Commands:</b>\n"
        "  /search <code>&lt;username&gt;</code> — Search for a username\n"
        "  /multi <code>&lt;user1 user2 ...&gt;</code> — Search multiple usernames\n"
        "  /sites — List available sites\n"
        "  /help — Show help information\n"
        "  /about — About this bot\n\n"
        "Or simply <b>send me a username</b> and I'll search for it!\n\n"
        "⚠️ <i>Please use responsibly and respect privacy.</i>"
    )

    keyboard = [
        [
            InlineKeyboardButton("🔍 Search Username", callback_data="prompt_search"),
            InlineKeyboardButton("❓ Help", callback_data="help"),
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        welcome_message,
        parse_mode=ParseMode.HTML,
        reply_markup=reply_markup,
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /help command."""
    help_text = (
        "🕵️ <b>Sherlock Bot — Help</b>\n\n"
        "<b>Basic Usage:</b>\n"
        "Send me any username and I'll search for it across social networks.\n\n"
        "<b>Commands:</b>\n\n"
        "🔹 <code>/search username</code>\n"
        "   Search for a single username.\n"
        "   Example: <code>/search john_doe</code>\n\n"
        "🔹 <code>/multi user1 user2 user3</code>\n"
        "   Search for multiple usernames (max 5).\n"
        "   Example: <code>/multi alice bob charlie</code>\n\n"
        "🔹 <code>/sites</code>\n"
        "   Show the number of supported sites.\n\n"
        "🔹 <code>/cancel</code>\n"
        "   Cancel current operation.\n\n"
        "<b>Tips:</b>\n"
        "• Searches may take 1-3 minutes depending on network conditions\n"
        "• Results include direct links to found profiles\n"
        "• A text report file is attached for easy saving\n"
        "• Username must be 1-64 characters (alphanumeric, dots, dashes, underscores)\n"
    )
    await update.message.reply_text(help_text, parse_mode=ParseMode.HTML)


async def about_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /about command."""
    about_text = (
        "🕵️ <b>Sherlock Telegram Bot</b>\n\n"
        "This bot is powered by "
        "<a href='https://github.com/sherlock-project/sherlock'>Sherlock Project</a>, "
        "an open-source tool for finding usernames across social networks.\n\n"
        "<b>Disclaimer:</b>\n"
        "This tool is intended for legitimate purposes only. "
        "Users are responsible for ensuring they comply with applicable laws "
        "and terms of service.\n\n"
        "🔒 <i>No search data is stored or logged.</i>"
    )
    await update.message.reply_text(
        about_text,
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
    )


async def sites_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /sites command — show supported site count."""
    try:
        sites = SitesInformation(data_file_path=None)
        site_count = len(sites.site_data)
        site_names = sorted(sites.site_data.keys())

        message = (
            f"🌐 <b>Sherlock currently supports {site_count} sites!</b>\n\n"
            f"Some popular ones include:\n"
        )

        # Show first 30 as a sample
        popular = site_names[:30]
        message += ", ".join(f"<code>{s}</code>" for s in popular)
        message += f"\n\n... and {site_count - 30} more!"

        await update.message.reply_text(message, parse_mode=ParseMode.HTML)

    except Exception as e:
        logger.error(f"Error loading sites: {e}")
        await update.message.reply_text(
            "❌ Error loading site information. Please try again later."
        )


async def search_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /search command."""
    if not context.args:
        await update.message.reply_text(
            "🔍 <b>Please provide a username to search.</b>\n\n"
            "Usage: <code>/search username</code>\n"
            "Example: <code>/search john_doe</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    username = sanitize_username(context.args[0])

    if not username:
        await update.message.reply_text(
            "❌ Invalid username. Please use alphanumeric characters, "
            "dots, dashes, or underscores."
        )
        return

    if len(username) > MAX_USERNAME_LENGTH:
        await update.message.reply_text(
            f"❌ Username too long. Maximum {MAX_USERNAME_LENGTH} characters."
        )
        return

    await perform_search(update, context, username)


async def multi_search_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /multi command for searching multiple usernames."""
    if not context.args:
        await update.message.reply_text(
            "🔍 <b>Please provide usernames to search.</b>\n\n"
            "Usage: <code>/multi user1 user2 user3</code>\n"
            f"Maximum {MAX_USERNAMES_PER_REQUEST} usernames per request.",
            parse_mode=ParseMode.HTML,
        )
        return

    usernames = [sanitize_username(u) for u in context.args[:MAX_USERNAMES_PER_REQUEST]]
    usernames = [u for u in usernames if u and len(u) <= MAX_USERNAME_LENGTH]

    if not usernames:
        await update.message.reply_text("❌ No valid usernames provided.")
        return

    if len(context.args) > MAX_USERNAMES_PER_REQUEST:
        await update.message.reply_text(
            f"⚠️ Only the first {MAX_USERNAMES_PER_REQUEST} usernames will be searched.",
            parse_mode=ParseMode.HTML,
        )

    for username in usernames:
        await perform_search(update, context, username)


async def handle_text_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle plain text messages as username searches."""
    text = update.message.text.strip()

    # Ignore messages that look like commands
    if text.startswith("/"):
        return

    # Handle multi-word input
    words = text.split()

    if len(words) > MAX_USERNAMES_PER_REQUEST:
        await update.message.reply_text(
            f"⚠️ Too many usernames. Maximum {MAX_USERNAMES_PER_REQUEST} at once.\n"
            f"Searching the first {MAX_USERNAMES_PER_REQUEST}..."
        )
        words = words[:MAX_USERNAMES_PER_REQUEST]

    for word in words:
        username = sanitize_username(word)
        if username and len(username) <= MAX_USERNAME_LENGTH:
            await perform_search(update, context, username)
        else:
            await update.message.reply_text(
                f"❌ Skipping invalid username: <code>{word}</code>",
                parse_mode=ParseMode.HTML,
            )


async def perform_search(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    username: str,
):
    """Perform the actual Sherlock search and send results."""
    chat_id = update.effective_chat.id

    # Send initial status message
    status_msg = await update.message.reply_text(
        f"🔍 <b>Searching for:</b> <code>{username}</code>\n\n"
        f"⏳ This may take 1-3 minutes...\n"
        f"Checking across 400+ websites...",
        parse_mode=ParseMode.HTML,
    )

    # Show typing indicator
    await context.bot.send_chat_action(chat_id=chat_id, action=ChatAction.TYPING)

    try:
        # Run the search
        notifier, results = await run_sherlock_search(username)

        # Build the results message
        results_text = build_results_message(username, notifier)

        # Delete the status message
        await status_msg.delete()

        # Send results (handle long messages)
        chunks = split_message(results_text)
        for chunk in chunks:
            await update.message.reply_text(
                chunk,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )

        # Generate and send text report as a file
        if notifier.found_sites:
            report = generate_txt_report(username, notifier)
            report_bytes = report.encode("utf-8")

            await context.bot.send_document(
                chat_id=chat_id,
                document=report_bytes,
                filename=f"sherlock_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                caption=f"📄 Full report for <code>{username}</code>",
                parse_mode=ParseMode.HTML,
            )

        # Send summary keyboard
        keyboard = [
            [
                InlineKeyboardButton(
                    "🔍 Search Another",
                    callback_data="prompt_search",
                ),
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await update.message.reply_text(
            "✅ Search complete! What would you like to do next?",
            reply_markup=reply_markup,
        )

    except Exception as e:
        logger.error(f"Search error for '{username}': {e}", exc_info=True)

        try:
            await status_msg.delete()
        except Exception:
            pass

        await update.message.reply_text(
            f"❌ <b>Error searching for</b> <code>{username}</code>\n\n"
            f"Error: {str(e)}\n\n"
            f"Please try again later.",
            parse_mode=ParseMode.HTML,
        )


async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle inline keyboard callbacks."""
    query = update.callback_query
    await query.answer()

    if query.data == "prompt_search":
        await query.message.reply_text(
            "🔍 Send me a username to search for:",
            parse_mode=ParseMode.HTML,
        )
    elif query.data == "help":
        help_text = (
            "🕵️ <b>Quick Help</b>\n\n"
            "• Send any username to search\n"
            "• Use <code>/search username</code>\n"
            "• Use <code>/multi user1 user2</code> for multiple\n"
            "• Use <code>/help</code> for full details"
        )
        await query.message.reply_text(help_text, parse_mode=ParseMode.HTML)


async def cancel_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /cancel command."""
    await update.message.reply_text(
        "🛑 Operation cancelled.\n\nSend /start to begin again."
    )


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle errors globally."""
    logger.error(f"Update {update} caused error: {context.error}", exc_info=context.error)

    if update and update.effective_message:
        await update.effective_message.reply_text(
            "❌ An unexpected error occurred. Please try again later."
        )


# ─── Main Entry Point ────────────────────────────────────────────────────────

def main():
    """Start the Telegram bot."""
    if BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("=" * 60)
        print("ERROR: Bot token not configured!")
        print()
        print("Please set your Telegram bot token:")
        print("  Option 1: Set environment variable SHERLOCK_BOT_TOKEN")
        print("  Option 2: Edit BOT_TOKEN in this file")
        print()
        print("Get a token from @BotFather on Telegram")
        print("=" * 60)
        sys.exit(1)

    print("🕵️  Sherlock Telegram Bot Starting...")
    print(f"   Python Version: {sys.version.split()[0]}")

    # Build the application
    application = (
        Application.builder()
        .token(BOT_TOKEN)
        .read_timeout(30)
        .write_timeout(30)
        .connect_timeout(30)
        .build()
    )

    # Register command handlers
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("about", about_command))
    application.add_handler(CommandHandler("sites", sites_command))
    application.add_handler(CommandHandler("search", search_command))
    application.add_handler(CommandHandler("multi", multi_search_command))
    application.add_handler(CommandHandler("cancel", cancel_command))

    # Register callback handler for inline keyboards
    application.add_handler(CallbackQueryHandler(callback_handler))

    # Register text message handler (for direct username input)
    application.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text_message)
    )

    # Register error handler
    application.add_error_handler(error_handler)

    # Start the bot
    print("✅ Bot is running! Press Ctrl+C to stop.")
    application.run_polling(
        allowed_updates=Update.ALL_TYPES,
        drop_pending_updates=True,
    )


if __name__ == "__main__":
    main()

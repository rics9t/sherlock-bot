#! /usr/bin/env python3

"""
Sherlock Telegram Bot: Find Usernames Across Social Networks via Telegram
"""

import sys
import os
import asyncio
import logging
from datetime import datetime

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
)
from telegram.constants import ParseMode, ChatAction

from sherlock_project.sherlock import sherlock as sherlock_search
from sherlock_project.sites import SitesInformation
from sherlock_project.result import QueryStatus
from sherlock_project.notify import QueryNotify

# ─── Configuration ───────────────────────────────────────────────────────────

BOT_TOKEN = os.environ.get("SHERLOCK_BOT_TOKEN", "YOUR_BOT_TOKEN_HERE")

# Comma-separated list of allowed Telegram user IDs
# Example: "123456789,987654321"
ALLOWED_USER_IDS_RAW = os.environ.get("ALLOWED_USER_IDS", "")
ALLOWED_USER_IDS: set[int] = set()

if ALLOWED_USER_IDS_RAW.strip():
    try:
        ALLOWED_USER_IDS = {
            int(uid.strip())
            for uid in ALLOWED_USER_IDS_RAW.split(",")
            if uid.strip().isdigit()
        }
    except ValueError:
        print("ERROR: ALLOWED_USER_IDS must be comma-separated integers")
        sys.exit(1)

MAX_USERNAMES_PER_REQUEST = int(os.environ.get("MAX_USERNAMES", "5"))
MAX_USERNAME_LENGTH = int(os.environ.get("MAX_USERNAME_LENGTH", "64"))

# Logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


# ─── Access Control ──────────────────────────────────────────────────────────

def is_user_allowed(user_id: int) -> bool:
    """Check if a user is allowed to use the bot."""
    # If no allowed users configured, deny everyone (secure by default)
    if not ALLOWED_USER_IDS:
        logger.warning(
            f"ALLOWED_USER_IDS is empty. Denying user {user_id}. "
            f"Set the environment variable to allow access."
        )
        return False
    return user_id in ALLOWED_USER_IDS


async def check_access(update: Update) -> bool:
    """Check user access and send denial message if unauthorized."""
    user_id = update.effective_user.id
    username = update.effective_user.username or "unknown"

    if not is_user_allowed(user_id):
        logger.warning(f"Unauthorized access attempt by user {user_id} (@{username})")
        await update.message.reply_text(
            "🚫 <b>Access Denied</b>\n\n"
            f"Your user ID <code>{user_id}</code> is not authorized to use this bot.\n\n"
            "Contact the bot administrator to request access.",
            parse_mode=ParseMode.HTML,
        )
        return False
    return True


# ─── Custom Query Notifier ───────────────────────────────────────────────────

class TelegramQueryNotify(QueryNotify):
    """Collects Sherlock results for Telegram output."""

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


# ─── Helpers ─────────────────────────────────────────────────────────────────

def sanitize_username(username: str) -> str:
    """Sanitize and validate a username."""
    username = username.strip().lstrip("@")
    username = "".join(c for c in username if c.isalnum() or c in "._-")
    return username


def build_results_message(username: str, notifier: TelegramQueryNotify) -> str:
    """Build formatted results message."""
    lines = []
    lines.append(f"🔍 <b>Sherlock Results for:</b> <code>{username}</code>")
    lines.append(f"{'─' * 35}")

    if notifier.found_sites:
        lines.append(f"\n✅ <b>Found on {len(notifier.found_sites)} site(s):</b>\n")
        for i, site in enumerate(notifier.found_sites, 1):
            lines.append(f"  {i}. <b>{site['site_name']}</b>")
            lines.append(f"     🔗 <a href=\"{site['url']}\">{site['url']}</a>")
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
    """Split long message into Telegram-safe chunks."""
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
    """Run Sherlock search in a thread pool to avoid blocking."""
    def _search():
        notifier = TelegramQueryNotify()
        sites = SitesInformation(
            SitesInformation(data_file_path=None).site_data
        )

        site_data = sites.site_data

        if site_list:
            site_data = {
                k: v for k, v in site_data.items()
                if k.lower() in [s.lower() for s in site_list]
            }
            if not site_data:
                site_data = sites.site_data

        sites_info = SitesInformation(site_data)

        results = sherlock_search(
            username=username,
            site_data=sites_info.site_data,
            query_notify=notifier,
            tor=False,
            unique_tor=False,
            timeout=15,
        )

        return notifier, results

    loop = asyncio.get_running_loop()
    notifier, results = await loop.run_in_executor(None, _search)
    return notifier, results


def generate_txt_report(username: str, notifier: TelegramQueryNotify) -> str:
    """Generate a plain text report."""
    lines = [
        "Sherlock Username Search Report",
        f"Username: {username}",
        f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "=" * 50,
        "",
    ]

    if notifier.found_sites:
        lines.append(f"Found on {len(notifier.found_sites)} site(s):")
        lines.append("")
        for site in notifier.found_sites:
            lines.append(f"  [{site['site_name']}] {site['url']}")
    else:
        lines.append("No accounts found.")

    lines.extend([
        "",
        "=" * 50,
        f"Summary: {len(notifier.found_sites)} found, "
        f"{notifier.not_found_count} not found, "
        f"{notifier.error_count} errors, "
        f"{notifier.total_count} total",
    ])

    return "\n".join(lines)


# ─── Command Handlers ────────────────────────────────────────────────────────

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command."""
    if not await check_access(update):
        return

    user_id = update.effective_user.id
    welcome_message = (
        "🕵️ <b>Welcome to Sherlock Bot!</b>\n\n"
        "I can search for usernames across <b>400+</b> social networks.\n\n"
        "<b>Commands:</b>\n"
        "  /search <code>&lt;username&gt;</code> — Search for a username\n"
        "  /multi <code>&lt;user1 user2 ...&gt;</code> — Search multiple usernames\n"
        "  /sites — List available sites\n"
        "  /myid — Show your Telegram user ID\n"
        "  /help — Show help information\n"
        "  /about — About this bot\n\n"
        "Or simply <b>send me a username</b> and I'll search for it!\n\n"
        f"🆔 Your user ID: <code>{user_id}</code>\n"
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
    if not await check_access(update):
        return

    help_text = (
        "🕵️ <b>Sherlock Bot — Help</b>\n\n"
        "<b>Basic Usage:</b>\n"
        "Send me any username and I'll search for it.\n\n"
        "<b>Commands:</b>\n\n"
        "🔹 <code>/search username</code>\n"
        "   Search for a single username.\n"
        "   Example: <code>/search john_doe</code>\n\n"
        "🔹 <code>/multi user1 user2 user3</code>\n"
        "   Search multiple usernames (max 5).\n"
        "   Example: <code>/multi alice bob charlie</code>\n\n"
        "🔹 <code>/sites</code>\n"
        "   Show the number of supported sites.\n\n"
        "🔹 <code>/myid</code>\n"
        "   Show your Telegram user ID.\n\n"
        "🔹 <code>/cancel</code>\n"
        "   Cancel current operation.\n\n"
        "<b>Tips:</b>\n"
        "• Searches may take 1-3 minutes\n"
        "• Results include direct links to found profiles\n"
        "• A text report file is attached for easy saving\n"
    )
    await update.message.reply_text(help_text, parse_mode=ParseMode.HTML)


async def about_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /about command."""
    if not await check_access(update):
        return

    about_text = (
        "🕵️ <b>Sherlock Telegram Bot</b>\n\n"
        "Powered by "
        "<a href='https://github.com/sherlock-project/sherlock'>Sherlock Project</a>.\n\n"
        "<b>Disclaimer:</b>\n"
        "This tool is intended for legitimate purposes only.\n\n"
        "🔒 <i>No search data is stored or logged.</i>"
    )
    await update.message.reply_text(
        about_text,
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
    )


async def myid_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /myid command — show user their Telegram ID."""
    user = update.effective_user
    await update.message.reply_text(
        f"🆔 <b>Your Telegram Info:</b>\n\n"
        f"  User ID: <code>{user.id}</code>\n"
        f"  Username: @{user.username or 'N/A'}\n"
        f"  Name: {user.full_name}\n\n"
        f"{'✅ You are authorized.' if is_user_allowed(user.id) else '🚫 You are NOT authorized.'}",
        parse_mode=ParseMode.HTML,
    )


async def sites_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /sites command."""
    if not await check_access(update):
        return

    try:
        sites = SitesInformation(data_file_path=None)
        site_count = len(sites.site_data)
        site_names = sorted(sites.site_data.keys())

        popular = site_names[:30]
        message = (
            f"🌐 <b>Sherlock supports {site_count} sites!</b>\n\n"
            f"Some include:\n"
            + ", ".join(f"<code>{s}</code>" for s in popular)
            + f"\n\n... and {site_count - 30} more!"
        )

        await update.message.reply_text(message, parse_mode=ParseMode.HTML)

    except Exception as e:
        logger.error(f"Error loading sites: {e}")
        await update.message.reply_text(
            "❌ Error loading site information. Please try again later."
        )


async def search_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /search command."""
    if not await check_access(update):
        return

    if not context.args:
        await update.message.reply_text(
            "🔍 <b>Please provide a username.</b>\n\n"
            "Usage: <code>/search username</code>\n"
            "Example: <code>/search john_doe</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    username = sanitize_username(context.args[0])

    if not username:
        await update.message.reply_text(
            "❌ Invalid username. Use alphanumeric characters, dots, dashes, or underscores."
        )
        return

    if len(username) > MAX_USERNAME_LENGTH:
        await update.message.reply_text(
            f"❌ Username too long. Maximum {MAX_USERNAME_LENGTH} characters."
        )
        return

    await perform_search(update, context, username)


async def multi_search_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /multi command."""
    if not await check_access(update):
        return

    if not context.args:
        await update.message.reply_text(
            "🔍 <b>Please provide usernames.</b>\n\n"
            "Usage: <code>/multi user1 user2 user3</code>\n"
            f"Maximum {MAX_USERNAMES_PER_REQUEST} per request.",
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
            f"⚠️ Only the first {MAX_USERNAMES_PER_REQUEST} usernames will be searched."
        )

    for username in usernames:
        await perform_search(update, context, username)


async def handle_text_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle plain text messages as username searches."""
    if not await check_access(update):
        return

    text = update.message.text.strip()

    if text.startswith("/"):
        return

    words = text.split()

    if len(words) > MAX_USERNAMES_PER_REQUEST:
        await update.message.reply_text(
            f"⚠️ Too many usernames. Searching the first {MAX_USERNAMES_PER_REQUEST}..."
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

    status_msg = await update.message.reply_text(
        f"🔍 <b>Searching for:</b> <code>{username}</code>\n\n"
        f"⏳ This may take 1-3 minutes...\n"
        f"Checking across 400+ websites...",
        parse_mode=ParseMode.HTML,
    )

    await context.bot.send_chat_action(chat_id=chat_id, action=ChatAction.TYPING)

    try:
        notifier, results = await run_sherlock_search(username)

        results_text = build_results_message(username, notifier)

        await status_msg.delete()

        chunks = split_message(results_text)
        for chunk in chunks:
            await update.message.reply_text(
                chunk,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )

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

        keyboard = [
            [InlineKeyboardButton("🔍 Search Another", callback_data="prompt_search")]
        ]
        await update.message.reply_text(
            "✅ Search complete!",
            reply_markup=InlineKeyboardMarkup(keyboard),
        )

    except Exception as e:
        logger.error(f"Search error for '{username}': {e}", exc_info=True)

        try:
            await status_msg.delete()
        except Exception:
            pass

        await update.message.reply_text(
            f"❌ <b>Error searching for</b> <code>{username}</code>\n\n"
            f"Error: {str(e)}\n\nPlease try again later.",
            parse_mode=ParseMode.HTML,
        )


async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle inline keyboard callbacks."""
    query = update.callback_query
    await query.answer()

    user_id = query.from_user.id
    if not is_user_allowed(user_id):
        await query.message.reply_text("🚫 Access denied.")
        return

    if query.data == "prompt_search":
        await query.message.reply_text("🔍 Send me a username to search for:")
    elif query.data == "help":
        await query.message.reply_text(
            "🕵️ <b>Quick Help</b>\n\n"
            "• Send any username to search\n"
            "• Use <code>/search username</code>\n"
            "• Use <code>/multi user1 user2</code> for multiple\n"
            "• Use <code>/help</code> for full details",
            parse_mode=ParseMode.HTML,
        )


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


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    """Start the Telegram bot."""
    if BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("=" * 60)
        print("ERROR: Bot token not configured!")
        print()
        print("Set environment variable: SHERLOCK_BOT_TOKEN")
        print("Get a token from @BotFather on Telegram")
        print("=" * 60)
        sys.exit(1)

    if not ALLOWED_USER_IDS:
        print("=" * 60)
        print("WARNING: ALLOWED_USER_IDS is not set!")
        print("No one will be able to use the bot.")
        print()
        print("Set environment variable: ALLOWED_USER_IDS=123456789,987654321")
        print("Use @userinfobot on Telegram to find your user ID.")
        print("=" * 60)

    print("🕵️  Sherlock Telegram Bot Starting...")
    print(f"   Python Version: {sys.version.split()[0]}")
    print(f"   Allowed Users: {ALLOWED_USER_IDS if ALLOWED_USER_IDS else 'NONE (bot locked)'}")

    # Build the application
    application = (
        Application.builder()
        .token(BOT_TOKEN)
        .read_timeout(30)
        .write_timeout(30)
        .connect_timeout(30)
        .build()
    )

    # Register handlers
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("about", about_command))
    application.add_handler(CommandHandler("myid", myid_command))
    application.add_handler(CommandHandler("sites", sites_command))
    application.add_handler(CommandHandler("search", search_command))
    application.add_handler(CommandHandler("multi", multi_search_command))
    application.add_handler(CommandHandler("cancel", cancel_command))
    application.add_handler(CallbackQueryHandler(callback_handler))
    application.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text_message)
    )
    application.add_error_handler(error_handler)

    print("✅ Bot is running! Press Ctrl+C to stop.")

    # ─── FIX for Python 3.14+ (no auto event loop) ───────────────────────
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    application.run_polling(
        allowed_updates=Update.ALL_TYPES,
        drop_pending_updates=True,
    )


if __name__ == "__main__":
    main()

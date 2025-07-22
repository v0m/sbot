import asyncio
import logging
import subprocess
import tempfile
import os
import time
from urllib.parse import urlparse
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    CallbackContext,
    CallbackQueryHandler
)

# تمكين التسجيل
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# ثغرات للفحص
VULNERABILITIES = {
    'sql': 'SQL Injection',
    'xss': 'Cross-Site Scripting (XSS)',
    'csrf': 'Cross-Site Request Forgery (CSRF)',
    'lfi': 'Local File Inclusion',
    'rfi': 'Remote File Inclusion',
    'xxe': 'XML External Entity (XXE)',
    'ssrf': 'Server-Side Request Forgery (SSRF)',
    'cmd': 'Command Injection',
    'idor': 'Insecure Direct Object References',
    'ports': 'Open Ports Scan',
    'services': 'Services Detection'
}

# تعريف الدوال أولاً
async def start(update: Update, context: CallbackContext) -> None:
    """إرسال رسالة ترحيبية عند استخدام الأمر /start"""
    user = update.effective_user
    await update.message.reply_text(
        f"مرحبًا {user.first_name}!\n\n"
        "أنا بوت فحص الثغرات الأمنية المتقدم. أرسل لي رابط موقع وسأفحصه باستخدام sqlmap و nmap.\n\n"
        "استخدم /scan <رابط الموقع> لبدء الفحص أو /help للمساعدة."
    )

async def help_command(update: Update, context: CallbackContext) -> None:
    """إرسال رسالة المساعدة عند استخدام الأمر /help"""
    await update.message.reply_text(
        "🛡️ كيفية استخدام بوت الفحص الأمني المتقدم:\n\n"
        "1. الفحص الأساسي:\n"
        "   - أرسل /scan <رابط الموقع> (مثال: /scan https://example.com)\n"
        "   - أو أرسل الرابط مباشرة\n\n"
        "2. الفحص المتقدم:\n"
        "   - بعد الفحص الأساسي، استخدم الأزرار للفحوصات المتخصصة:\n"
        "     * فحص SQL Injection متقدم (sqlmap)\n"
        "     * فحص المنافذ المفتوحة والخدمات (nmap)\n"
        "     * فحص شامل لجميع الثغرات\n\n"
        "3. أوامر خاصة:\n"
        "   /nmap <رابط> - فحص nmap سريع\n"
        "   /sqlmap <رابط> - فحص sqlmap سريع\n\n"
        "⚠️ تحذير: تأكد من أن لديك إذنًا لفحص الموقع المستهدف."
    )

# ... (أضف هنا جميع الدوال الأخرى بنفس الطريقة قبل الدالة main())

def main() -> None:
    """تشغيل البوت"""
    application = Application.builder().token("7869694847:AAGqNKvVPcz6NTURhifRN4hgg4Y2azH2Zs8").build()
    
    # المعالجات
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    # ... (أضف باقي المعالجات هنا)
    
    application.run_polling()

if __name__ == '__main__':
    main()

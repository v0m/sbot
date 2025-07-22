import logging
import subprocess
import tempfile
import os
import asyncio
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackContext,
    CallbackQueryHandler,
    filters
)
import requests
from urllib.parse import urlparse
import nmap
import json
from datetime import datetime

# إعداد التسجيل
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# قائمة الثغرات للفحص
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

async def start(update: Update, context: CallbackContext) -> None:
    user = update.effective_user
    welcome_message = (
        f"👋 مرحبًا {user.first_name}!\n"
        "أنا بوت الفحص الأمني المتقدم 🛡️\n"
        "أرسل لي رابط موقع وسأقوم بفحصه خطوة بخطوة.\n\n"
        "✅ ابدأ بـ /scan <الرابط> أو فقط أرسل الرابط مباشرة.\n"
        "📖 للمساعدة استخدم /help"
    )
    await update.message.reply_text(welcome_message)

async def help_command(update: Update, context: CallbackContext) -> None:
    help_text = (
        "📖 *كيفية الاستخدام:*\n"
        "1️⃣ أرسل /scan <الرابط> لبدء الفحص الأساسي.\n"
        "2️⃣ بعد الفحص، اختر نوع الفحص المتقدم من الأزرار التفاعلية.\n"
        "3️⃣ للأوامر المباشرة:\n"
        "   - /nmap <الرابط> لفحص المنافذ\n"
        "   - /sqlmap <الرابط> لفحص SQL Injection\n\n"
        "⚠️ تأكد من أنك مخوّل بفحص الموقع المستهدف."
    )
    await update.message.reply_text(help_text, parse_mode='Markdown')

async def scan_website(update: Update, context: CallbackContext) -> None:
    if update.message.text.startswith('/scan'):
        if not context.args:
            await update.message.reply_text("❗ الرجاء إدخال رابط الموقع بعد الأمر /scan")
            return
        url = context.args[0]
    else:
        url = update.message.text

    if not is_valid_url(url):
        await update.message.reply_text("⛔ الرابط غير صالح. تأكد أنه يبدأ بـ http:// أو https://")
        return

    await update.message.reply_text(f"🔎 *بدء فحص الموقع:* {url}", parse_mode='Markdown')
    steps = [
        "✅ المرحلة 1/4: التحقق من الرابط...",
        "🔍 المرحلة 2/4: فحص الثغرات السريعة (SQL/XSS/CSRF)...",
        "🛰️ المرحلة 3/4: فحص المنافذ والخدمات (Nmap)...",
        "📦 المرحلة 4/4: تجميع التقرير النهائي..."
    ]
    for step in steps:
        await update.message.reply_text(step)
        await asyncio.sleep(2)

    results = perform_basic_scan(url)
    nmap_results = perform_quick_nmap_scan(url)
    results['nmap'] = nmap_results

    await send_results(update, context, url, results)

def perform_basic_scan(url: str) -> dict:
    results = {'url': url, 'vulnerabilities': {}}
    try:
        sql_test = f"{url}?id=1'"
        response = requests.get(sql_test, timeout=10)
        if any(err in response.text.lower() for err in ['sql', 'syntax', 'mysql', 'ora-']):
            results['vulnerabilities']['sql'] = 'محتمل وجود SQL Injection'

        xss_test = f"{url}?search=<script>alert('xss')</script>"
        response = requests.get(xss_test, timeout=10)
        if '<script>alert(\'xss\')</script>' in response.text:
            results['vulnerabilities']['xss'] = 'محتمل وجود XSS'

        response = requests.get(url, timeout=10)
        if 'csrf' not in response.text.lower() and 'token' not in response.text.lower():
            results['vulnerabilities']['csrf'] = 'لم يتم العثور على حماية CSRF'
    except requests.RequestException as e:
        results['error'] = f"خطأ أثناء الفحص: {str(e)}"
    return results

def perform_quick_nmap_scan(url: str) -> dict:
    nm = nmap.PortScanner()
    domain = urlparse(url).netloc
    results = {'target': domain, 'ports': {}}
    try:
        nm.scan(hosts=domain, arguments='-F -T4')
        for host in nm.all_hosts():
            results['host'] = host
            results['state'] = nm[host].state()
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    service = nm[host][proto][port]
                    results['ports'][port] = {
                        'state': service['state'],
                        'service': service['name'],
                        'product': service.get('product', ''),
                        'version': service.get('version', '')
                    }
    except Exception as e:
        results['error'] = f"خطأ في فحص Nmap: {str(e)}"
    return results

async def send_results(update: Update, context: CallbackContext, url: str, results: dict) -> None:
    message = f"📊 *تقرير الفحص لموقع:* {url}\n\n"
    if 'error' in results:
        message += f"❌ {results['error']}"
    else:
        if results['vulnerabilities']:
            message += "⚠️ *الثغرات المكتشفة:*\n"
            for vuln, desc in results['vulnerabilities'].items():
                message += f"🔴 {VULNERABILITIES.get(vuln, vuln)}: {desc}\n"
        else:
            message += "✅ لم يتم اكتشاف ثغرات في الفحص الأساسي.\n"
        nmap_data = results.get('nmap', {})
        if nmap_data and not nmap_data.get('error'):
            message += "\n🛰️ *نتائج Nmap:*\n"
            for port, info in nmap_data['ports'].items():
                message += f"- {port}/{info['service']} ({info['state']})\n"
    keyboard = [
        [InlineKeyboardButton("⚡️ فحص SQL Injection متقدم", callback_data=f"sql_{url}")],
        [InlineKeyboardButton("🛰️ فحص Nmap متقدم", callback_data=f"nmap_{url}")],
        [InlineKeyboardButton("📦 فحص شامل", callback_data=f"full_{url}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(message, parse_mode='Markdown', reply_markup=reply_markup)

async def button_handler(update: Update, context: CallbackContext) -> None:
    query = update.callback_query
    await query.answer()
    data = query.data.split('_')
    scan_type = data[0]
    url = '_'.join(data[1:])
    await query.edit_message_text(f"⏳ جاري تنفيذ فحص {VULNERABILITIES.get(scan_type, scan_type)} لموقع: {url}")
    if scan_type == 'sql':
        result = perform_sqlmap_scan(url)
    elif scan_type == 'nmap':
        result = perform_full_nmap_scan(url)
    elif scan_type == 'full':
        result = perform_sqlmap_scan(url) + "\n\n" + perform_full_nmap_scan(url)
    else:
        result = "⚠️ نوع الفحص غير معروف"
    await query.edit_message_text(result)

def perform_sqlmap_scan(url: str) -> str:
    try:
        command = ['sqlmap', '-u', f"{url}?id=1", '--batch', '--risk=2', '--level=3']
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if b"[INFO]" in stdout:
            return "🔴 تم العثور على ثغرات SQL Injection.\nراجع التفاصيل في سجل sqlmap."
        return "✅ لم يتم اكتشاف SQL Injection."
    except Exception as e:
        return f"❌ خطأ في فحص SQLMap: {str(e)}"

def perform_full_nmap_scan(url: str) -> str:
    try:
        nm = nmap.PortScanner()
        domain = urlparse(url).netloc
        nm.scan(hosts=domain, arguments='-sV -T4 -A --script=vuln')
        results = [f"📊 تقرير Nmap لموقع {domain}"]
        for host in nm.all_hosts():
            results.append(f"الخادم: {host} ({nm[host].state()})")
            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto].keys()):
                    svc = nm[host][proto][port]
                    results.append(f"🚪 منفذ {port}/{proto}: {svc['name']} - {svc['state']}")
        return "\n".join(results)
    except Exception as e:
        return f"❌ خطأ في فحص Nmap: {str(e)}"

def is_valid_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
    except ValueError:
        return False

def main() -> None:
    application = Application.builder().token("8016307177:AAFlxm08xJ2ZxQRuQzDUVOMPDoV-F-Tz1jg").build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("scan", scan_website))
    application.add_handler(CommandHandler("nmap", scan_website))
    application.add_handler(CommandHandler("sqlmap", scan_website))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, scan_website))
    application.add_handler(CallbackQueryHandler(button_handler))
    application.run_polling()

if __name__ == '__main__':
    main()

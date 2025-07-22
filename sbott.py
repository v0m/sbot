import asyncio
import logging
import subprocess
import tempfile
import os
import time
import requests
import nmap
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
        "     * فحص المنافذ والخدمات (nmap)\n"
        "     * فحص شامل لجميع الثغرات\n\n"
        "3. أوامر خاصة:\n"
        "   /nmap <رابط> - فحص nmap سريع\n"
        "   /sqlmap <رابط> - فحص sqlmap سريع\n\n"
        "⚠️ تحذير: تأكد من أن لديك إذنًا لفحص الموقع المستهدف."
    )

def is_valid_url(url: str) -> bool:
    """التحقق من صحة الرابط"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
    except ValueError:
        return False

async def scan_website(update: Update, context: CallbackContext) -> None:
    """فحص الموقع المطلوب"""
    if update.message.text.startswith('/scan'):
        if not context.args:
            await update.message.reply_text("الرجاء إدخال رابط الموقع بعد الأمر /scan")
            return
        url = context.args[0]
    else:
        url = update.message.text
    
    if not is_valid_url(url):
        await update.message.reply_text("الرابط غير صالح. الرجاء إدخال رابط صحيح يبدأ بـ http:// أو https://")
        return
    
    await update.message.reply_text(f"🔍 جاري فحص الموقع: {url}\nقد يستغرق هذا بعض الوقت...")
    
    # فحص أساسي
    results = await perform_basic_scan(url)
    # فحص nmap
    nmap_results = await perform_quick_nmap_scan(url)
    results['nmap'] = nmap_results
    
    await send_results(update, context, url, results)

async def perform_basic_scan(url: str) -> dict:
    """فحص الثغرات الأساسية"""
    results = {'url': url, 'vulnerabilities': {}}
    try:
        # فحص SQL Injection
        sql_test = f"{url}?id=1'"
        response = requests.get(sql_test, timeout=10)
        if any(error in response.text.lower() for error in ['sql', 'syntax', 'mysql', 'ora-']):
            results['vulnerabilities']['sql'] = 'Possible SQL Injection detected'
        
        # فحص XSS
        xss_test = f"{url}?search=<script>alert('xss')</script>"
        response = requests.get(xss_test, timeout=10)
        if '<script>alert(\'xss\')</script>' in response.text:
            results['vulnerabilities']['xss'] = 'Possible XSS vulnerability detected'
        
        # فحص CSRF
        response = requests.get(url, timeout=10)
        if 'csrf' not in response.text.lower() and 'token' not in response.text.lower():
            results['vulnerabilities']['csrf'] = 'No obvious CSRF protection detected'
    
    except Exception as e:
        results['error'] = f"Error scanning website: {str(e)}"
    
    return results

async def perform_quick_nmap_scan(url: str) -> dict:
    """فحص nmap سريع"""
    nm = nmap.PortScanner()
    domain = urlparse(url).netloc
    results = {'target': domain, 'ports': {}}
    
    try:
        progress_msg = await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="🌐 بدء فحص المنافذ السريع..."
        )
        
        nm.scan(hosts=domain, arguments='-F -T4')
        
        for host in nm.all_hosts():
            results['host'] = host
            results['state'] = nm[host].state()
            
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    results['ports'][port] = {
                        'state': nm[host][proto][port]['state'],
                        'service': nm[host][proto][port]['name']
                    }
        
        await progress_msg.edit_text("✅ اكتمل فحص المنافذ السريع")
    
    except Exception as e:
        results['error'] = f"Nmap scan error: {str(e)}"
        await progress_msg.edit_text(f"❌ خطأ في فحص nmap: {str(e)}")
    
    return results

async def perform_full_scan(scan_type: str, url: str, update: Update) -> str:
    """إجراء فحص متقدم مع تتبع التقدم"""
    progress_msg = await update.message.reply_text(f"🔄 بدء فحص {scan_type}...")
    
    if scan_type == 'sqlmap':
        result = await run_sqlmap(url, progress_msg)
    elif scan_type == 'nmap':
        result = await run_nmap(url, progress_msg)
    else:
        result = "⚠️ نوع الفحص غير معروف"
    
    await progress_msg.edit_text(result)
    return result

async def run_sqlmap(url: str, progress_msg) -> str:
    """تنفيذ فحص sqlmap مع تتبع التقدم"""
    with tempfile.NamedTemporaryFile(delete=False, suffix='.log') as log_file:
        log_path = log_file.name
    
    command = [
        'sqlmap',
        '-u', f"{url}?id=1",
        '--batch',
        '--output', log_path,
        '--progress',
        '--smart',
        '--threads=3',
        '--flush-session'
    ]
    
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if "progress" in line.lower():
                await progress_msg.edit_text(f"🔍 {line.strip()}")
        
        with open(log_path, 'r') as f:
            return f.read()
    
    except Exception as e:
        return f"❌ خطأ: {str(e)}"
    finally:
        if os.path.exists(log_path):
            os.remove(log_path)

async def run_nmap(url: str, progress_msg) -> str:
    """تنفيذ فحص nmap مع تتبع التقدم"""
    domain = urlparse(url).netloc
    with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as xml_file:
        xml_path = xml_file.name
    
    command = [
        'nmap',
        '-oX', xml_path,
        '--stats-every=10s',
        '-T4',
        '-A',
        domain
    ]
    
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if "Stats:" in line:
                await progress_msg.edit_text(f"🌐 {line.strip()}")
        
        with open(xml_path, 'r') as f:
            return f.read()
    
    except Exception as e:
        return f"❌ خطأ: {str(e)}"
    finally:
        if os.path.exists(xml_path):
            os.remove(xml_path)

async def send_results(update: Update, context: CallbackContext, url: str, results: dict) -> None:
    """إرسال النتائج مع أزرار الفحص المتقدم"""
    message = f"📊 نتائج فحص الموقع: {url}\n\n"
    
    if 'error' in results:
        message += f"❌ حدث خطأ: {results['error']}"
    else:
        if results.get('vulnerabilities'):
            message += "⚠️ تم اكتشاف الثغرات:\n"
            for vuln, desc in results['vulnerabilities'].items():
                message += f"🔴 {VULNERABILITIES.get(vuln, vuln)}: {desc}\n"
        else:
            message += "✅ لم يتم اكتشاف ثغرات واضحة\n"
        
        if 'nmap' in results:
            message += "\n🔍 المنافذ المفتوحة:\n"
            for port, info in results['nmap']['ports'].items():
                message += f"🚪 {port}: {info['service']} ({info['state']})\n"
    
    keyboard = [
        [InlineKeyboardButton("فحص SQL Injection متقدم", callback_data=f"sql_{url}")],
        [InlineKeyboardButton("فحص Nmap متقدم", callback_data=f"nmap_{url}")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(message, reply_markup=reply_markup)

async def button_handler(update: Update, context: CallbackContext) -> None:
    """معالجة ضغطات الأزرار"""
    query = update.callback_query
    await query.answer()
    
    data = query.data.split('_')
    scan_type = data[0]
    url = '_'.join(data[1:])
    
    result = await perform_full_scan(scan_type, url, update)
    await query.edit_message_text(result)

async def nmap_command(update: Update, context: CallbackContext) -> None:
    """فحص nmap مباشر"""
    if not context.args:
        await update.message.reply_text("الرجاء إدخال رابط بعد الأمر /nmap")
        return
    
    url = context.args[0]
    if not is_valid_url(url):
        await update.message.reply_text("الرابط غير صالح")
        return
    
    await perform_full_scan('nmap', url, update)

async def sqlmap_command(update: Update, context: CallbackContext) -> None:
    """فحص sqlmap مباشر"""
    if not context.args:
        await update.message.reply_text("الرجاء إدخال رابط بعد الأمر /sqlmap")
        return
    
    url = context.args[0]
    if not is_valid_url(url):
        await update.message.reply_text("الرابط غير صالح")
        return
    
    await perform_full_scan('sqlmap', url, update)

def main() -> None:
    """تشغيل البوت"""
    application = Application.builder().token("8016307177:AAFlxm08xJ2ZxQRuQzDUVOMPDoV-F-Tz1jg").build()
    
    # المعالجات
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("scan", scan_website))
    application.add_handler(CommandHandler("nmap", nmap_command))
    application.add_handler(CommandHandler("sqlmap", sqlmap_command))
    
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, scan_website))
    application.add_handler(CallbackQueryHandler(button_handler))
    
    application.run_polling()

if __name__ == '__main__':
    main()

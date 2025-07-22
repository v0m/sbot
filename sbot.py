import logging
import subprocess
import tempfile
import os
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
        "     * فحص المنافذ المفتوحة والخدمات (nmap)\n"
        "     * فحص شامل لجميع الثغرات\n\n"
        "3. أوامر خاصة:\n"
        "   /nmap <رابط> - فحص nmap سريع\n"
        "   /sqlmap <رابط> - فحص sqlmap سريع\n\n"
        "⚠️ تحذير: تأكد من أن لديك إذنًا لفحص الموقع المستهدف."
    )

async def scan_website(update: Update, context: CallbackContext) -> None:
    """فحص الموقع المطلوب"""
    # الحصول على الرابط من رسالة المستخدم
    if update.message.text.startswith('/scan'):
        if not context.args:
            await update.message.reply_text("الرجاء إدخال رابط الموقع بعد الأمر /scan")
            return
        url = context.args[0]
    else:
        url = update.message.text
    
    # التحقق من صحة الرابط
    if not is_valid_url(url):
        await update.message.reply_text("الرابط غير صالح. الرجاء إدخال رابط صحيح يبدأ بـ http:// أو https://")
        return
    
    # إعلام المستخدم ببدء الفحص
    await update.message.reply_text(f"🔍 جاري فحص الموقع: {url}\nقد يستغرق هذا بعض الوقت...")
    
    # فحص الثغرات الأساسية
    results = perform_basic_scan(url)
    
    # إضافة فحص nmap الأساسي
    nmap_results = perform_quick_nmap_scan(url)
    results['nmap'] = nmap_results
    
    # إرسال النتائج
    await send_results(update, context, url, results)

def perform_basic_scan(url: str) -> dict:
    """تنفيذ فحص الثغرات الأساسي"""
    results = {'url': url, 'vulnerabilities': {}}
    
    try:
        # فحص SQL Injection الأساسي
        sql_test = f"{url}?id=1'"
        response = requests.get(sql_test, timeout=10)
        if any(error in response.text.lower() for error in ['sql', 'syntax', 'mysql', 'ora-']):
            results['vulnerabilities']['sql'] = 'Possible SQL Injection detected'
        
        # فحص XSS الأساسي
        xss_test = f"{url}?search=<script>alert('xss')</script>"
        response = requests.get(xss_test, timeout=10)
        if '<script>alert(\'xss\')</script>' in response.text:
            results['vulnerabilities']['xss'] = 'Possible XSS vulnerability detected'
        
        # فحص CSRF الأساسي
        response = requests.get(url, timeout=10)
        if 'csrf' not in response.text.lower() and 'token' not in response.text.lower():
            results['vulnerabilities']['csrf'] = 'No obvious CSRF protection detected'
        
    except requests.RequestException as e:
        results['error'] = f"Error scanning website: {str(e)}"
    
    return results

def perform_quick_nmap_scan(url: str) -> dict:
    """تنفيذ فحص nmap سريع"""
    nm = nmap.PortScanner()
    domain = urlparse(url).netloc
    results = {'target': domain, 'ports': {}}
    
    try:
        nm.scan(hosts=domain, arguments='-F -T4')
        
        for host in nm.all_hosts():
            results['host'] = host
            results['state'] = nm[host].state()
            
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    results['ports'][port] = {
                        'state': nm[host][proto][port]['state'],
                        'service': nm[host][proto][port]['name'],
                        'product': nm[host][proto][port].get('product', ''),
                        'version': nm[host][proto][port].get('version', '')
                    }
                    
                    if 'http' in nm[host][proto][port]['name'] and port != 80 and port != 443:
                        results['vulnerabilities'] = results.get('vulnerabilities', {})
                        results['vulnerabilities'][f'port_{port}'] = f'Non-standard HTTP port ({port}) detected'
                    
                    if 'ftp' in nm[host][proto][port]['name'] and 'anonymous' in nm[host][proto][port].get('script', {}):
                        results['vulnerabilities'] = results.get('vulnerabilities', {})
                        results['vulnerabilities']['ftp_anon'] = 'Anonymous FTP login allowed'
    
    except Exception as e:
        results['error'] = f"Nmap scan error: {str(e)}"
    
    return results

def perform_sqlmap_scan(url: str) -> str:
    """تنفيذ فحص SQL Injection باستخدام sqlmap"""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as temp_file:
            temp_path = temp_file.name
        
        command = [
            'sqlmap',
            '-u', f"{url}?id=1",
            '--batch',
            '--risk=2',
            '--level=3',
            '--output', temp_path,
            '--flush-session',
            '--crawl=1'
        ]
        
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        
        if os.path.exists(temp_path):
            with open(temp_path, 'r') as f:
                results = json.load(f)
            
            vulnerabilities = []
            for target in results.get('targets', {}):
                for data in target.get('data', []):
                    if data.get('true', False) and data.get('payload'):
                        vulnerabilities.append(f"Parameter: {data['parameter']} - Type: {data['title']}")
            
            if vulnerabilities:
                return "🔴 تم اكتشاف ثغرات SQL Injection:\n" + "\n".join(vulnerabilities)
            else:
                return "✅ لم يتم اكتشاف ثغرات SQL Injection"
        else:
            return "⚠️ لم يتم العثور على ملف النتائج"
    
    except Exception as e:
        return f"❌ خطأ في فحص sqlmap: {str(e)}"
    
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

def perform_full_nmap_scan(url: str) -> str:
    """تنفيذ فحص nmap متقدم"""
    nm = nmap.PortScanner()
    domain = urlparse(url).netloc
    results = []
    
    try:
        nm.scan(hosts=domain, arguments='-sV -T4 -A --script=vuln')
        
        for host in nm.all_hosts():
            results.append(f"🔍 نتائج فحص {host}:")
            results.append(f"الحالة: {nm[host].state()}")
            
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                results.append(f"\nالبروتوكول: {proto}")
                
                for port in sorted(ports):
                    service = nm[host][proto][port]
                    results.append(f"\n🚪 المنفذ: {port}/{proto}")
                    results.append(f"الحالة: {service['state']}")
                    results.append(f"الخدمة: {service['name']}")
                    results.append(f"المنتج: {service.get('product', 'غير معروف')}")
                    results.append(f"الإصدار: {service.get('version', 'غير معروف')}")
                    
                    if 'script' in service:
                        for script, output in service['script'].items():
                            if 'vuln' in script.lower() or 'VULNERABLE' in output.upper():
                                results.append(f"⚠️ ثغرة محتملة ({script}):")
                                results.append(output.strip())
        
        return "\n".join(results)
    
    except Exception as e:
        return f"❌ خطأ في فحص nmap: {str(e)}"

async def send_results(update: Update, context: CallbackContext, url: str, results: dict) -> None:
    """إرسال نتائج الفحص للمستخدم"""
    message = f"📊 نتائج فحص الموقع: {url}\n\n"
    
    if 'error' in results:
        message += f"❌ حدث خطأ أثناء الفحص:\n{results['error']}"
    else:
        if results.get('vulnerabilities'):
            message += "⚠️ تم اكتشاف الثغرات المحتملة التالية:\n"
            for vuln, desc in results['vulnerabilities'].items():
                message += f"🔴 {VULNERABILITIES.get(vuln, vuln)}: {desc}\n"
            message += "\n"
        else:
            message += "✅ لم يتم اكتشاف أي ثغرات أمنية واضحة في الفحص الأساسي.\n\n"
        
        if 'nmap' in results and not results['nmap'].get('error'):
            message += "🔍 نتائج فحص المنافذ الأساسي:\n"
            message += f"الخادم: {results['nmap'].get('host', 'غير معروف')}\n"
            message += f"الحالة: {results['nmap'].get('state', 'غير معروف')}\n"
            
            if results['nmap'].get('ports'):
                message += "\nالمنافذ المفتوحة:\n"
                for port, info in results['nmap']['ports'].items():
                    message += f"- {port}: {info['service']} ({info['state']})"
                    if info.get('product'):
                        message += f" - {info['product']}"
                    if info.get('version'):
                        message += f" v{info['version']}"
                    message += "\n"
            
            if results['nmap'].get('vulnerabilities'):
                message += "\n⚠️ ثغرات محتملة:\n"
                for vuln, desc in results['nmap']['vulnerabilities'].items():
                    message += f"- {desc}\n"
        
        message += "\nملاحظة: هذه النتائج أولية وقد تحتاج إلى تأكيد بواسطة أدوات متخصصة."
    
    keyboard = [
        [InlineKeyboardButton("فحص SQL Injection متقدم (sqlmap)", callback_data=f"sql_{url}")],
        [InlineKeyboardButton("فحص المنافذ والخدمات (nmap)", callback_data=f"nmap_{url}")],
        [InlineKeyboardButton("فحص شامل لجميع الثغرات", callback_data=f"full_{url}")]
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
    
    await query.edit_message_text(text=f"🔍 جاري تنفيذ فحص {VULNERABILITIES.get(scan_type, scan_type)} متقدم للموقع: {url}...")
    
    if scan_type == 'sql':
        result = perform_sqlmap_scan(url)
    elif scan_type == 'nmap':
        result = perform_full_nmap_scan(url)
    elif scan_type == 'full':
        result = "📌 الفحص الشامل:\n"
        result += perform_sqlmap_scan(url) + "\n\n"
        result += perform_full_nmap_scan(url)
    else:
        result = "نوع الفحص غير معروف"
    
    await query.edit_message_text(text=f"نتيجة فحص {VULNERABILITIES.get(scan_type, scan_type)} لـ {url}:\n\n{result}")

async def nmap_command(update: Update, context: CallbackContext) -> None:
    """معالجة أمر nmap المباشر"""
    if not context.args:
        await update.message.reply_text("الرجاء إدخال رابط الموقع بعد الأمر /nmap")
        return
    
    url = context.args[0]
    if not is_valid_url(url):
        await update.message.reply_text("الرابط غير صالح. الرجاء إدخال رابط صحيح يبدأ بـ http:// أو https://")
        return
    
    await update.message.reply_text(f"🔍 جاري تنفيذ فحص nmap متقدم للموقع: {url}...")
    result = perform_full_nmap_scan(url)
    await update.message.reply_text(f"نتائج فحص nmap لـ {url}:\n\n{result}")

async def sqlmap_command(update: Update, context: CallbackContext) -> None:
    """معالجة أمر sqlmap المباشر"""
    if not context.args:
        await update.message.reply_text("الرجاء إدخال رابط الموقع بعد الأمر /sqlmap")
        return
    
    url = context.args[0]
    if not is_valid_url(url):
        await update.message.reply_text("الرابط غير صالح. الرجاء إدخال رابط صحيح يبدأ بـ http:// أو https://")
        return
    
    await update.message.reply_text(f"🔍 جاري تنفيذ فحص sqlmap متقدم للموقع: {url}...")
    result = perform_sqlmap_scan(url)
    await update.message.reply_text(f"نتائج فحص sqlmap لـ {url}:\n\n{result}")

def is_valid_url(url: str) -> bool:
    """التحقق من صحة الرابط"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
    except ValueError:
        return False

def main() -> None:
    """تشغيل البوت"""
    application = Application.builder().token("7869694847:AAGqNKvVPcz6NTURhifRN4hgg4Y2azH2Zs8").build()
    
    # معالجات الأوامر
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("scan", scan_website))
    application.add_handler(CommandHandler("nmap", nmap_command))
    application.add_handler(CommandHandler("sqlmap", sqlmap_command))
    
    # معالجة الرسائل النصية
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, scan_website))
    
    # معالجة ضغطات الأزرار
    application.add_handler(CallbackQueryHandler(button_handler))
    
    # بدء البوت
    application.run_polling()

if __name__ == '__main__':
    main()

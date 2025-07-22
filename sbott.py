import asyncio
import logging
import subprocess
import tempfile
import os
import time
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    CallbackContext,
    CallbackQueryHandler
)

# ... (ابق على إعدادات التسجيل والثغرات كما هي)

async def perform_sqlmap_scan(url: str, update: Update) -> str:
    """فحص SQL Injection مع تتبع التقدم"""
    progress_msg = await update.effective_message.reply_text("🔄 بدء فحص SQL Injection... 0%")
    
    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.log') as log_file:
        log_path = log_file.name
    
    command = [
        'sqlmap',
        '-u', f"{url}?id=1",
        '--batch',
        '--output', log_path,
        '--progress',  # تفعيل تقارير التقدم
        '--keep-alive',
        '--smart',  # الوضع الذكي لتسريع الفحص
        '--threads=3',  # عدد ثابت من الثreads
        '--flush-session'
    ]
    
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        last_update = time.time()
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
                
            if "progress" in line.lower():
                progress = line.split("progress")[1].strip()
                await progress_msg.edit_text(f"🔍 فحص SQL Injection... {progress}")
                
            if time.time() - last_update > 300:  # تحديث كل 5 دقائق
                await update.effective_chat.send_message(
                    chat_id=update.effective_chat.id,
                    text="⚡ فحص SQL Injection لا يزال يعمل..."
                )
                last_update = time.time()
        
        # إرسال التقرير النهائي
        with open(log_path, 'rb') as report:
            await update.effective_chat.send_document(
                document=report,
                caption="📊 تقرير SQL Injection النهائي"
            )
            
        return "✅ اكتمل فحص SQL Injection"
        
    except Exception as e:
        return f"❌ خطأ: {str(e)}"
    finally:
        if os.path.exists(log_path):
            os.remove(log_path)

async def perform_nmap_scan(target: str, update: Update) -> str:
    """فحص Nmap مع تتبع التقدم"""
    progress_msg = await update.effective_message.reply_text("🔄 بدء فحص Nmap... 0%")
    
    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.xml') as xml_file:
        xml_path = xml_file.name
    
    command = [
        'nmap',
        '-oX', xml_path,  # إخراج بتنسيق XML
        '--stats-every=10s',  # تحديث الإحصائيات كل 10 ثوان
        '-T4',  # السرعة القصوى
        '-A',  # الفحص المتقدم
        '--version-intensity=5',
        target
    ]
    
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        last_progress = 0
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
                
            if "Stats:" in line:
                progress = int(line.split("%")[0].split()[-1])
                if progress > last_progress:
                    await progress_msg.edit_text(f"🌐 فحص Nmap... {progress}%")
                    last_progress = progress
                    
            if time.time() - last_update > 300:
                await update.effective_chat.send_message(
                    chat_id=update.effective_chat.id,
                    text="⚡ فحص Nmap لا يزال يعمل..."
                )
                last_update = time.time()
        
        # تحويل XML إلى تقرير مقروء
        with open(xml_path, 'rb') as report:
            await update.effective_chat.send_document(
                document=report,
                caption="📊 تقرير Nmap النهائي"
            )
            
        return "✅ اكتمل فحص Nmap"
        
    except Exception as e:
        return f"❌ خطأ: {str(e)}"
    finally:
        if os.path.exists(xml_path):
            os.remove(xml_path)

async def button_handler(update: Update, context: CallbackContext) -> None:
    """معالجة ضغطات الأزرار مع التحديثات"""
    query = update.callback_query
    await query.answer()
    
    data = query.data.split('_')
    scan_type = data[0]
    url = '_'.join(data[1:])
    
    if scan_type == 'sql':
        await query.edit_message_text("🔍 بدء فحص SQL Injection...")
        result = await perform_sqlmap_scan(url, update)
    elif scan_type == 'nmap':
        await query.edit_message_text("🌐 بدء فحص Nmap...")
        result = await perform_nmap_scan(urlparse(url).netloc, update)
    else:
        result = "⚠️ نوع الفحص غير معروف"
    
    await query.edit_message_text(result)

# ... (ابق على باقي الدوال كما هي)

def main() -> None:
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

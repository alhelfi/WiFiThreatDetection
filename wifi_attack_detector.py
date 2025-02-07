#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import pyshark
import asyncio
from datetime import datetime
from telegram import Bot

# =========== Telegram Settings ===========
TELEGRAM_BOT_TOKEN = "your_telegram_bot_token"
TELEGRAM_CHAT_ID = "your_telegram_chat_id"

# =========== Country Flags List ===========
FLAGS = {
    "CN": "🇨🇳", "US": "🇺🇸", "RU": "🇷🇺", "DE": "🇩🇪", "IQ": "🇮🇶", "IL": "🇮🇱",
    "FR": "🇫🇷", "UK": "🇬🇧", "IN": "🇮🇳", "SA": "🇸🇦", "TR": "🇹🇷", "AE": "🇦🇪",
    "BR": "🇧🇷", "JP": "🇯🇵", "CA": "🇨🇦", "AU": "🇦🇺", "KR": "🇰🇷", "IR": "🇮🇷"
}

# =========== Function to Fetch Country Information Using ipinfo.io ===========
def get_geo_info(ip):
    """
    Sends a query to ipinfo.io to obtain information about the IP address.
    If the query is successful, it extracts the country code and adds the appropriate flag.
    In case of an error or if data is unavailable, it returns "Unknown".
    """
    try:
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            country = data.get("country", "Unknown")
            flag = FLAGS.get(country, "🏴‍☠️")
            return f"{country} {flag}"
        else:
            return "Unknown"
    except Exception as e:
        print(f"Error in ipinfo lookup for {ip}: {e}")
        return "Unknown"

# =========== Send Alert to Telegram Using Asyncio ===========
def send_alert_to_telegram(source_ip, dest_ip, reason, severity):
    src_location = get_geo_info(source_ip) if source_ip else "Unknown"
    dest_location = get_geo_info(dest_ip) if dest_ip else "Unknown"
    current_time = datetime.now().strftime("%H:%M:%S %d-%m-%Y")

    alert_message = (
        "<b>🔴 Advanced Security Alert 🔴</b>\n\n"
        "⏰ <b>Time:</b> " + current_time + "\n"
        "📡 <b>Source:</b> " + source_ip + " (" + src_location + ")\n"
        "🎯 <b>Destination:</b> " + dest_ip + " (" + dest_location + ")\n"
        "⚠️ <b>Severity Level:</b> " + severity + "\n\n"
        "🔍 <b>Possible Reasons:</b>\n"
        " - " + reason + "\n\n"
        "🛡️ <b>Immediate Recommendations:</b>\n"
        "- 🔒 Isolate the affected system immediately.\n"
        "- 🔍 Conduct a comprehensive network analysis.\n"
        "- 🚫 Block the source IP range.\n"
        "- 📱 Enable intensive monitoring."
    )

    async def _send_telegram_message():
        try:
            bot = Bot(token=TELEGRAM_BOT_TOKEN)
            await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=alert_message, parse_mode="HTML")
            print("🚨 Alert sent to Telegram")
        except Exception as e:
            print(f"❌ Failed to send alert to Telegram: {e}")

    asyncio.run(_send_telegram_message())

# =========== Load Tor Exit Nodes List from Text File ===========
def load_tor_exit_nodes(file_path="tor_exit_nodes.txt"):
    tor_nodes = set()
    try:
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    tor_nodes.add(line)
    except Exception as e:
        print(f"❌ Failed to load Tor Exit Nodes file: {e}")
    return tor_nodes

TOR_EXIT_NODES = load_tor_exit_nodes("tor_exit_nodes.txt")

# =========== Analyze Packets and Detect Attacks ===========
def analyze_packet(packet):
    try:
        if not hasattr(packet, 'ip'):
            return

        source_ip = packet.ip.src
        dest_ip = packet.ip.dst

        # Detecting Insecure Protocols (HTTP, FTP, Telnet, SMTP, POP3)
        if hasattr(packet, 'tcp'):
            dst_port = int(packet.tcp.dstport)
            insecure_ports = {
                21: "FTP",
                23: "Telnet",
                25: "SMTP",
                80: "HTTP",
                110: "POP3"
            }
            if dst_port in insecure_ports:
                proto_name = insecure_ports[dst_port]
                reason = f"👤 Usage of insecure protocol {proto_name}!"
                send_alert_to_telegram(source_ip, dest_ip, reason, "🟠 Medium")

        # Detecting Connection with APT (e.g., connecting to suspicious addresses)
        if source_ip.startswith("103.") or source_ip.startswith("45."):
            send_alert_to_telegram(source_ip, dest_ip, "⚠️ Detected connection with suspicious APT", "🔴 High")

        # Detecting Tor Usage
        if source_ip in TOR_EXIT_NODES or dest_ip in TOR_EXIT_NODES:
            send_alert_to_telegram(source_ip, dest_ip, "🚨 Suspicious connection to Tor Exit Node", "🔴 High")

    except Exception as e:
        print(f"⚠️ Error analyzing packet: {e}")

# =========== Start Network Monitoring ===========
def start_monitoring(interface="wlan0"):
    print(f"📡 Starting network monitoring on interface: {interface}")
    try:
        capture = pyshark.LiveCapture(interface=interface, display_filter="")
        for packet in capture.sniff_continuously():
            analyze_packet(packet)
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped by user.")
    except Exception as e:
        print(f"❌ Error during monitoring: {e}")

if __name__ == "__main__":
    start_monitoring("wlan0")

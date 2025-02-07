#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import scapy.all as scapy
import asyncio
from datetime import datetime
from telegram import Bot

# =========== Telegram Settings ===========
TELEGRAM_BOT_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID = "YOUR_TELEGRAM_CHAT_ID"

# =========== List of Suspicious MAC Addresses Used in Wifite ===========
SUSPICIOUS_MAC_PREFIXES = ["00:11:22", "02:", "66:55:44", "DE:AD:BE"]

# =========== Send Alert to Telegram ===========
async def send_alert_to_telegram(mac_address, reason, severity):
    """Send an alert to Telegram using asyncio"""
    current_time = datetime.now().strftime("%H:%M:%S %d-%m-%Y")
    alert_message = f"""
<b>🔴 Advanced Security Alert 🔴</b>

⏰ <b>Time:</b> {current_time}
🔗 <b>MAC Address:</b> {mac_address}

⚠️ <b>Threat Level:</b> {severity}

🔍 <b>Possible Reasons:</b>
 - {reason}

🛡️ <b>Immediate Recommendations:</b>
- 🔒 Block this device from accessing the network.
- 🚨 Change the network password immediately.
- 📊 Disable WPS to secure the network.
"""
    try:
        bot = Bot(token=TELEGRAM_BOT_TOKEN)
        await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=alert_message, parse_mode="HTML")
        print(f"🚨 Alert sent to Telegram - MAC: {mac_address}")
    except Exception as e:
        print(f"❌ Failed to send alert to Telegram: {e}")

# =========== Packet Analysis and Attack Detection ===========
async def detect_wifi_attacks(packet):
    """Analyze packets to detect Wifite activities, Deauth attacks, and WPS brute-force attempts"""
    if packet.haslayer(scapy.Dot11):
        mac_address = packet.addr2

        # Detect fake MAC addresses used in Wifite
        if mac_address and any(mac_address.startswith(prefix) for prefix in SUSPICIOUS_MAC_PREFIXES):
            await send_alert_to_telegram(mac_address, "⚠️ Suspicious MAC address detected, likely using Wifite", "🟠 Medium")

        # Detect Deauthentication Attack
        if packet.haslayer(scapy.Dot11Deauth):
            await send_alert_to_telegram(mac_address, "🚨 Deauthentication Attack Detected! Devices are being disconnected from the network", "🔴 High")

        # Detect WPS Brute Force Attack
        if packet.haslayer(scapy.Dot11Auth):
            await send_alert_to_telegram(mac_address, "🚨 WPS Brute Force Attempt Detected!", "🔴 High")

# =========== Start Network Monitoring ===========
def start_monitoring(interface="wlan0mon"):
    print("📡 Starting network monitoring (Monitor Mode required)...")
    try:
        scapy.sniff(iface=interface, prn=lambda pkt: asyncio.run(detect_wifi_attacks(pkt)), store=False)
    except Exception as e:
        print(f"❌ Error occurred while monitoring the network: {e}")

if __name__ == "__main__":
    start_monitoring("wlan0mon")  # Ensure Monitor Mode is enabled on this interface

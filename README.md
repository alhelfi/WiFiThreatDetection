# Network Security Monitoring Suite

This suite comprises two Python-based tools designed to enhance network security through real-time monitoring and alerting mechanisms.

## Table of Contents

- [Overview](https://github.com/alhelfi/WiFiThreatDetection#overview)
- [Features](https://github.com/alhelfi/WiFiThreatDetection#features)
- [Installation](https://github.com/alhelfi/WiFiThreatDetection#installation)
- [Usage](https://github.com/alhelfi/WiFiThreatDetection#usage)
  - [Wi-Fi Attack Detector](https://github.com/alhelfi/WiFiThreatDetection#wi-fi-attack-detector)
  - [Network Traffic Analyzer](https://github.com/alhelfi/WiFiThreatDetection#network-traffic-analyzer)
- [Configuration](https://github.com/alhelfi/WiFiThreatDetection#configuration)
- [Contributing](https://github.com/alhelfi/WiFiThreatDetection#contributing)
- [License](https://github.com/alhelfi/WiFiThreatDetection#license)

## Overview

The **Network Security Monitoring Suite** consists of:

1. **Wi-Fi Attack Detector**: Monitors Wi-Fi networks to detect potential attacks such as deauthentication, WPS brute force attempts, and the use of tools like Wifite.

2. **Network Traffic Analyzer**: Analyzes network traffic to identify insecure protocols, connections to suspicious IP addresses, and usage of Tor exit nodes.

Both tools provide real-time alerts via Telegram to notify administrators of potential security threats.

## Features

- **Real-Time Monitoring**: Continuously monitors network traffic for suspicious activities.

- **Comprehensive Detection**:
  - Identifies insecure protocols such as FTP, Telnet, HTTP, SMTP, and POP3.
  - Detects connections to known Advanced Persistent Threat (APT) IP addresses.
  - Alerts on communications with Tor exit nodes.
  - Monitors for Wi-Fi specific attacks including deauthentication and WPS brute force attempts.

- **Telegram Integration**: Sends detailed alerts to a specified Telegram chat, including information such as source and destination IPs, MAC addresses, severity levels, and recommended actions.

## Installation

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/alhelfi/WiFiThreatDetection
   cd WiFiThreatDetection



2.  **Set Up a Virtual Environment** (Optional but recommended):
    
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    
    ```
    
3.  **Install Dependencies**:
    
    ```bash
    pip install -r requirements.txt
    
    ```
    
4.  **Configure Telegram Bot**:
    
    -   Create a Telegram bot by talking to the [BotFather](https://t.me/BotFather) and obtain your bot token.
        
    -   Obtain your chat ID by messaging your bot and using the [getUpdates](https://api.telegram.org/bot%3CYourBOTToken%3E/getUpdates) method to find your chat ID.
        
5.  **Update Configuration**:
    
    Replace the placeholder values in both scripts with your actual `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`.
    

## Usage

### Wi-Fi Attack Detector

This tool monitors Wi-Fi traffic to detect potential attacks.

**Prerequisites**:

-   Ensure your wireless network interface supports monitor mode and is enabled.

**Running the Detector**:

```bash
sudo python3 wifi_attack_detector.py

```

**Note**: Root privileges are required to capture packets in monitor mode.

### Network Traffic Analyzer

This tool analyzes network traffic to identify insecure protocols and suspicious connections.

**Running the Analyzer**:

```bash
sudo python3 network_traffic_analyzer.py

```

**Note**: Root privileges are required to capture network packets.

## Configuration

Both tools can be configured by modifying the respective Python scripts:

-   **Telegram Settings**: Update the `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` variables with your bot's token and your chat ID.
    
-   **Network Interface**: Specify the network interface to monitor by changing the `interface` parameter in the `start_monitoring` function call.
    
-   **Suspicious MAC Addresses**: The `SUSPICIOUS_MAC_PREFIXES` list in the Wi-Fi Attack Detector script contains MAC address prefixes associated with known attack tools. Update this list as needed.
    
-   **Tor Exit Nodes**: The Network Traffic Analyzer loads a list of Tor exit nodes from a file named `tor_exit_nodes.txt`. Ensure this file is present and up-to-date.
    

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/alhelfi/WiFiThreatDetection/blob/main/LICENSE) file for details.


# Live Game IP 

Monitor UDP traffic for active game servers and copy detected IPs and ports to the clipboard. Logs results to a file for easy tracking.

---

## Features
- Detects and logs active game server IPs and ports.
- Copies detected IP:Port combinations to the clipboard.
- Categorizes "Rotating IP" vs. "Live Game Session."
- Logs results by session with timestamps.

---

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/zebbern/InstaIP.git
   cd InstaIP
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the script:
   ```bash
   python Sniff.py
   ```

---

## Usage
- Detected IPs are logged in `udp_monitor_log.txt`.
- IP:Port combinations are automatically copied to your clipboard in the format:
  ```
  udp 12.34.56.78 dport=12345
  ```

https://imgur.com/a/BxOcwLj

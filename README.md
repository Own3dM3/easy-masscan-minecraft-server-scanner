# Minecraft Server Finder/Scanner

**Screenshot:**

![Minecraft Server Scanner Screenshot](https://i.imgur.com/47LBZMC.png)

**Key Features:**
- Fast IP range scanning using `masscan`.
- Automated server detection and filtering.
- Easy setup and execution via shell script.

## Requirements
- Linux-based system (for `masscan` compatibility).
- `masscan` installed (e.g., via `sudo apt install masscan` on Ubuntu).
- Python 3.x installed.
- Necessary permissions for network scanning (run as root if required).

## Installation
1. Download the scripts: `run_masscan.sh` and `main.py`.
2. Make them executable:
   ```
   chmod +x run_masscan.sh main.py
   ```

## Usage
Execute the scanning process with the following command:

```
./run_masscan.sh
```

### Step-by-Step Guide
1. **Prepare the Environment**: Ensure all dependencies are installed.
2. **Run the Scanner**: Use the command above to start scanning IP ranges for open Minecraft servers (default port: 25565).
3. **View Results**: Output will be logged or displayed, showing discovered servers with details like IP, version, and player count.

## Example Output
```
Scanning IP range: 192.168.0.0/24
Discovered server at 192.168.0.15:25565
- Version: 1.20.1
- Players: 5/20
- MOTD: Welcome to My Minecraft Server!
```

## Troubleshooting
- **Permission Denied**: Run with `sudo` if scanning requires elevated privileges.
- **No Servers Found**: Expand IP ranges or check firewall settings.
- **Errors in Execution**: Verify Python dependencies (e.g., `pip install requests` if needed).

## Disclaimer
Use this tool responsibly and ethically. Network scanning may violate terms of service or laws in some jurisdictions. Always obtain permission before scanning networks you do not own.

For more details or support, check the original source or community forums.

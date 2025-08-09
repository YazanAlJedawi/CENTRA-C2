# CentraC2 - Command & Control Framework

"""

 ██████╗███████╗███╗  ██╗████████╗██████╗  █████╗  ██████╗    ██████╗
██╔════╝██╔════╝████╗ ██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝    ╚════██╗
██║     █████╗  ██╔██╗██║   ██║   ██████╔╝███████║██║          █████╔╝
██║     ██╔══╝  ██║╚████║   ██║   ██╔══██╗██╔══██║██║         ██╔═══╝ 
╚██████╗███████╗██║ ╚███║   ██║   ██║  ██║██║  ██║╚██████╗    ███████╗
 ╚═════╝╚══════╝╚═╝  ╚══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝    ╚══════╝

"""


A secure C2 framework with Python server and lightweight C agent.

## Features
✔ Encrypted AES-GCM communication  
✔ Multi-client management  
✔ Cross-platform agent  
✔ Minimal resource footprint  
✔ Interactive command shell  

## Quick Start

### Server Setup

# Install dependencies
pip install pycryptodome cjson

# Start server
python3 Centra_Server.py
Agent Compilation
bash
gcc -o agent Centra_Agent.c -lssl -lcrypto -lcjson
Server Commands
Command	Description
list	Show connected clients
select #	Choose client by ID
listen	Start listening for connections
help	Show command help
exit	Shutdown server
Configuration
Edit these values in both server and agent:

python
# Server (Centra_Server.py)
key = "CHANGE_THIS_SECRET" 
COMMAND_COMMUNICATION_SECRET = b'\x9a\x7f...'  # Change this

# Agent (Centra_Agent.c)
const char *INIT_KEY = "CHANGE_THIS_SECRET";
const char *SERVER_HOST = "YOUR_SERVER_IP"; 
const int SERVER_PORT = 9999;
Security Notice
❗ Always change default credentials
❗ Use in authorized environments only
❗ Not recommended for production without modifications

License
MIT License - See LICENSE file
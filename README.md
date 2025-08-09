# CentraC2 - Command & Control Framework

```


 ██████╗███████╗███╗  ██╗████████╗██████╗  █████╗  ██████╗    ██████╗
██╔════╝██╔════╝████╗ ██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝    ╚════██╗
██║     █████╗  ██╔██╗██║   ██║   ██████╔╝███████║██║          █████╔╝
██║     ██╔══╝  ██║╚████║   ██║   ██╔══██╗██╔══██║██║         ██╔═══╝ 
╚██████╗███████╗██║ ╚███║   ██║   ██║  ██║██║  ██║╚██████╗    ███████╗
 ╚═════╝╚══════╝╚═╝  ╚══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝    ╚══════╝


```

CentraC2 is a basic Command and Control (C2) framework consisting of a Python server and a C agent. It provides a straightforward way to establish reverse shell connections and execute commands on client machines.

## ✨ Features
Encrypted Communication: All command and output communication between the server and agent is encrypted using AES-256-GCM.

SHA256 Key Exchange: A simple SHA256 hash-based key exchange ensures initial connection authenticity.

Multi-client Handling: The Python server can handle multiple simultaneous client connections.

Interactive Shell: The server provides a "turtle" shell for interacting with connected clients.

Cross-Platform Agent (Linux/Unix-like): The C agent is designed for Linux/Unix-like systems.

## 🚀 Getting Started

Prerequisites:

### For the Server (Python):

Python 3.x

pycryptodome library:

```
pip install pycryptodome
```

For the Agent (C):

GCC (or any C compiler)

OpenSSL development libraries:

Debian/Ubuntu: sudo apt-get install libssl-dev

Red Hat/CentOS/Fedora: sudo yum install openssl-devel

### Installation and Setup

Clone the Repository:

```
git clone https://github.com/YazanAlJedawi/CENTRA-C2.git
cd CENTRA-C2
```
### Configure Shared Secrets:

Open Centra_Server.py and Centra_Agent.c.

Locate the key variable in Centra_Server.py and INIT_KEY in Centra_Agent.c. These must be identical.

Locate the COMMAND_COMMUNICATION_SECRET in both files. These 32-byte secrets must also be identical. You can generate a new random 32-byte (256-bit) key if you wish.

Compile the C Agent:

```
gcc Centra_Agent.c -o Centra_Agent -lssl -lcrypto -lcjson
```
### Usage

Start the Server:
```
python3 Centra_Server.py
```
The server will display a logo and an introductory message. It will then enter the turtle shell.

Make the Server Listen:
In the turtle shell, type:
```
trutle>listen
```
The server will start listening for incoming connections on 0.0.0.0:9999.

Run the C Agent (on the target machine):

```
./Centra_Agent
```
The agent will attempt to connect to the configured SERVER_HOST (default: 127.0.0.1) and SERVER_PORT (default: 9999).

Interact with Clients from the Server:

List Connected Clients:

```
list
```
This will show active connections with their respective IDs.

Select a Client:
```
select <client_ID>
```
Replace <client_ID> with the ID obtained from the list command. Your prompt will change to client_address > indicating you are now interacting with that specific client.

Execute Commands:
Once a client is selected, any command you type will be sent to and executed by the agent on that client machine. The output will be displayed in your server terminal.

you can always ask for help with the "help" command.

## ⚙️ Configuration

To get CentraC2 up and running smoothly, you'll need to adjust a few key parameters. These values define how your client and server find each other and secure their communication. Make sure these settings are perfectly aligned in both the client and server files for a successful connection!

### Network Endpoint 🌐
Server Host and Port:

In Centra_Agent.c, modify SERVER_HOST (e.g., "127.0.0.1" for local testing) and SERVER_PORT (e.g., 9999).

In Centra_Server.py, the line s.bind(("0.0.0.0", 9999)) explicitly sets the server's listening address and port. Adjust 0.0.0.0 to a specific IP if needed, and change 9999 to your desired port.

### Initial Authentication Key 🔑
The Shared Secret: This key ensures only legitimate clients can initiate a connection.

In Centra_Agent.c, update INIT_KEY (a string like "TRUSTME").

In Centra_Server.py, modify the key variable (also a string).

How it Works: These strings are securely hashed using SHA256 for the initial connection authentication, preventing unauthorized access attempts.

### Command Communication Secret (AES-GCM) 🔒
The Encryption Powerhouse: This is the heart of your secure command and control.

In Centra_Agent.c, the COMMAND_COMMUNICATION_SECRET is a 32-byte array (e.g., 0x9a, 0x7f, ...).

In Centra_Server.py, COMMAND_COMMUNICATION_SECRET is also defined as a 32-byte byte string.

Critical Match: This 32-byte array serves as the AES-256 key for encrypting and decrypting all commands sent from the server to the client, and all responses sent back. It is absolutely crucial that these 32 bytes are identical in both files!


## 🤝 Contributing
Contributions are welcome! Please feel free to open issues or submit pull requests.


Y.


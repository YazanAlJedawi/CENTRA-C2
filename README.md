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
Prerequisites
For the Server (Python):

Python 3.x

pycryptodome library:

pip install pycryptodome

For the Agent (C):

GCC (or any C compiler)

OpenSSL development libraries:

Debian/Ubuntu: sudo apt-get install libssl-dev

Red Hat/CentOS/Fedora: sudo yum install openssl-devel

Installation and Setup
Clone the Repository:

git clone https://github.com/YazanAlJedawi/CentraC2.git
cd CentraC2

Configure Shared Secrets:

Open Centra_Server.py and Centra_Agent.c.

Locate the key variable in Centra_Server.py and INIT_KEY in Centra_Agent.c. These must be identical.

Locate the COMMAND_COMMUNICATION_SECRET in both files. These 32-byte secrets must also be identical. You can generate a new random 32-byte (256-bit) key if you wish.

Compile the C Agent:

gcc Centra_Agent.c -o Centra_Agent -lssl -lcrypto -lcjson

Usage
Start the Server:

python3 Centra_Server.py

The server will display a logo and an introductory message. It will then enter the turtle shell.

Make the Server Listen:
In the turtle shell, type:

listen

The server will start listening for incoming connections on 0.0.0.0:9999.

Run the C Agent (on the target machine):

./Centra_Agent

The agent will attempt to connect to the configured SERVER_HOST (default: 127.0.0.1) and SERVER_PORT (default: 9999).

Interact with Clients from the Server:

List Connected Clients:

list

This will show active connections with their respective IDs.

Select a Client:

select <client_ID>

Replace <client_ID> with the ID obtained from the list command. Your prompt will change to client_address > indicating you are now interacting with that specific client.

Execute Commands:
Once a client is selected, any command you type will be sent to and executed by the agent on that client machine. The output will be displayed in your server terminal.

Other Server Commands:

help: Displays available server commands.

logo: Prints the CentraC2 logo.

exit: Shuts down the server.

## ⚙️ Configuration
Server Host and Port:

Centra_Agent.c: SERVER_HOST and SERVER_PORT

Centra_Server.py: The s.bind(("0.0.0.0", 9999)) line defines the listening address and port.

Authentication Key:

Centra_Agent.c: INIT_KEY

Centra_Server.py: key

These strings are hashed using SHA256 for initial connection authentication.

Communication Secret (AES-GCM):

Centra_Agent.c: COMMAND_COMMUNICATION_SECRET

Centra_Server.py: COMMAND_COMMUNICATION_SECRET

This 32-byte array is used as the AES-256 key for command and response encryption.

It is crucial that the INIT_KEY/key and COMMAND_COMMUNICATION_SECRET values are identical in both Centra_Agent.c and Centra_Server.py for successful communication.



## 🤝 Contributing
Contributions are welcome! Please feel free to open issues or submit pull requests.


Y.


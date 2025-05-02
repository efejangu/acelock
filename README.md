# Ransomware Proof of Concept (PoC)

## Project Overview
This project is a ransomware proof of concept designed to demonstrate the principles of ransomware behavior and the methods for detection and mitigation. It serves as an educational tool for understanding ransomware threats and developing protective measures.

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

## Installation

### Prerequisites
- Python 3.x
- pip (Python package installer)

### Clone the Repository
```bash
git clone https://github.com/yourusername/ransomware_pof.git
cd ransomware_pof
```
### Create and Activate Virtual Environment with venv
```
python3 -m venv venv
```
```
source vemv/bin/activate
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

## Using the Command Shell

The command shell allows you to interact with the server and connected clients. Below are the available commands:

- **Start the Server**: `start_server [-host HOST] [-port PORT] [-cert CERTFILE]`
- **Check Server Status**: `server_status`
- **List Connected Clients**: `list_clients`
- **Send File**: `send_file <local_file_path> [client_index]`
- **Execute Command on Client**: `cmd <command_and_args>`
- **Select Client**: `select_client <client_index>`
- **Encrypt Files on Client**: `encrypt_files`
- **Decrypt Files on Client**: `decrypt_files <base64_encoded_key>`
- **Disconnect Client**: `disconnect_client <client_index>`
- **Stop the Server**: `stop_server`
- **Enter Shell Mode**: `shell_mode`
- **Exit Command Shell**: `exit | quit | EOF`

These commands provide various functionalities for managing the server and interacting with clients.

### Running the Server
To start the server, navigate to the `server` directory and run:
```bash
python main.py
```

### Running the Client
To run the client application, navigate to the `client` directory and execute:
```bash
python main_client.py
```

### Generating Certificates
To generate necessary certificates, run the following shell script:
```bash
bash generate_cert.sh
```

## Project Structure
```plaintext
ransomware_pof/
│
├── server/
│   ├── main.py
│   ├── command_shell.py
│   └── server.py
│
├── client/
│   ├── main_client.py
│   └── client.py
│
├── generate_cert.sh
└── requirements.txt
```

## Contributing
Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.


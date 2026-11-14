
# BC-Recon.py - Mini Reconnaissance Tool

## About
BC-Recon is a Python 3 based mini reconnaissance
tool developed for cybersecurity learning.

It combines three practical security labs.

## Features

- Scope validation using allowlist
- Multi-threaded TCP port scanning
- Service banner grabbing
- HTTP security header auditing
- JSON report generation
- Logging of scan activity

## Technologies

- Python 3
- Socket
- ThreadPoolExecutor
- Requests
- SSL
- JSON
- Argparse
- Logging

## Project Structure

```text
BC-Recon/
├── bc-recon.py
├── README.md
├── .gitignore
└── requirements.txt
```

## Installation

```bash
git clone https://github.com/mmhking78/BC-Recon.git 
cd BC-Recon

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

## Usage

```bash
python3 bc-recon.py --help
```

Example:

```bash
python3 bc-recon.py AUTHORIZED_TARGET -p 1-1024 -o report.json
```

## Disclaimer

This tool is developed for educational purposes
and authorized security testing only.

Always obtain permission before testing any target.

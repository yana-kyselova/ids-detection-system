# MY_IDS: Intelligent Network Intrusion Detection System

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![Security](https://img.shields.io/badge/security-NIDS-red)](https://github.com/yana-kyselova/ids-detection-system)

**MY_IDS** is a modular Network Intrusion Detection System (NIDS) designed for real-time traffic monitoring and automated cyber threat identification. The project integrates advanced security simulation tools with heuristic anomaly detection algorithms.

## Key Features

- **Real-time Packet Capture:** Leveraging the Scapy library for low-level network traffic analysis.
- **Attack Simulation Suite:**
  - **ARP Spoofer:** Evaluates network vulnerability to Man-in-the-Middle (MitM) attacks.
  - **SYN Flooder:** Simulates Denial-of-Service (DoS) attacks at the transport layer.
  - **Port Scanner:** Detects reconnaissance attempts and unauthorized network mapping.
- **Detection Algorithms:**
  - **Sliding Window Methodology:** Analyzes event frequency and traffic spikes within specific timeframes.
  - **Data Normalization:** Pre-processing raw packets into structured formats for high-fidelity logging.
- **Incident Reporting:** Secure event logging in `.log` and `.jsonl` formats for digital forensics and auditing.

## Project Structure

```text
├── ids-detection-system/ # Core system directory
│   ├── detectors/        # Detection logic (Sliding Window & Rule-based engines)
│   ├── scripts/          # Attack simulation scripts (ARP, SYN, Port Scan)
│   ├── samples/          # PCAP samples and traffic captures
│   ├── capture.py        # Network sniffing and packet acquisition module
│   ├── normalize.py      # Data cleaning and feature extraction
│   └── storage.py        # Event logging and database management system
├── .gitignore            # Technical noise exclusion (e.g., __pycache__)
└── README.md             # Project documentation
# Python Network Port Scanner

## Overview
This project is a Python-based network port scanner that leverages both the `socket` library and `scapy` to identify open ports on target IP addresses. The scanner is designed to work sequentially to ensure stability and ease-of-debugging, and it uses Python's built-in logging module for detailed output.

## Features
- **Socket Scanning:** Uses standard socket connections to determine if ports are open.
- **Scapy SYN Scanning:** Sends TCP SYN packets to gather more detailed information about port states.
- **Sequential Scanning:** Processes each IP and port one at a time to avoid issues related to multi-threading.
- **Interactive Input:** Provides menus to enter a single IP, a range of IPs (CIDR or start-end format), or a list of IPs, as well as various options for port selection.
- **Logging:** Implements logging to track progress and errors, making it easier to troubleshoot and analyze results.

## Disclaimer
**IMPORTANT:** This tool is intended only for use on systems where you have explicit permission to scan. Unauthorized scanning is illegal and unethical. Use this tool responsibly and at your own risk.

## Prerequisites
- **Python 3.x**
- **Required Python packages:**
  - `scapy`  
    Install the necessary package using pip:
    ```bash
    pip install scapy
    ```
## Usage
  1. **Clone the Repository:**
        ```bash
        git clone https://github.com/your-username/your-repo.git
        cd your-repo
        ```
  2. **Run the Scanner:**
        ```bash
        python port_scanner.py
        ```
  3. **Follow the Prompts:**
      - Confirm authorization and read the legal disclaimer.
      - Choose your target specification (single IP, range, or list).
      - Choose your port specification (predefined, single, custom range, or list).
      - The scanner will first run a basic socket scan and then a detailed scan using scapy.
      - Results will be output to the console and logged for review.
  
## Testing
To verify that the system works as expected:
- **Local Testing:** Run the scanner on your own machine (e.g., using 127.0.0.1) where you know which services are active.

**Example:**
  1. Start a simple HTTP server:
        ```bash
        python -m http.server 80
        ```
  2. Ensure an SSH service is running on port 22 (or adjust accordingly).
  3. Run the scanner and confirm that the ports corresponding to the running services are reported as open.

## Configuration
- **Timeouts:** Adjust the timeout values in the source code if necessary to better suit your network conditions.
- **Logging Level:** By default, logging is set to INFO. You can change the logging level (e.g., to DEBUG) for more verbose output.


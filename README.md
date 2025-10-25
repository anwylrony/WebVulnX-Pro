# WebVulnX Pro

<p align="center">
  <strong>Advanced Automated Vulnerability Discovery for Authorized Testing</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
</p>

WebVulnX Pro is a sophisticated, Python-based vulnerability scanner that combines network reconnaissance with deep web application vulnerability analysis into a single, automated workflow. It provides a professional web interface to control scans and view results in real-time.

---

## 🔴 LEGAL AND ETHICAL DISCLAIMER 🔴

This tool is for **EDUCATIONAL and AUTHORIZED TESTING PURPOSES ONLY**. Running this tool against any website for which you do not have explicit, written permission is **ILLEGAL**. The creator of this tool assumes no liability for any misuse. Always operate within a strict legal framework and adhere to ethical guidelines.

---

## 🚀 Key Features

*   **🤖 Automated 2-Stage Scanning:** Automatically performs Nmap reconnaissance first, then launches targeted web vulnerability scans on any discovered web services.
*   **🖥️ Professional Web UI:** A modern, real-time web interface to control scans and view results as they happen.
*   **📡 Network Reconnaissance:** Uses a Python-based Nmap automator to discover open ports, identify services, and detect the operating system.
*   **🕸️ Advanced Web Crawling:** Uses Playwright to crawl modern, JavaScript-heavy web applications, just like a real user.
*   **🔍 Web Vulnerability Scanning:** Scans for a wide range of critical vulnerabilities, including SQL Injection (SQLi), Cross-Site Scripting (XSS), and Command Injection.
*   **📄 Professional Reporting:** Generates detailed PDF reports (with Nmap output as proof) and clean CSV summaries for easy integration into other systems.

---

## 📋 Prerequisites

Before you begin, ensure you have the following installed on your system:

*   **Python 3.8 or higher**
*   **Nmap:** The network scanning tool must be installed and accessible from your command line.
    *   **On Debian/Ubuntu:** `sudo apt update && sudo apt install nmap -y`
    *   **On CentOS/RHEL:** `sudo yum install nmap -y`
    *   **On macOS (with Homebrew):** `brew install nmap`
    *   **On Windows:** Download from the [official Nmap site](https://nmap.org/download.html).

---

## 📦 Installation & Setup

Follow these steps to get the project running on your local machine.

1.  **Clone or Download the Project:**
    ```bash
    git clone https://github.com/anwylrony/webvulnx-pro.git
    cd webvulnx-pro
    ```

2.  **Create and Activate a Virtual Environment (Recommended):**
    This isolates the project's dependencies from your system's Python environment.
    ```bash
    # For macOS/Linux
    python3 -m venv venv
    source venv/bin/activate

    # For Windows
    python -m venv venv
    .\venv\Scripts\activate
    ```

3.  **Install Python Dependencies:**
    The `requirements.txt` file contains all the necessary Python packages.
    ```bash
    pip install -r requirements.txt
    ```

4.  **Install Playwright Browser Binaries:**
    This is a crucial step to enable the headless browser functionality for web crawling.
    ```bash
    playwright install
    ```

---

## 💡 How to Use

1.  **Run the Web Application:**
    Start the Flask server from your terminal.
    ```bash
    python app.py
    ```

2.  **Access the Web Interface:**
    Open your web browser and navigate to:
    **http://127.0.0.1:5000**

3.  **Start a Scan:**
    *   Enter the target IP address or hostname in the "Target Host / URL" field.
    *   Adjust the "Web Crawl Depth" if needed.
    *   Click the **"Start Scan"** button.

4.  **Monitor Progress:**
    Watch the "Live Scan Log" for real-time updates as the tool performs network reconnaissance and then web vulnerability scanning.

5.  **Download Reports:**
    Once the scan is complete, the "Download Report" buttons will become enabled. You can download the findings as a professional PDF or a CSV file.

---

## 📊 Reporting

The tool generates two types of reports:

*   **PDF Report:** A comprehensive document containing:
    *   **Stage 1: Network Reconnaissance Findings**, including open ports, detected OS, and raw Nmap script output as verifiable proof.
    *   **Stage 2: Web Application Vulnerabilities**, with a detailed table of any discovered flaws, including the URL, parameter, and payload used.
*   **CSV Report:** A lightweight, comma-separated file containing only the list of discovered web vulnerabilities, ideal for data analysis.

---

## 📁 Project Structure

```
webvulnx-pro/
├── app.py                 # Main Flask Web Application
├── scanner.py             # Core Web Vulnerability Scanning Logic
├── nmapAutomator.py       # Python module for Network Reconnaissance
├── requirements.txt       # Python Dependencies
├── templates/
│   └── index.html         # The Professional Web UI
├── README.md              # This file
└── LICENSE                # Project License
```

---

## 🛠️ Technology Stack

*   **Backend:** Python, Flask, Flask-SocketIO
*   **Frontend:** HTML5, CSS3 (Tailwind CSS), JavaScript
*   **Scanning Engines:** Nmap, Playwright, Requests
*   **Reporting:** ReportLab (for PDF generation)

---

## 🤝 Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1.  Fork the Project
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the Branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

## ⚠️ Acknowledgement

Remember, with great power comes great responsibility. Use this tool wisely and ethically. Happy hunting (on authorized targets only)!

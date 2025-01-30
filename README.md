# Snifd

Snifd is a basic network intrusion detection system (IDS) designed for educational purposes and simple monitoring. It uses Scapy for packet sniffing and a Flask-based web interface for administration and visualization. Snifd is intended to detect potentially malicious activities, such as excessive failed login attempts and ping sweeps, by monitoring network traffic on a specified interface.

## What is Snifd?

Snifd is designed to empower you to:

-   👁️ **Monitor Network Activity:** Observe real-time network traffic, with a focus on ports that are most often targets for intrusion.
-   🚨 **Detect Suspicious Behavior:** Identify unusual login attempts or potentially malicious ping floods that may signal an intrusion.
-   🛡️ **Block Attacking IPs:** Instantly block suspicious IP addresses using `iptables` to mitigate threats as they occur.
-   📜 **Track Alert History:** Review past incidents to understand patterns of attacks and fine-tune your defenses.
-   🛠️ **Customize Your Defenses:** Easily configure monitored ports, threshold values, and other settings to suit your environment.

---

### Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Alert Monitoring](#alert-monitoring)
  - [Configuration](#configuration)
  - [IP Blocking/Unblocking](#ip-blockingunblocking)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Contributing](#contributing)
- [License](#license)

---

### Features

-   **Real-Time Alert Monitoring:** Displays a table of active alerts, with details on source IPs, failed attempt counts, and last seen time.
-   **Configurable Ports:** Allows you to specify which ports should be monitored for login attempts.
-   **Filter & Sort:** Filter alerts based on source IP and sort by IP, count, or last seen time.
-   **Real-Time Activity Chart:** Shows a visual representation of failed logins and ping activities over the past 24 hours.
-   **IP Blocking/Unblocking:** Allows you to block attacking IPs using `iptables` and to unblock these IPs.
-   **Alert History:** Maintains a history of past alerts with timestamps, IPs, and messages.
-   **Configuration Settings:** Allows modification of threshold values, monitored interfaces, and ports directly from the web interface.
-   **Notification System:** Provides email and Slack notifications when IPs are blocked due to suspicious activity.
-   **Database Logging:** Logs all alert events and blocked IP events to a database (SQLite by default).
-   **Input Sanitization:** Uses `shlex.quote` to prevent command injection vulnerabilities.

---

### Installation

To run Snifd locally, follow these steps:

#### 1. Clone the Repository

```bash
git clone https://github.com/CodeByKalvin/Snifd.git
cd Snifd
```

#### 2. Install Dependencies

Make sure you have **Python 3** installed. Install the required dependencies using `pip`:

```bash
pip install -r requirements.txt
```

The `requirements.txt` file should include the following:

```txt
flask
scapy
requests
sqlalchemy
python-dotenv
```

#### 3. Ensure `iptables` is installed (Linux systems):

```bash
sudo apt install iptables  # For Debian/Ubuntu
# or
sudo yum install iptables # For CentOS/RHEL
```
---

### Usage

Once installed, you can run the application from the command line using:

```bash
sudo python snifd.py
```

This will launch the web application, which you can access from your browser.

---

#### Alert Monitoring

1.  **Access the Dashboard:** Open your web browser and navigate to `http://<your-server-ip>:5000` (replace `<your-server-ip>` with your server's IP address).
2.  **Real-Time Alerts:** The main page will display a table of active alerts, including IP addresses, their activity count, and the last seen time.
3.  **Visual Activity:** A chart provides a graphical representation of hourly activity (login attempts and pings).
4.  **Alert History:** The Alert History table allows you to see previously detected alerts.

---

#### Configuration

1.  **Access Settings:** Use the configuration form on the main page to adjust settings.
2.  **Configure:** Customize the following settings to suit your environment:
    -   **Threshold:** The number of failed attempts from an IP to trigger a block.
    -   **Time Window:** The time period in seconds for which an IP's activity is tracked.
    -   **Interface:** The network interface to monitor (e.g., `eth0`).
    -   **Ports:** A comma separated list of ports to monitor for login attempts (e.g., `22,23`).
3.  **Update:** Click "Update Config" to save your changes.

---

#### IP Blocking/Unblocking

1. **Blocking:** When Snifd detects suspicious activity (based on the configured thresholds), it will block the IP automatically.
2. **Unblocking:** Use the unblock button in the "Blocked IPs" table to remove any IP address from the blocklist.

---

### Project Structure

```
snifd/
│
├── snifd.py                # Main Python script for running the web application
├── static/
│   └── style.css           # CSS file for styling the application
├── templates/
│   └── index.html          # HTML template for the main page
├── snifd_config.json       # Configuration file (created on first run)
├── snifd_blocked_ips.json  # Blocked IPs file
├── requirements.txt        # List of dependencies
└── ids.log                 # Log file for the IDS events
```

---

### Requirements

-   **Python 3** or higher
-   **Pip** to install dependencies
-   Required Python libraries (in `requirements.txt`):
    -   `flask`: To create the web interface.
    -   `scapy`: To sniff network packets.
    -   `requests`: To send Slack messages and fetch data from remote APIs.
    -   `sqlalchemy`: For logging events and blocked IPs to a database.
    -   `python-dotenv`: To manage configuration settings.
    -   `shlex` for input sanitation

To install the dependencies:

```bash
pip install -r requirements.txt
```

---

### Contributing

If you want to contribute to this project, feel free to submit a pull request or create an issue with a detailed description of the feature or bug you're addressing.

#### Steps to Contribute:

1.  Fork the repository.
2.  Create a new branch for your feature (`git checkout -b feature-name`).
3.  Make your changes.
4.  Test your changes.
5.  Commit your changes (`git commit -m 'Add some feature'`).
6.  Push to your branch (`git push origin feature-name`).
7.  Create a pull request.

---

### License

This project is open-source and available under the [MIT License](LICENSE).

---
### Authors
- **CodeByKalvin** - *Initial work* - [GitHub Profile](https://github.com/codebykalvin)

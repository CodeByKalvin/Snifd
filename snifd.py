from flask import Flask, render_template, jsonify, request
import time
from collections import defaultdict
from threading import Thread
import logging
from scapy.all import IP, TCP, Raw, sniff, ICMP
import json
import os
import datetime
from copy import deepcopy
import subprocess
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Sequence
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import shlex

# CodeByKalvin
print("CodeByKalvin")

# --- Setup ---
logging.basicConfig(filename='snifd.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DEFAULT_THRESHOLD = 3
DEFAULT_INTERFACE = 'eth0'
DEFAULT_TIME_WINDOW = 60
DEFAULT_PORTS = [22, 23]
CONFIG_FILE = 'snifd_config.json'
BLOCKED_IPS_FILE = 'snifd_blocked_ips.json'
MAX_HISTORY_SIZE = 100

DATABASE_URL = 'sqlite:///snifd.db'
Base = declarative_base()

EMAIL_HOST = "smtp.example.com" # Replace with actual mail host.
EMAIL_PORT = 587
EMAIL_USERNAME = "user@example.com" # Replace with actual mail host user
EMAIL_PASSWORD = "password" # Replace with actual password for mail user
EMAIL_FROM = "user@example.com"
EMAIL_TO = ["admin@example.com"]

SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX" # Replace with real slack url

class AlertLog(Base):
    __tablename__ = 'alert_logs'
    id = Column(Integer, Sequence('alert_log_id_seq'), primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.now)
    source_ip = Column(String)
    message = Column(String)

class BlockedIPLog(Base):
    __tablename__ = 'blocked_ip_logs'
    id = Column(Integer, Sequence('blocked_ip_log_id_seq'), primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.now)
    ip_address = Column(String)

alerts = defaultdict(int)
last_alert_time = defaultdict(float)
history = []

config = {}
def load_config():
    global config
    try: config = json.load(open(CONFIG_FILE, 'r'))
    except (FileNotFoundError, json.JSONDecodeError):
        config = {
            'threshold': DEFAULT_THRESHOLD,
            'interface': DEFAULT_INTERFACE,
            'time_window': DEFAULT_TIME_WINDOW,
            'ports': DEFAULT_PORTS
        }
    return config

config = load_config()

blocked_ips = []
def load_blocked_ips():
    global blocked_ips
    try: blocked_ips = json.load(open(BLOCKED_IPS_FILE, 'r'))
    except (FileNotFoundError, json.JSONDecodeError): blocked_ips = []
    return blocked_ips
blocked_ips = load_blocked_ips()

def save_config():
    global config
    json.dump(config, open(CONFIG_FILE, 'w'), indent=4)

def save_blocked_ips():
    global blocked_ips
    json.dump(blocked_ips, open(BLOCKED_IPS_FILE, 'w'), indent=4)

engine = create_engine(DATABASE_URL)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
db_session = Session()

app = Flask(__name__, static_folder='static')

# --- IDS Logic ---

def record_alert(source_ip, message):
    global history
    timestamp = datetime.datetime.now()
    history.insert(0, {'timestamp': timestamp.isoformat(), 'source_ip': source_ip, 'message': message})
    history = history[:MAX_HISTORY_SIZE]
    log_db_event(source_ip, message)

def log_db_event(source_ip, message):
    try:
        new_log = AlertLog(source_ip=source_ip, message=message)
        db_session.add(new_log)
        db_session.commit()
    except Exception as e:
        logging.error(f"DB error: {e}")
        db_session.rollback()

def process_packet(packet):
    global alerts, last_alert_time
    if packet.haslayer(TCP):
        if packet[TCP].dport in config.get('ports', DEFAULT_PORTS):
           if packet.haslayer(Raw):
              payload = str(packet[Raw])
              if 'Failed password' in payload:
                 src_ip = packet[IP].src
                 alerts[src_ip] += 1
                 last_alert_time[src_ip] = time.time()
                 logging.info(f'Failed login from {src_ip}, count: {alerts[src_ip]}')
                 if alerts[src_ip] > config.get('threshold', DEFAULT_THRESHOLD):
                     logging.warning(f'Intrusion from {src_ip}!')
                     record_alert(src_ip, f'Intrusion from {src_ip}!')
    elif packet.haslayer(ICMP):
        src_ip = packet[IP].src
        logging.info(f'Ping from {src_ip}')
        record_alert(src_ip, f"Ping from {src_ip}")
        alerts[src_ip] += 1
        last_alert_time[src_ip] = time.time()

def clear_old_alerts():
    global alerts, last_alert_time
    now = time.time()
    to_delete = [ip for ip, last_time in last_alert_time.items()
                if (now - last_time) > config.get('time_window', DEFAULT_TIME_WINDOW)]
    for ip in to_delete:
        del alerts[ip]
        del last_alert_time[ip]

def start_sniffer():
    print("Sniffer Thread Running")
    try:
        while True:
            sniff(iface=config.get('interface', DEFAULT_INTERFACE), prn=process_packet, store=False, timeout=5)
            clear_old_alerts()
            time.sleep(1)
    except Exception as e:
        print(f"Sniffer error: {e}")

sniffer_thread = Thread(target=start_sniffer)
sniffer_thread.daemon = True
sniffer_thread.start()

def block_ip(ip_address):
   try:
        sanitized_ip = shlex.quote(ip_address) # Sanitize IP
        subprocess.run(['iptables', '-A', 'INPUT', '-s', sanitized_ip, '-j', 'DROP'], check=True, capture_output=True)
        subprocess.run(['iptables', '-A', 'OUTPUT', '-d', sanitized_ip, '-j', 'DROP'], check=True, capture_output=True)
        return True, "IP Blocked Successfully"
   except subprocess.CalledProcessError as e:
        logging.error(f'Iptables error: {e}')
        return False, f"Iptables Error: {e}"

def unblock_ip(ip_address):
    try:
        sanitized_ip = shlex.quote(ip_address) # Sanitize IP
        subprocess.run(['iptables', '-D', 'INPUT', '-s', sanitized_ip, '-j', 'DROP'], check=True, capture_output=True)
        subprocess.run(['iptables', '-D', 'OUTPUT', '-d', sanitized_ip, '-j', 'DROP'], check=True, capture_output=True)
        return True, "IP Unblocked Successfully"
    except subprocess.CalledProcessError as e:
        logging.error(f"Iptables error unblocking {ip_address}: {e}")
        return False, f"Iptables error unblocking {ip_address}: {e}"

def send_email(ip_address):
    try:
        message = MIMEMultipart()
        message['From'] = EMAIL_FROM
        message['To'] = ', '.join(EMAIL_TO)
        message['Subject'] = f'Blocked IP Alert: {ip_address}'
        body = f"IP address {ip_address} blocked due to excessive activity."
        message.attach(MIMEText(body, 'plain'))
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
        server.send_message(message)
        server.quit()
    except Exception as e:
        logging.error(f"Email error: {e}")
        return False, str(e)
    return True, "Email Sent"

def send_slack(ip_address):
    try:
        message = { "text": f"IP Address {ip_address} blocked due to excessive activity."}
        headers = { "Content-type" : "application/json"}
        response = requests.post(SLACK_WEBHOOK_URL, json = message, headers=headers)
        response.raise_for_status()
    except Exception as e:
        logging.error(f"Slack error: {e}")
        return False, str(e)
    return True, "Slack Sent"
# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html', config=config)

@app.route('/get_alerts')
def get_alerts():
    alerts_list = [{'ip': ip, 'count': count, 'last_seen': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_alert_time[ip]))}
                   for ip, count in alerts.items()]

    filter_ip = request.args.get('filter_ip')
    if filter_ip:
        alerts_list = [alert for alert in alerts_list if filter_ip in alert['ip']]

    sort_by = request.args.get('sort_by', 'last_seen')
    sort_order = request.args.get('sort_order', 'asc')
    if sort_by and sort_order:
         alerts_list.sort(key=lambda x: x[sort_by], reverse=(sort_order == 'desc'))

    return jsonify(alerts_list)

@app.route('/get_chart_data')
def get_chart_data():
    hourly_counts = defaultdict(int)
    now = datetime.datetime.now()
    for ip, last_time in last_alert_time.items():
        time_diff = now - datetime.datetime.fromtimestamp(last_time)
        if time_diff.days < 1:
            hour_diff = (now - datetime.datetime.fromtimestamp(last_time)).seconds//3600
            hourly_counts[hour_diff] += alerts[ip]

    labels = [f"{now.hour - i}" for i in range(24)][::-1]
    data = [hourly_counts[hour] for hour in range(24)][::-1]
    chart_data = {
      "labels": labels,
      "datasets": [
        {
          "label": "Activity",
          "data": data,
          "borderColor": "blue",
          "fill": False
        }
      ]
    }
    return jsonify(chart_data)

@app.route('/get_alert_history')
def get_alert_history():
    global history
    return jsonify(history)

@app.route('/block_ip', methods=['POST'])
def handle_block_ip():
    global blocked_ips
    ip_address = request.form['ip']
    logging.info(f"Blocking IP: {ip_address}")
    success, message = block_ip(ip_address)
    if not success:
        return jsonify({'message': message}), 500
    blocked_ips.append({"ip":ip_address, "time": datetime.datetime.now().isoformat()})
    save_blocked_ips()
    try:
         new_log = BlockedIPLog(ip_address=ip_address)
         db_session.add(new_log)
         db_session.commit()
    except Exception as e:
         logging.error(f"DB error: {e}")
         db_session.rollback()

    email_success, email_message = send_email(ip_address)
    slack_success, slack_message = send_slack(ip_address)

    logging.info(f"Notifications for {ip_address} : Email: {email_success}, {email_message}, Slack: {slack_success} {slack_message}")
    return jsonify({'message': f'IP {ip_address} blocked, email: {email_success}, slack: {slack_success}'})

@app.route('/unblock_ip', methods=['POST'])
def handle_unblock_ip():
    ip_address = request.form['ip']
    logging.info(f"Unblocking IP: {ip_address}")
    success, message = unblock_ip(ip_address)
    if success:
      global blocked_ips
      blocked_ips = [blocked_ip for blocked_ip in blocked_ips if blocked_ip["ip"] != ip_address]
      save_blocked_ips()
      return jsonify({'message': f'IP {ip_address} unblocked'}), 200
    else:
      return jsonify({'message': message}), 500

@app.route('/get_blocked_ips')
def get_blocked_ips():
    return jsonify(blocked_ips)

@app.route('/update_config', methods=['POST'])
def handle_update_config():
    global config
    try:
      new_config = request.form.to_dict()
      config = deepcopy(load_config())
      for k, v in new_config.items():
            if k == "threshold": config["threshold"] = int(v)
            if k == "time_window":  config["time_window"] = int(v)
            if k == "interface": config["interface"] = v
            if k == "ports":
                try:
                    config["ports"] = [int(port) for port in v.split(",")]
                except:
                     pass
      save_config()
      return jsonify({'message': 'Config updated'})
    except Exception as e:
      logging.error(f"Config error: {e}")
      return jsonify({'message': f'Config update failed due to {e}'}), 500
if __name__ == '__main__':
   app.run(debug=True, host='0.0.0.0')

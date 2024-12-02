
#Read and Parse the Log Files
with open("system_logs.log", 'r') as file:
    logs = file.readlines()

#Filter for Relevant Data
suspicious_logs = [log for log in logs if 'failure' in log.lower() or 'abnormally' in log.lower()]

with open('summary_report.txt', 'w') as f:
    f.write(f"Total suspicious logs found: {len(suspicious_logs)}\n")
    for log in suspicious_logs:
        f.write(log + '\n')

# Install the psutil Library in terminal (Copy/paste into terminal)
# pip install psutil

# Collect System Metrics
import psutil

# Get CPU usage
cpu_usage = psutil.cpu_percent(interval=1)
print(f"CPU Usage: {cpu_usage}%")

# Get Memory usage
memory_info = psutil.virtual_memory()
print(f"Memory Usage: {memory_info.percent}%")

#Log the Performance Data
with open('performance_log.txt', 'a') as f:
    f.write(f"CPU: {cpu_usage}%, Memory: {memory_info.percent}%\n")

#Generate Alerts for High Usage
if cpu_usage > 90:
    print("ALERT: High CPU usage detected!")

#Alert Generation
#Send Alerts via Email

import smtplib
from email.message import EmailMessage

def send_alert(subject, body):
    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = 'your_email@gmail.com'
    msg['To'] = 'recipient_email@gmail.com'

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login('your_email@gmail.com', 'your_password')
        smtp.send_message(msg)

# Example: send an alert when CPU usage is high
if cpu_usage > 90:
    send_alert('High CPU Usage Alert', f'CPU usage is {cpu_usage}%')

#Log Alerts

# Automating Routine Security Checks


# Install (In Terminal) and use nmap for Vulnerability Scanning
# pip install python-nmap
# Use Homebrew to install nmap on macOS
# sudo apt install nmap

import subprocess

def run_nmap(target):
    result = subprocess.run(['nmap', '-sV', target], capture_output=True, text=True)
    print(result.stdout)

run_nmap('127.0.0.1')  # Scan localhost

# Install the scapy Library in terminal (Copy/paste into terminal)
# pip install scapy

from scapy.all import sniff
from scapy.layers.inet import TCP, IP

def monitor_packets(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        print(f"Source IP: {pkt[IP].src}, Destination IP: {pkt[IP].dst}")

sniff(prn=monitor_packets, count=10)  # Capture 10 packets



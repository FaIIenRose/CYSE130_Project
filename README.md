# Financial Firm Cybersecurity System
## Project Overview
This project aims to enhance the cybersecurity posture of a financial firm by implementing a system that monitors system performance, tracks suspicious activities through log analysis, and provides basic employee training to recognize potential threats. The system automatically parses log files, detects anomalies such as multiple failed login attempts or high system usage, and sends alerts via email to administrators. The project also includes basic encryption practices to protect confidential information and aims to raise employee awareness about common cyber threats, such as phishing.

## Goals
**Log Monitoring:** Parse and analyze system logs to identify suspicious activity.    
**Encryption:** Implement basic encryption techniques to safeguard sensitive data.    
**Employee Training:** Educate employees about security threats and how to recognize them.    
**Real-time Alerts:** Automatically generate alerts (e.g., email notifications) for system administrators upon detecting suspicious activity.    

## Installation
To set up this project locally, follow these steps:

### Prerequisites:  
1. Python 3.x or higher    
2. Git (for version control and collaboration)       
4. Pip (for Python package installation)

> Additional Setup for UML Diagrams:    
To visualize the system architecture and processes, you can use LucidChart (or any UML diagram tool) to create and view the use case and activity diagrams. The diagrams are included in the project directory, diagrams/, as .png files.

### Steps to Install & Setup
1. Clone the Repository    
```
git clone https://github.com/FaIIenRose/CYSE130_Project.git    
cd financial-cybersecurity-project
```

2. Install necessary Python packages    
Create a virtual environment and install required dependencies.    
```
pip install psutil python-nmap scapy
```

3. Create Log Files    
Ensure that the `system_logs.log` file is present in the project directory for the system to parse. If it’s not available, you can generate a sample log file.

## Usage   
Once you have configured everything, you can run the sscript by clicking run in your editor or executing the command below:
```
python automation.py
```
When ran, the system will monitor CPU and memory usage, parse logs for suspicious activities (like multiple failed logins or abnormal behavior), and generate performance logs and a summary report.

### System Monitoring
* Monitor CPU and memory usage.
* Write performance data to `performance_log.txt`.
* Send alerts for high CPU usage.

### Log Parsing and Report Generation
The system will scan `system_logs.log` for suspicious activities (e.g., failed logins) and generate a `summary_report.txt` file with the findings.

## Security Tools
**Vulnerability Scanning:** The script uses nmap to run vulnerability scans on the target machine. Replace the target IP address in the run_nmap() function to scan a different machine.

**Network Monitoring:** Scapy is used to sniff TCP packets on the network. The captured data includes source and destination IPs for each packet.

## Team Members
This project was completed by the following team members:

**Ryan Dunn:** Model Architect     
**Ethan Motter:** Model Achitect     
**Bibek Kharel:** Python Developer       
**Carlos Navarro-Montanez:** Python Developer    
**David Wong:** Data Analyst    
**Jessica Yan:** Project Manager    

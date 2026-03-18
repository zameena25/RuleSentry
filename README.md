# RuleSentry – Smart Firewall and Traffic Alert Simulator

RuleSentry is a beginner-level cybersecurity project that I built using Python to understand how firewall rules and traffic monitoring work in a real environment.

The main idea behind this project was to simulate how a firewall makes decisions based on rules and how network traffic can be analyzed. Instead of just allowing or blocking traffic, I tried to make it a bit more realistic by also identifying suspicious activity and marking it as MONITOR with a risk level.


**Project Overview**

In this project, the system allows users to create their own firewall rules and test different types of network traffic. Based on the rules and some basic logic, the system decides whether the traffic should be:

ALLOW – normal traffic
MONITOR – suspicious traffic
BLOCK – restricted or dangerous traffic

It also assigns a risk level (Low, Medium, High) and keeps a record of all traffic events.


**Features**

Add custom firewall rules (direction, protocol, port, action)
View all configured rules
Analyze traffic using user input
Decision output: ALLOW / MONITOR / BLOCK
Risk level classification
Detection of sensitive ports like SSH, RDP, SMB, FTP, and Telnet
Event/alert history
Generate a report file with results


**Example Scenarios**

Here are a few cases I tested:

Blocking inbound RDP traffic (port 3389) → BLOCK
Allowing outbound HTTPS traffic (port 443) → ALLOW
Inbound SSH traffic (port 22) without a rule → MONITOR


**Technologies Used**

Python
Command Line Interface


**What I Learned**

Through this project, I learned:
how firewall rules are created and used
how traffic can be analyzed based on different conditions
how sensitive ports can indicate potential risks
how to build a Python program using functions, lists, and dictionaries
how event logging and simple risk classification works in security systems


**Report**

The full project report is included in this repository.


**Final Thoughts**

This project helped me understand the basics of firewall logic and traffic analysis in a practical way. It also improved my Python skills and gave me a better idea of how security systems make decisions.

This is one of the projects I built as part of improving my hands-on experience in cybersecurity.

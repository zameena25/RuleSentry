"""RuleSentry - Smart Firewall & Traffic Alert Simulator
A beginner friendly cybersecurity prohject for learning firewall rules  and traffic analysis."""

import json
import os
from datetime import datetime
from typing import List, Dict, Optional

#snsitive ports and their risk levels
SENSITIVE_PORTS = {
    21: "FTP (High riisk - unencrypted credentials)",
    22: "SSH (Medium risk - remote access)",
    23: "Telnet (High risk - unencrypted)",
    25: "SMTP (Medium risk - email service)",
    445: "SMB (High risk - file sharing)",
    3389: "RDP (High risk - remote desktop)",
}

class FirewallRule: 
    """Representing a single firewall rule."""

    def __init__(self, name: str, directions: str, protocol: str, port: int, action: str):
        self.name = name
        self.direction = directions
        self.protocol = protocol.upper()
        self.port = port
        self.action = action.upper ()
    
    def __str__ (self) -> str:
        return f"[{self.name}] {self.direction} {self.protocol}:{self.port} -> {self.action}"
    
    def matches (self, direction: str, protocol: str, port: int) -> bool:
        """Check if the rule matches the given traffic."""
        return (self.direction == direction.upper() or self.direction == "ANY") and \
                (self.protocol == protocol.upper() or self.protocol == "ANY")and \
                (self.port == port or self.port == 0)

class TrafficEvent: 
    """Representing analyzed network traffic."""

    def __init__(self, source_ip: str, direction: str, protocol: str, dest_port: int, verdict: str, risk_level: str, reason: str):
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.source_ip = source_ip
        self.direction = direction.upper()
        self.protocol = protocol.upper()
        self.dest_port = dest_port
        self.verdict = verdict.upper()
        self.risk_level = risk_level.upper()
        self.reason = reason
    
    def __str__(self) -> str:
        return f"[{self.timestamp}] {self.source_ip} {self.direction} {self.protocol}:{self.dest_port} " \
                f"-> {self.verdict} | {self.risk_level} | {self.reason}"

class RuleSentry: 
    """Main RuleSentry firewall simulator."""
    
    def __init__ (self):
        self.rules: List[FirewallRule] = []
        self.events: List[TrafficEvent] = []
        self.data_file = "rulesentry_data.json"
        self.load_data()
    
    def load_data(self):
        """Load rules and events from file."""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r') as f:
                    data = json.load(f)
                    self.rules = [FirewallRule(**rule) for rule in data.get('rules', [])]
                    self.events = [TrafficEvent(**event) for event in data.get('events', [])]
                print("Data loaded sucessfully.")
            except:
                print("Could not load data, starting fresh")
    
    def save_data(self):
        """Save rules and events to file."""
        data = {
            'rules': [rule.__dict__ for rule in self.rules],
            'events': [event.__dict__ for event in self.events]
        }
        with open(self.data_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def add_rules(self):
        """Add a new firewall rule."""
        print("\n" + "="*50)
        print("Add a New Firewall Rule")
        print("="*50)

        name= input("Rule name: ").strip()
        if not name: 
            print("Rule name cannot be empty!")
            return
        
        direction = input ("Direction (inbound/outbound/any) [inbound]: ").strip().lower() or "inbound"
        protocol = input ("Protocol (TCP/UDP/any) [TCP]: ").strip().upper() or "TCP"
        port_input = input ("Port (0 for any): ").strip()
        port = int(port_input) if port_input.isdigit()else 0
        action = input("Action (allow/block): ").strip().lower()

        if direction not in ['inbound', 'outbound', 'any']:
            direction = 'inbound'
        if protocol not in ['TCP', 'UDP', 'ANY']:
            protocol = 'TCP'
        if action not in ['allow', 'block']:
            print ("Invalid action! Using 'allow'")
            action = 'allow'
        
        rule = FirewallRule(name, direction, protocol, port, action)
        self.rules.append(rule)
        print (f"Rule '{name}' added successfully!")
    
    def view_rules(self):
        """Display all firewall rules."""
        print("\n" + "="*60)
        print("Current Firewall Rules")
        print("="*60)
        if not self.rules:
            print("No rules configured yet.")
            return
        
        for i, rule in enumerate(self.rules, 1):
            print(f"{i:2d}. {rule}")
        print("-" * 60)
    
    def analyze_traffic(self):
        """Analyze network traffic against rules"""
        print("\n" + "="*50)

        source_ip = input ("Source IP: ").strip() or "192.168.1.100"
        direction = input ("Direction (inbound/outbound): ").strip().lower() or "inbound"
        protocol = input ("Protocol (TCP/UDP): ").strip().upper() or "TCP"
        dest_port = int(input("Destination Port: ").strip() or "80")

        block_match = False
        allow_match = False 

        for rule in self.rules:
            if rule.matches(direction, protocol, dest_port):
                if rule.action == "BLOCK":
                    block_match = True
                elif rule.action == "ALLOW": 
                    allow_match = True
        
        #Decision logic 
        if block_match:
            verdict, risk, reason = "BLOCK", "HIGH", "Blocked by firewall ruke"
        elif allow_match:
            verdict, risk, reason = "ALLOW", "LOW", "Allowed by firewall rule"
        elif direction == "inbound" and dest_port in SENSITIVE_PORTS:
            port_info = SENSITIVE_PORTS[dest_port]
            verdict, risk, reason = "MONITOR", "MEDIUM", f"Sensitive port detected: {port_info}"
        else:
            verdict, risk, reason = "ALLOW", "LOW", "No matching rules - default allow"
        
        #creating and storing the event
        event = TrafficEvent(source_ip, direction, protocol, dest_port, verdict, risk, reason)
        self.events.append(event)

        #displaying result
        print ("\n" + "█" *70)
        print(f"Analysis Result")
        print("█"*70)
        print(f"Source: {source_ip}")
        print(f"Direction: {direction.upper()}")
        print(f"Protocol: {protocol}")
        print(f"Dest port: {dest_port}")
        print(f"Verdict: {verdict}")
        print(f"Risk: {risk}")
        print(f"Reason: {reason}")
        print("█"*70)
    
    def view_alert_history(self):
        """Show recent traffic events."""
        print("\n" + "="*60)
        print("Alert History (Last 10 events)")
        print("="*60)
        if not self.events:
            print("No traffic events recorded yet.")
            return
        
        recent_events = self.events[-10:]
        for event in reversed(recent_events):
            marker = "⚠️" if event.risk_level == "HIGH" else "✅" if event.risk_level == "LOW" else "🔍"
            print(f"{marker} {event}")
            print("-" * 60)
            print(f"Total events: {len(self.events)}")
        
    def save_reports(self):
        """Generate and save a comprehensive report"""
        timestamp=datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"rulesentry_report_{timestamp}.txt"

        with open(report_file, 'w') as f:
            f.write("RULE SENTRY - Firewall Report \n")
            f.write("="*60 +"\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            f.write("Configured Rules: \n")
            f.write("-" *40 + "\n")
            if self.rules: 
                for rule in self.rules:
                    f.write(f"{rule}\n")
            else: 
                f.write("No rules are configured.\n")
            f.write("\n")

            f.write("Recent Traffic Events: \n")
            f.write("-" * 40 + "\n")
            recent = self.events[-20:] if len (self.events) > 20 else self.events
            for events in reversed(recent):
                f.write(f"{event}\n")
            
            f.write("\n Statistics: \n")
            f.write("-"* 20 + "\n")
            verdicts ={}
            risks ={}
            for event in self.events:
                verdicts[events.verdict] = verdicts.get(event.verdict, 0) + 1
                risks[event.risk_level] = risks.get(events.risk_level, 0) + 1
            
            for v, count in verdicts.items():
                f.write(f"{v}: {count}\n")
            f.write(f"\n Total events analyzed: {len(self.events)}\n")

        print(f"Report Saved: {report_file}")
    
    def show_menu(self):
        """Display the main menu"""
        print("\n" + "█"*50)
        print("RuleSentry - Smart Firewall")
        print("█"*50)
        print("1. Add firewall rule")
        print("2. View firewall rules")
        print("3. Analyze traffic")
        print("4. View alert history")
        print("5. Save report")
        print("6. Exit")
        print("█"*50)
    
    def main():
        """Main program loop"""
        firewall= RuleSentry()

        while True:
            firewall.show_menu()
            choice=input("\n Select Option (1-6): ").strip()

            if choice == '1':
                firewall.add_rules()
            elif choice == '2':
                firewall.view_rules()
            elif choice == '3':
                firewall.analyze_traffic()
            elif choice == '4':
                firewall.view_alert_history()
            elif choice == '5':
                firewall.save_reports()
            elif choice == '6':
                firewall.save_data()
                print("\n Thank you for using RuleSentry!")
                break
            else:
                print("Invalid option! Please try again.")
            
            input ("\n Press Enter to continue...")
if __name__ == "__main__":
    RuleSentry.main()

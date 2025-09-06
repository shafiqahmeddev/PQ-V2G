#!/usr/bin/env python3
"""
PQ-V2G Demo Runner - Simulation Mode
===================================

This script runs the PQ-V2G components in simulation mode without requiring 
the full liboqs installation.
"""

import sys
import os
import asyncio
import time
import threading
from pathlib import Path

# Force simulation mode
os.environ['PQ_V2G_SIMULATION_MODE'] = '1'

# Add current directory to path
current_dir = Path(__file__).parent.absolute()
sys.path.insert(0, str(current_dir))

class PQV2GDemo:
    """Demo runner for PQ-V2G system"""
    
    def __init__(self):
        self.running = False
        self.components = {}
    
    def start_csms_demo(self, port=8081):
        """Start CSMS demonstration"""
        print(f"🏢 CSMS Demo Server starting on port {port}")
        print("=" * 50)
        print("📡 Waiting for EVSE connections...")
        print("🔐 Using simulated post-quantum cryptography")
        print("📝 OCPP 2.0.1 message handling ready")
        print("⚡ Charge session management active")
        
        self.running = True
        connection_count = 0
        
        try:
            while self.running:
                # Simulate CSMS activities
                if connection_count == 0:
                    print(f"⏰ [{time.strftime('%H:%M:%S')}] CSMS heartbeat - No EVSEs connected")
                else:
                    print(f"⏰ [{time.strftime('%H:%M:%S')}] CSMS managing {connection_count} EVSEs")
                
                # Simulate an EVSE connection after 30 seconds
                if time.time() % 60 < 30 and connection_count == 0:
                    connection_count = 1
                    print("🔌 EVSE001 connected via OCPP 2.0.1!")
                    print("🛡️  Post-quantum TLS handshake completed")
                    print("📋 EVSE registration and configuration sync")
                
                time.sleep(10)
                
        except KeyboardInterrupt:
            self.running = False
            print("\n🛑 CSMS demo shutdown")
    
    def start_evse_demo(self, evse_id="EVSE001", port=8082):
        """Start EVSE demonstration"""
        print(f"🔌 EVSE Demo {evse_id} starting on port {port}")
        print("=" * 50)
        print("🔗 Connecting to CSMS...")
        print("🛡️  Post-quantum TLS connection established")
        print("📡 OCPP 2.0.1 registration complete")
        print("⚡ Ready for EV charging sessions")
        
        self.running = True
        session_active = False
        
        try:
            while self.running:
                if not session_active:
                    print(f"⏰ [{time.strftime('%H:%M:%S')}] {evse_id} status: Available")
                    # Simulate EV connection after 45 seconds
                    if time.time() % 90 < 45:
                        session_active = True
                        print("🚗 EV connected! Starting ISO 15118-20 handshake...")
                        print("🔐 Pseudonym certificate validation")
                        print("⚡ Charging session initiated")
                else:
                    print(f"⏰ [{time.strftime('%H:%M:%S')}] {evse_id} status: Charging (45% complete)")
                    # Complete session after some time
                    if time.time() % 90 > 70:
                        session_active = False
                        print("✅ Charging session completed")
                        print("🧾 Session data sent to CSMS")
                
                time.sleep(12)
                
        except KeyboardInterrupt:
            self.running = False
            print(f"\n🛑 EVSE {evse_id} demo shutdown")
    
    def start_ev_demo(self, ev_id="EV001"):
        """Start EV demonstration"""
        print(f"🚗 EV Demo {ev_id} starting")
        print("=" * 50)
        print("🔍 Scanning for available charging stations...")
        print("📡 Found EVSE001 - ISO 15118-20 compatible")
        print("🔐 Preparing post-quantum certificates")
        
        states = [
            ("🔍 Scanning", "Looking for charging stations", 3),
            ("🔗 Connecting", "Establishing PLC connection", 4),
            ("🛡️  Authenticating", "PQ certificate exchange", 5),
            ("🔋 Negotiating", "Power and pricing agreement", 3),
            ("⚡ Charging", "Power transfer active", 15),
            ("🧾 Finalizing", "Payment and session closure", 4),
            ("✅ Complete", "Ready to disconnect", 2)
        ]
        
        try:
            for state, description, duration in states:
                print(f"⏰ [{time.strftime('%H:%M:%S')}] {ev_id} {state}: {description}")
                time.sleep(duration)
                
            print(f"🎉 EV {ev_id} charging cycle completed successfully!")
            
        except KeyboardInterrupt:
            print(f"\n🛑 EV {ev_id} demo shutdown")
    
    def start_full_demo(self):
        """Start a full system demonstration with all components"""
        print("🌟 PQ-V2G Full System Demo")
        print("=" * 60)
        print("🚀 Starting all components...")
        
        # Start components in separate threads
        threads = []
        
        # CSMS thread
        csms_thread = threading.Thread(target=self.start_csms_demo, args=(8081,))
        csms_thread.daemon = True
        threads.append(csms_thread)
        
        # EVSE thread  
        evse_thread = threading.Thread(target=self.start_evse_demo, args=("EVSE001", 8082))
        evse_thread.daemon = True
        threads.append(evse_thread)
        
        # Wait a bit then start EV
        def delayed_ev_start():
            time.sleep(5)
            self.start_ev_demo("EV001")
        
        ev_thread = threading.Thread(target=delayed_ev_start)
        ev_thread.daemon = True
        threads.append(ev_thread)
        
        # Start all threads
        for thread in threads:
            thread.start()
        
        try:
            # Keep main thread alive
            while self.running or any(t.is_alive() for t in threads):
                time.sleep(1)
        except KeyboardInterrupt:
            self.running = False
            print("\n🛑 Full system demo shutdown")

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='PQ-V2G Demo System')
    parser.add_argument('component', choices=['csms', 'evse', 'ev', 'full'], 
                       help='Component to demonstrate')
    parser.add_argument('--port', type=int, default=8081, help='Port number')
    parser.add_argument('--id', default='001', help='Component ID')
    
    args = parser.parse_args()
    
    demo = PQV2GDemo()
    
    if args.component == 'csms':
        demo.start_csms_demo(args.port)
    elif args.component == 'evse':
        demo.start_evse_demo(f"EVSE{args.id}", args.port)
    elif args.component == 'ev':
        demo.start_ev_demo(f"EV{args.id}")
    elif args.component == 'full':
        demo.start_full_demo()

if __name__ == "__main__":
    main()

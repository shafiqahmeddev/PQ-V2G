#!/usr/bin/env python3
"""
PQ-V2G Main Entry Point
=======================

Main entry point for the PQ-V2G system that can start different roles
based on environment configuration.

Author: Shafiq Ahmed <s.ahmed@essex.ac.uk>
Institution: University of Essex  
License: MIT
"""

import os
import sys
import asyncio
import argparse
import logging
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from src.utils.config_loader import load_config
from src.utils.logger import setup_logging

async def start_ca_service(config):
    """Start Certificate Authority service"""
    from src.identity.pq_ca import create_identity_plane
    from src.crypto.pq_crypto import create_crypto_manager
    
    print("Starting PQ-V2G Certificate Authority...")
    
    # Initialize crypto and CA
    crypto_manager = create_crypto_manager(config.get('crypto', {}))
    ca, pseudonym_manager = create_identity_plane(config)
    
    # Keep running
    while True:
        await asyncio.sleep(60)
        # In production, this would run actual CA service
        print("CA service running...")

async def start_csms_service(config):
    """Start CSMS service"""
    from src.roles.csms.csms_server import CSMSApplication
    
    print("Starting PQ-V2G CSMS...")
    
    app = CSMSApplication("config/pq_v2g_config.yaml")
    await app.start()

async def start_evse_service(config):
    """Start EVSE service"""
    from src.roles.evse.evse_controller import EVSEApplication
    
    evse_id = os.getenv('EVSE_ID', 'EVSE001')
    print(f"Starting PQ-V2G EVSE: {evse_id}")
    
    app = EVSEApplication("config/pq_v2g_config.yaml", evse_id)
    await app.start()

async def start_ev_service(config):
    """Start EV service"""
    from src.roles.ev.ev_client import EVApplication
    
    ev_id = os.getenv('EV_ID', 'EV001')
    print(f"Starting PQ-V2G EV: {ev_id}")
    
    app = EVApplication("config/pq_v2g_config.yaml", ev_id)
    await app.start()

async def start_policy_node_service(config):
    """Start Policy Node service"""
    print("Starting PQ-V2G Policy Node...")
    
    # Policy node implementation would go here
    while True:
        await asyncio.sleep(60)
        print("Policy node running...")

async def start_monitor_service(config):
    """Start monitoring service"""
    print("Starting PQ-V2G Performance Monitor...")
    
    # Monitoring implementation would go here
    while True:
        await asyncio.sleep(30)
        print("Monitor service running...")

async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='PQ-V2G System')
    parser.add_argument('--config', default='config/pq_v2g_config.yaml',
                       help='Configuration file path')
    parser.add_argument('--role', help='Service role to start')
    
    args = parser.parse_args()
    
    try:
        # Load configuration
        config = load_config(args.config)
        
        # Setup logging
        setup_logging(config.get('logging', {}))
        
        # Get role from argument or environment
        role = args.role or os.getenv('PQ_V2G_ROLE', 'ca')
        
        print(f"Starting PQ-V2G system in {role} mode...")
        
        # Start appropriate service
        if role == 'ca':
            await start_ca_service(config)
        elif role == 'csms':
            await start_csms_service(config)
        elif role == 'evse':
            await start_evse_service(config)
        elif role == 'ev':
            await start_ev_service(config)
        elif role == 'policy_node':
            await start_policy_node_service(config)
        elif role == 'monitor':
            await start_monitor_service(config)
        else:
            print(f"Unknown role: {role}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("PQ-V2G system interrupted by user")
    except Exception as e:
        print(f"PQ-V2G system error: {e}")
        logging.exception("System startup error")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())

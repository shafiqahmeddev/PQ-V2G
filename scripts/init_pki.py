#!/usr/bin/env python3
"""
PQ-V2G PKI Initialization Script
================================

This script initializes the post-quantum PKI infrastructure for the PQ-V2G system,
generating root certificates, intermediate CAs, and initial device certificates.

Author: Shafiq Ahmed <s.ahmed@essex.ac.uk>
Institution: University of Essex
License: MIT
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from datetime import datetime, timedelta

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

# PQ-V2G imports
from src.crypto.pq_crypto import create_crypto_manager
from src.identity.pq_ca import create_identity_plane
from src.utils.config_loader import load_config
from src.utils.logger import setup_logging

def setup_certificate_directories(base_path: Path):
    """Create certificate directory structure"""
    directories = [
        'root',
        'intermediate', 
        'evse',
        'ev',
        'policy_node',
        'private',
        'crl'  # Certificate Revocation Lists
    ]
    
    for dir_name in directories:
        cert_dir = base_path / dir_name
        cert_dir.mkdir(parents=True, exist_ok=True)
        print(f"Created directory: {cert_dir}")

def initialize_root_ca(ca, config, cert_path: Path):
    """Initialize root CA and save certificates"""
    try:
        print("\n=== Initializing Root CA ===")
        
        # Root CA is automatically created in the constructor
        root_cert_info = None
        for cert_info in ca.certificates.values():
            if cert_info.certificate_type.value == 'root_ca':
                root_cert_info = cert_info
                break
        
        if root_cert_info:
            # Save root certificate
            root_cert_file = cert_path / 'root' / 'root-ca.pem'
            root_cert_pem = ca._create_certificate_pem(root_cert_info)
            
            with open(root_cert_file, 'w') as f:
                f.write(root_cert_pem)
            
            print(f"Root CA certificate saved: {root_cert_file}")
            print(f"  Serial Number: {root_cert_info.serial_number}")
            print(f"  Subject: {root_cert_info.subject}")
            print(f"  Valid Until: {root_cert_info.valid_until}")
            print(f"  Fingerprint: {root_cert_info.fingerprint}")
            
            return root_cert_info
        else:
            raise Exception("Root CA certificate not found")
            
    except Exception as e:
        print(f"Error initializing Root CA: {e}")
        raise

def generate_evse_certificates(ca, cert_path: Path, count: int = 5):
    """Generate initial EVSE certificates"""
    try:
        print(f"\n=== Generating {count} EVSE Certificates ===")
        
        evse_certs = []
        
        for i in range(1, count + 1):
            evse_id = f"EVSE{i:03d}"
            
            # Generate key pair for EVSE
            public_key, private_key = ca.crypto.generate_dsa_keypair("ML-DSA-65")
            
            # Issue EVSE certificate
            cert_pem = ca.issue_evse_certificate(evse_id, public_key)
            
            # Save certificate
            cert_file = cert_path / 'evse' / f'{evse_id}.pem'
            with open(cert_file, 'w') as f:
                f.write(cert_pem)
            
            # Save private key (in production, this would be stored securely)
            key_file = cert_path / 'private' / f'{evse_id}-key.bin'
            with open(key_file, 'wb') as f:
                f.write(private_key)
            
            # Extract certificate info
            valid, cert_info = ca.validate_certificate(cert_pem)
            if valid and cert_info:
                evse_certs.append({
                    'evse_id': evse_id,
                    'serial_number': cert_info.serial_number,
                    'certificate_file': str(cert_file),
                    'private_key_file': str(key_file)
                })
                
                print(f"  Generated EVSE certificate: {evse_id} ({cert_info.serial_number})")
        
        # Save EVSE certificate index
        index_file = cert_path / 'evse' / 'index.json'
        with open(index_file, 'w') as f:
            json.dump(evse_certs, f, indent=2)
        
        print(f"EVSE certificate index saved: {index_file}")
        return evse_certs
        
    except Exception as e:
        print(f"Error generating EVSE certificates: {e}")
        raise

def generate_policy_node_certificates(ca, cert_path: Path, count: int = 2):
    """Generate policy node certificates"""
    try:
        print(f"\n=== Generating {count} Policy Node Certificates ===")
        
        policy_certs = []
        
        for i in range(1, count + 1):
            policy_id = f"POLICY{i:03d}"
            
            # Generate key pair for policy node
            public_key, private_key = ca.crypto.generate_dsa_keypair("ML-DSA-65")
            
            # Create policy node certificate (similar to EVSE but different purpose)
            # In production, would have separate method for policy nodes
            cert_pem = ca.issue_evse_certificate(policy_id, public_key)  # Reusing EVSE method
            
            # Save certificate
            cert_file = cert_path / 'policy_node' / f'{policy_id}.pem'
            with open(cert_file, 'w') as f:
                f.write(cert_pem)
            
            # Save private key
            key_file = cert_path / 'private' / f'{policy_id}-key.bin'
            with open(key_file, 'wb') as f:
                f.write(private_key)
            
            # Extract certificate info
            valid, cert_info = ca.validate_certificate(cert_pem)
            if valid and cert_info:
                policy_certs.append({
                    'policy_id': policy_id,
                    'serial_number': cert_info.serial_number,
                    'certificate_file': str(cert_file),
                    'private_key_file': str(key_file)
                })
                
                print(f"  Generated Policy Node certificate: {policy_id} ({cert_info.serial_number})")
        
        # Save policy certificate index
        index_file = cert_path / 'policy_node' / 'index.json'
        with open(index_file, 'w') as f:
            json.dump(policy_certs, f, indent=2)
        
        print(f"Policy Node certificate index saved: {index_file}")
        return policy_certs
        
    except Exception as e:
        print(f"Error generating Policy Node certificates: {e}")
        raise

def initialize_ev_pseudonym_pools(pseudonym_manager, cert_path: Path, ev_count: int = 3, pool_size: int = 10):
    """Initialize EV pseudonym certificate pools"""
    try:
        print(f"\n=== Initializing {ev_count} EV Pseudonym Pools (size={pool_size}) ===")
        
        ev_pools = []
        
        for i in range(1, ev_count + 1):
            ev_id = f"EV{i:03d}"
            
            # Create pseudonym pool
            pool = pseudonym_manager.create_pseudonym_pool(ev_id, pool_size)
            
            if pool:
                # Save pool information
                pool_info = {
                    'ev_id': ev_id,
                    'pool_size': pool.pool_size,
                    'certificates': []
                }
                
                # Save each certificate in the pool
                pool_dir = cert_path / 'ev' / ev_id
                pool_dir.mkdir(exist_ok=True)
                
                for j, cert_info in enumerate(pool.certificates):
                    cert_file = pool_dir / f'pseudonym_{j+1:02d}.pem'
                    
                    # Create certificate PEM from info
                    cert_pem = pseudonym_manager.ca._create_certificate_pem(cert_info)
                    
                    with open(cert_file, 'w') as f:
                        f.write(cert_pem)
                    
                    pool_info['certificates'].append({
                        'serial_number': cert_info.serial_number,
                        'subject': cert_info.subject,
                        'certificate_file': str(cert_file),
                        'active': (cert_info.serial_number == pool.active_certificate)
                    })
                
                ev_pools.append(pool_info)
                print(f"  Created pseudonym pool for {ev_id}: {len(pool.certificates)} certificates")
        
        # Save EV pools index
        index_file = cert_path / 'ev' / 'pools_index.json'
        with open(index_file, 'w') as f:
            json.dump(ev_pools, f, indent=2)
        
        print(f"EV pseudonym pools index saved: {index_file}")
        return ev_pools
        
    except Exception as e:
        print(f"Error initializing EV pseudonym pools: {e}")
        raise

def create_pki_summary(cert_path: Path, root_cert_info, evse_certs, policy_certs, ev_pools):
    """Create PKI summary document"""
    try:
        print(f"\n=== Creating PKI Summary ===")
        
        summary = {
            'pki_initialization': {
                'timestamp': datetime.utcnow().isoformat(),
                'version': '1.0.0',
                'cryptographic_algorithms': {
                    'key_encapsulation': 'ML-KEM-768',
                    'digital_signature': 'ML-DSA-65',
                    'hash_function': 'SHA-256'
                }
            },
            'root_ca': {
                'serial_number': root_cert_info.serial_number,
                'subject': root_cert_info.subject,
                'valid_until': root_cert_info.valid_until.isoformat(),
                'fingerprint': root_cert_info.fingerprint
            },
            'statistics': {
                'evse_certificates': len(evse_certs),
                'policy_node_certificates': len(policy_certs),
                'ev_pseudonym_pools': len(ev_pools),
                'total_ev_certificates': sum(len(pool['certificates']) for pool in ev_pools)
            },
            'certificate_files': {
                'root_ca': 'root/root-ca.pem',
                'evse_index': 'evse/index.json',
                'policy_node_index': 'policy_node/index.json',
                'ev_pools_index': 'ev/pools_index.json'
            },
            'security_notes': [
                'Private keys are stored in the private/ directory',
                'In production, private keys should be stored in HSMs',
                'Certificate revocation lists should be regularly updated',
                'EV pseudonym pools should be rotated according to privacy policy'
            ]
        }
        
        summary_file = cert_path / 'pki_summary.json'
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"PKI summary saved: {summary_file}")
        
        # Print summary to console
        print(f"\n=== PKI Initialization Complete ===")
        print(f"Root CA: {root_cert_info.serial_number}")
        print(f"EVSE Certificates: {len(evse_certs)}")
        print(f"Policy Node Certificates: {len(policy_certs)}")
        print(f"EV Pseudonym Pools: {len(ev_pools)}")
        print(f"Total EV Certificates: {sum(len(pool['certificates']) for pool in ev_pools)}")
        print(f"\nAll certificates saved to: {cert_path}")
        
        return summary
        
    except Exception as e:
        print(f"Error creating PKI summary: {e}")
        raise

def main():
    """Main PKI initialization function"""
    parser = argparse.ArgumentParser(description='Initialize PQ-V2G PKI')
    parser.add_argument('--config', required=True, help='Configuration file path')
    parser.add_argument('--cert-path', help='Certificate output directory (default: certificates/)')
    parser.add_argument('--evse-count', type=int, default=5, help='Number of EVSE certificates to generate')
    parser.add_argument('--policy-count', type=int, default=2, help='Number of policy node certificates to generate')
    parser.add_argument('--ev-count', type=int, default=3, help='Number of EV pseudonym pools to create')
    parser.add_argument('--pool-size', type=int, default=10, help='Size of each EV pseudonym pool')
    parser.add_argument('--force', action='store_true', help='Force regeneration if certificates exist')
    
    args = parser.parse_args()
    
    try:
        # Load configuration
        print("Loading configuration...")
        config = load_config(args.config)
        
        # Setup logging
        setup_logging(config.get('logging', {}))
        
        # Determine certificate path
        if args.cert_path:
            cert_path = Path(args.cert_path)
        else:
            cert_path = Path(__file__).parent.parent / 'certificates'
        
        print(f"Certificate path: {cert_path}")
        
        # Check if certificates already exist
        if (cert_path / 'root' / 'root-ca.pem').exists() and not args.force:
            print("PKI already exists. Use --force to regenerate.")
            return
        
        # Create certificate directories
        print("Setting up certificate directories...")
        setup_certificate_directories(cert_path)
        
        # Initialize crypto and identity components
        print("Initializing cryptographic components...")
        ca, pseudonym_manager = create_identity_plane(config)
        
        # Initialize root CA
        root_cert_info = initialize_root_ca(ca, config, cert_path)
        
        # Generate EVSE certificates
        evse_certs = generate_evse_certificates(ca, cert_path, args.evse_count)
        
        # Generate policy node certificates
        policy_certs = generate_policy_node_certificates(ca, cert_path, args.policy_count)
        
        # Initialize EV pseudonym pools
        ev_pools = initialize_ev_pseudonym_pools(pseudonym_manager, cert_path, 
                                               args.ev_count, args.pool_size)
        
        # Create PKI summary
        summary = create_pki_summary(cert_path, root_cert_info, evse_certs, 
                                   policy_certs, ev_pools)
        
        print(f"\nPKI initialization successful!")
        print(f"Generated {summary['statistics']['total_ev_certificates'] + len(evse_certs) + len(policy_certs) + 1} certificates total")
        
    except KeyboardInterrupt:
        print("\nPKI initialization interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"PKI initialization failed: {e}")
        logging.exception("PKI initialization error")
        sys.exit(1)

if __name__ == "__main__":
    main()

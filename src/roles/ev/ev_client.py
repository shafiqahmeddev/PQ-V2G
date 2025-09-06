"""
PQ-V2G Electric Vehicle (EV) Role Implementation
===============================================

This module implements the Electric Vehicle role in the PQ-V2G system,
providing ISO 15118-20 communication, post-quantum TLS client functionality,
and pseudonymous certificate management for privacy-preserving charging.

Key Features:
- ISO 15118-20 Plug-and-Charge protocol implementation
- Post-quantum TLS 1.3 client with ML-KEM and ML-DSA
- Pseudonymous certificate rotation for privacy
- PLC emulation for vehicle-to-charger communication
- Outage token validation and sidelink communication
- Energy metering and session management

Author: Shafiq Ahmed <s.ahmed@essex.ac.uk>
Institution: University of Essex
License: MIT
"""

import os
import asyncio
import logging
import json
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import Enum

# PQ-V2G imports
from ..crypto.pq_crypto import PQCryptoManager, create_crypto_manager
from ..identity.pq_ca import PQCertificateAuthority, PseudonymManager, CertificateInfo
from ..session.pq_tls import PQTLSContext, PQTLSClient, create_tls_context, create_tls_client
from ..control.authorization import AuthorizationRequest, AuthorizationResponse, OutageToken
from ..data.metering import MeterReading, TelemetryType
from ..protocols.iso15118.ev_client import ISO15118EVClient
from ..utils.config_loader import load_config
from ..utils.logger import setup_logging

# Configure logging
logger = logging.getLogger(__name__)

class EVState(Enum):
    """EV charging session states"""
    IDLE = "idle"
    CONNECTING = "connecting"
    AUTHENTICATING = "authenticating"
    AUTHORIZING = "authorizing"
    CHARGING = "charging"
    STOPPING = "stopping"
    DISCONNECTED = "disconnected"
    ERROR = "error"

class ChargingMode(Enum):
    """EV charging modes"""
    AC = "ac"
    DC = "dc"
    BIDIRECTIONAL = "bidirectional"

@dataclass
class EVConfiguration:
    """EV configuration parameters"""
    ev_id: str
    make: str
    model: str
    year: int
    battery_capacity_kwh: float
    max_charge_power_kw: float
    charging_modes: List[ChargingMode]
    plug_type: str
    
@dataclass
class ChargingSession:
    """Charging session data"""
    session_id: str
    evse_id: str
    start_time: datetime
    end_time: Optional[datetime]
    start_soc_percent: float
    end_soc_percent: Optional[float]
    energy_delivered_kwh: Optional[float]
    cost: Optional[float]
    certificate_used: str
    authorization_method: str

class EVClient:
    """Electric Vehicle Client Implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # EV configuration
        self.ev_config = EVConfiguration(**config['ev_config'])
        self.ev_id = self.ev_config.ev_id
        
        # Initialize components
        self.crypto_manager = create_crypto_manager(config.get('crypto', {}))
        
        # TLS context (will be set up with certificates)
        self.tls_context = None
        self.tls_client = None
        
        # Certificate management
        self.pseudonym_manager = None
        self.current_certificate = None
        self.certificate_private_key = None
        
        # Session state
        self.current_state = EVState.IDLE
        self.current_session = None
        self.connected_evse_id = None
        
        # Battery simulation
        self.current_soc_percent = config.get('initial_soc', 30.0)
        self.is_charging = False
        
        # Performance metrics
        self.session_metrics = {}
        
        # Protocols
        self.iso15118_client = None
        
        logger.info(f"EV Client initialized: {self.ev_id}")
    
    async def initialize(self, ca: PQCertificateAuthority, pseudonym_manager: PseudonymManager):
        """Initialize EV with certificate authority and pseudonym manager"""
        try:
            self.pseudonym_manager = pseudonym_manager
            
            # Create pseudonym pool if not exists
            try:
                pool = self.pseudonym_manager.pseudonym_pools.get(self.ev_id)
                if not pool:
                    pool = self.pseudonym_manager.create_pseudonym_pool(self.ev_id)
                    
                # Get active certificate
                self.current_certificate = self.pseudonym_manager.get_active_certificate(self.ev_id)
                if self.current_certificate:
                    # Generate corresponding private key (in production, this would be securely stored)
                    self.certificate_private_key = self._generate_private_key_for_certificate()
                    
            except Exception as e:
                logger.error(f"Failed to initialize pseudonym pool: {e}")
                return False
            
            # Initialize TLS context
            self.tls_context = create_tls_context(
                self.config.get('tls', {}), 
                self.crypto_manager, 
                ca
            )
            
            # Load certificate chain
            if self.current_certificate:
                cert_chain = ca.get_certificate_chain(self.current_certificate.serial_number)
                self.tls_context.load_certificate_chain(cert_chain)
                self.tls_context.load_private_key(self.certificate_private_key)
            
            # Initialize ISO 15118 client
            self.iso15118_client = ISO15118EVClient(self.config.get('iso15118', {}), self)
            
            logger.info("EV initialization completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"EV initialization failed: {e}")
            return False
    
    async def connect_to_evse(self, evse_host: str, evse_port: int = 8444) -> bool:
        """Connect to EVSE and establish secure communication"""
        try:
            logger.info(f"Connecting to EVSE: {evse_host}:{evse_port}")
            self._change_state(EVState.CONNECTING)
            
            # Create TLS client
            self.tls_client = create_tls_client(self.tls_context)
            
            # Establish connection
            start_time = time.time()
            connected = await self.tls_client.connect(evse_host, evse_port)
            connection_time = time.time() - start_time
            
            if connected:
                logger.info(f"Connected to EVSE successfully in {connection_time:.3f}s")
                
                # Record performance metrics
                self.session_metrics['connection_time'] = connection_time
                handshake_metrics = self.tls_client.get_handshake_metrics()
                if handshake_metrics:
                    self.session_metrics['handshake_metrics'] = handshake_metrics
                
                # Start ISO 15118 communication
                self._change_state(EVState.AUTHENTICATING)
                return await self._start_iso15118_session()
            else:
                logger.error("Failed to connect to EVSE")
                self._change_state(EVState.ERROR)
                return False
                
        except Exception as e:
            logger.error(f"EVSE connection failed: {e}")
            self._change_state(EVState.ERROR)
            return False
    
    async def _start_iso15118_session(self) -> bool:
        """Start ISO 15118-20 communication session"""
        try:
            if not self.iso15118_client:
                logger.error("ISO 15118 client not initialized")
                return False
            
            # Start ISO 15118 session
            session_started = await self.iso15118_client.start_session(self.tls_client)
            
            if session_started:
                logger.info("ISO 15118 session started successfully")
                
                # Get EVSE information
                evse_info = await self.iso15118_client.get_evse_information()
                if evse_info:
                    self.connected_evse_id = evse_info.get('evse_id')
                    logger.info(f"Connected to EVSE: {self.connected_evse_id}")
                
                # Proceed to authorization
                self._change_state(EVState.AUTHORIZING)
                return await self._request_authorization()
            else:
                logger.error("ISO 15118 session start failed")
                return False
                
        except Exception as e:
            logger.error(f"ISO 15118 session start error: {e}")
            return False
    
    async def _request_authorization(self) -> bool:
        """Request Plug-and-Charge authorization"""
        try:
            if not self.current_certificate or not self.connected_evse_id:
                logger.error("Missing certificate or EVSE ID for authorization")
                return False
            
            # Create authorization request
            session_id = f"SESSION_{self.ev_id}_{int(time.time())}"
            
            auth_request = AuthorizationRequest(
                evse_id=self.connected_evse_id,
                ev_certificate=self._get_certificate_pem(),
                session_id=session_id,
                requested_energy_kwh=self._calculate_needed_energy(),
                payment_method="Plug-and-Charge",
                timestamp=datetime.utcnow()
            )
            
            # Send authorization request via ISO 15118
            auth_response = await self.iso15118_client.request_authorization(auth_request)
            
            if auth_response and auth_response.status.value == "authorized":
                logger.info(f"Authorization granted: Session {session_id}")
                
                # Create charging session
                self.current_session = ChargingSession(
                    session_id=session_id,
                    evse_id=self.connected_evse_id,
                    start_time=datetime.utcnow(),
                    end_time=None,
                    start_soc_percent=self.current_soc_percent,
                    end_soc_percent=None,
                    energy_delivered_kwh=None,
                    cost=None,
                    certificate_used=self.current_certificate.serial_number,
                    authorization_method="cloud"
                )
                
                # Start charging
                self._change_state(EVState.CHARGING)
                return await self._start_charging()
            else:
                reason = auth_response.reason if auth_response else "Unknown error"
                logger.error(f"Authorization denied: {reason}")
                
                # Try outage token if available
                return await self._try_outage_authorization()
                
        except Exception as e:
            logger.error(f"Authorization request failed: {e}")
            return await self._try_outage_authorization()
    
    async def _try_outage_authorization(self) -> bool:
        """Try authorization using outage token"""
        try:
            logger.info("Attempting outage authorization via sidelink")
            
            # Request outage token via sidelink (simulation)
            outage_token = await self._request_outage_token()
            
            if outage_token:
                logger.info(f"Outage token received: {outage_token.token_id}")
                
                # Validate token locally
                if await self._validate_outage_token(outage_token):
                    # Create charging session with outage token
                    session_id = f"OUTAGE_{self.ev_id}_{int(time.time())}"
                    
                    self.current_session = ChargingSession(
                        session_id=session_id,
                        evse_id=self.connected_evse_id,
                        start_time=datetime.utcnow(),
                        end_time=None,
                        start_soc_percent=self.current_soc_percent,
                        end_soc_percent=None,
                        energy_delivered_kwh=None,
                        cost=None,
                        certificate_used=self.current_certificate.serial_number,
                        authorization_method="outage_token"
                    )
                    
                    # Start charging with energy cap
                    self._change_state(EVState.CHARGING)
                    return await self._start_charging(max_energy=outage_token.max_energy_kwh)
                else:
                    logger.error("Outage token validation failed")
            else:
                logger.error("No outage token available")
            
            return False
            
        except Exception as e:
            logger.error(f"Outage authorization failed: {e}")
            return False
    
    async def _request_outage_token(self) -> Optional[OutageToken]:
        """Request outage token via NR sidelink"""
        try:
            # Simulate sidelink discovery and token request
            # In production, this would use actual 5G NR sidelink protocols
            
            # Simulate sidelink communication delay
            await asyncio.sleep(2.0)
            
            # Simulate token reception (80% success rate)
            import secrets
            if secrets.randbelow(100) < 80:
                # Create simulated outage token
                token_data = {
                    "token_id": f"TOK_{secrets.token_hex(8)}",
                    "evse_id": self.connected_evse_id,
                    "ev_pseudonym": self.current_certificate.subject,
                    "max_energy_kwh": min(50.0, self._calculate_needed_energy()),
                    "expiry_time": (datetime.utcnow() + timedelta(hours=1)).isoformat(),
                    "issued_time": datetime.utcnow().isoformat(),
                    "tariff_per_kwh": 0.30,
                    "policy_node_id": "POLICY001",
                    "nonce": secrets.token_bytes(16).hex(),
                    "signature": secrets.token_bytes(64).hex(),  # Simulated signature
                    "signature_algorithm": "ML-DSA-65"
                }
                
                return OutageToken.from_dict(token_data)
            else:
                return None
                
        except Exception as e:
            logger.error(f"Outage token request failed: {e}")
            return None
    
    async def _validate_outage_token(self, token: OutageToken) -> bool:
        """Validate outage token locally"""
        try:
            # Basic validation
            now = datetime.utcnow()
            
            # Check expiry
            if now > token.expiry_time:
                logger.warning("Outage token expired")
                return False
            
            # Check EVSE ID match
            if token.evse_id != self.connected_evse_id:
                logger.warning("Outage token EVSE ID mismatch")
                return False
            
            # In production, would verify signature with policy node public key
            # For simulation, assume valid
            logger.info("Outage token validated successfully")
            return True
            
        except Exception as e:
            logger.error(f"Outage token validation error: {e}")
            return False
    
    async def _start_charging(self, max_energy: Optional[float] = None) -> bool:
        """Start the charging process"""
        try:
            logger.info("Starting charging process")
            
            # Calculate charging parameters
            needed_energy = self._calculate_needed_energy()
            if max_energy:
                needed_energy = min(needed_energy, max_energy)
            
            # Start charging via ISO 15118
            charging_started = await self.iso15118_client.start_charging(
                target_energy_kwh=needed_energy,
                max_power_kw=self.ev_config.max_charge_power_kw
            )
            
            if charging_started:
                self.is_charging = True
                logger.info(f"Charging started: target={needed_energy}kWh")
                
                # Start charging simulation
                await self._charging_loop()
                return True
            else:
                logger.error("Failed to start charging")
                return False
                
        except Exception as e:
            logger.error(f"Charging start failed: {e}")
            return False
    
    async def _charging_loop(self):
        """Main charging loop"""
        try:
            start_soc = self.current_soc_percent
            target_soc = min(100.0, start_soc + 50.0)  # Charge up to 50% more or 100%
            
            logger.info(f"Charging loop started: {start_soc}% -> {target_soc}%")
            
            while self.is_charging and self.current_soc_percent < target_soc:
                # Simulate charging progress
                await asyncio.sleep(5.0)  # 5-second intervals
                
                # Simulate battery charging (1% per 5 seconds for demo)
                self.current_soc_percent += 1.0
                
                # Log progress
                if int(self.current_soc_percent) % 10 == 0:
                    logger.info(f"Charging progress: {self.current_soc_percent:.1f}%")
                
                # Check for stop conditions
                if self.current_soc_percent >= target_soc:
                    logger.info("Target SOC reached, stopping charging")
                    break
            
            # Stop charging
            await self._stop_charging()
            
        except Exception as e:
            logger.error(f"Charging loop error: {e}")
            await self._stop_charging()
    
    async def _stop_charging(self):
        """Stop the charging process"""
        try:
            logger.info("Stopping charging process")
            self._change_state(EVState.STOPPING)
            
            self.is_charging = False
            
            # Stop charging via ISO 15118
            if self.iso15118_client:
                await self.iso15118_client.stop_charging()
            
            # Finalize session
            if self.current_session:
                self.current_session.end_time = datetime.utcnow()
                self.current_session.end_soc_percent = self.current_soc_percent
                
                # Calculate energy delivered
                energy_delivered = (self.current_session.end_soc_percent - 
                                  self.current_session.start_soc_percent) / 100.0 * self.ev_config.battery_capacity_kwh
                self.current_session.energy_delivered_kwh = energy_delivered
                
                # Estimate cost (would come from EVSE in real implementation)
                tariff = 0.25 if self.current_session.authorization_method == "cloud" else 0.30
                self.current_session.cost = energy_delivered * tariff
                
                logger.info(f"Session completed: {energy_delivered:.2f}kWh delivered, cost: £{self.current_session.cost:.2f}")
            
            # Disconnect
            await self._disconnect()
            
        except Exception as e:
            logger.error(f"Charging stop error: {e}")
    
    async def _disconnect(self):
        """Disconnect from EVSE"""
        try:
            logger.info("Disconnecting from EVSE")
            
            # End ISO 15118 session
            if self.iso15118_client:
                await self.iso15118_client.end_session()
            
            # Close TLS connection
            if self.tls_client:
                # In production, would properly close connection
                pass
            
            # Reset state
            self.connected_evse_id = None
            self.current_session = None
            self.tls_client = None
            
            self._change_state(EVState.IDLE)
            logger.info("Disconnected from EVSE")
            
        except Exception as e:
            logger.error(f"Disconnect error: {e}")
            self._change_state(EVState.ERROR)
    
    def _change_state(self, new_state: EVState):
        """Change EV state and log transition"""
        old_state = self.current_state
        self.current_state = new_state
        logger.info(f"EV state transition: {old_state.value} -> {new_state.value}")
    
    def _calculate_needed_energy(self) -> float:
        """Calculate energy needed to charge battery"""
        current_energy = (self.current_soc_percent / 100.0) * self.ev_config.battery_capacity_kwh
        max_energy = self.ev_config.battery_capacity_kwh
        return max_energy - current_energy
    
    def _get_certificate_pem(self) -> str:
        """Get current certificate in PEM format"""
        # In production, this would return actual PEM-encoded certificate
        # For simulation, return certificate info as JSON
        if self.current_certificate:
            cert_data = {
                "serial_number": self.current_certificate.serial_number,
                "subject": self.current_certificate.subject,
                "fingerprint": self.current_certificate.fingerprint,
                "valid_until": self.current_certificate.valid_until.isoformat()
            }
            return json.dumps(cert_data)
        return ""
    
    def _generate_private_key_for_certificate(self) -> bytes:
        """Generate private key corresponding to certificate public key"""
        # In production, private keys would be securely stored
        # For simulation, generate a key
        _, private_key = self.crypto_manager.generate_dsa_keypair("ML-DSA-65")
        return private_key
    
    async def rotate_certificate(self) -> bool:
        """Rotate to next pseudonym certificate"""
        try:
            if not self.pseudonym_manager:
                logger.error("No pseudonym manager available")
                return False
            
            # Check if rotation is needed
            if not self.pseudonym_manager.should_rotate_certificate(self.ev_id, 1.0):
                logger.debug("Certificate rotation not needed")
                return True
            
            # Rotate certificate
            new_cert = self.pseudonym_manager.rotate_certificate(self.ev_id)
            if new_cert:
                self.current_certificate = new_cert
                self.certificate_private_key = self._generate_private_key_for_certificate()
                
                # Update TLS context if available
                if self.tls_context:
                    # Would update certificate in TLS context
                    pass
                
                logger.info(f"Certificate rotated to: {new_cert.serial_number}")
                return True
            else:
                logger.error("Certificate rotation failed")
                return False
                
        except Exception as e:
            logger.error(f"Certificate rotation error: {e}")
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get EV status information"""
        return {
            "ev_id": self.ev_id,
            "state": self.current_state.value,
            "battery_soc_percent": self.current_soc_percent,
            "is_charging": self.is_charging,
            "connected_evse": self.connected_evse_id,
            "current_session": self.current_session.__dict__ if self.current_session else None,
            "current_certificate": self.current_certificate.serial_number if self.current_certificate else None
        }
    
    def get_session_history(self) -> List[Dict[str, Any]]:
        """Get charging session history"""
        # In production, this would retrieve from persistent storage
        sessions = []
        if self.current_session:
            sessions.append(self.current_session.__dict__)
        return sessions

# Main EV application class
class EVApplication:
    """Main EV Application"""
    
    def __init__(self, config_path: str, ev_id: str):
        # Load configuration
        self.config = load_config(config_path)
        self.config['ev_config']['ev_id'] = ev_id
        
        # Setup logging
        setup_logging(self.config.get('logging', {}))
        
        # Create EV client
        self.ev_client = EVClient(self.config)
        
        # Application state
        self.running = False
        
        logger.info(f"EV Application initialized: {ev_id}")
    
    async def start(self):
        """Start EV application"""
        try:
            logger.info("Starting EV application")
            self.running = True
            
            # Initialize crypto and identity components (simulation)
            crypto_manager = create_crypto_manager(self.config.get('crypto', {}))
            
            # Create mock CA and pseudonym manager for demo
            from ..identity.pq_ca import create_identity_plane
            ca, pseudonym_manager = create_identity_plane(self.config)
            
            # Initialize EV
            if not await self.ev_client.initialize(ca, pseudonym_manager):
                logger.error("EV initialization failed")
                return
            
            # Main application loop
            await self._application_loop()
            
        except Exception as e:
            logger.error(f"EV application error: {e}")
        finally:
            await self.stop()
    
    async def _application_loop(self):
        """Main application loop"""
        try:
            while self.running:
                # Check for charging opportunities
                if self.ev_client.current_state == EVState.IDLE:
                    # Simulate finding a charging station
                    await asyncio.sleep(30.0)  # Wait 30 seconds
                    
                    # Try to connect to EVSE
                    evse_host = self.config.get('evse_host', 'localhost')
                    evse_port = self.config.get('evse_port', 8444)
                    
                    logger.info(f"Attempting to connect to EVSE at {evse_host}:{evse_port}")
                    success = await self.ev_client.connect_to_evse(evse_host, evse_port)
                    
                    if not success:
                        logger.error("Failed to connect to EVSE, retrying in 60 seconds")
                        await asyncio.sleep(60.0)
                
                else:
                    # Check for certificate rotation
                    await self.ev_client.rotate_certificate()
                    await asyncio.sleep(10.0)
                
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Application loop error: {e}")
    
    async def stop(self):
        """Stop EV application"""
        logger.info("Stopping EV application")
        self.running = False
        
        # Disconnect if connected
        if self.ev_client.current_state not in [EVState.IDLE, EVState.DISCONNECTED]:
            await self.ev_client._disconnect()

# CLI entry point
async def main():
    """Main entry point for EV client"""
    import argparse
    
    parser = argparse.ArgumentParser(description='PQ-V2G Electric Vehicle Client')
    parser.add_argument('--config', required=True, help='Configuration file path')
    parser.add_argument('--ev-id', required=True, help='Electric Vehicle ID')
    parser.add_argument('--evse-host', default='localhost', help='EVSE host address')
    parser.add_argument('--evse-port', type=int, default=8444, help='EVSE port')
    
    args = parser.parse_args()
    
    # Create and start EV application
    app = EVApplication(args.config, args.ev_id)
    
    # Override EVSE connection details
    app.config['evse_host'] = args.evse_host
    app.config['evse_port'] = args.evse_port
    
    try:
        await app.start()
    except KeyboardInterrupt:
        logger.info("EV application interrupted by user")
        await app.stop()

if __name__ == "__main__":
    asyncio.run(main())

"""
PQ-V2G Policy Node Controller Implementation
===========================================

This module implements the Policy Node controller for the PQ-V2G system,
providing NR sidelink-based outage token management, local authorization
during backhaul failures, and policy enforcement for privacy-preserving
vehicle communication.

Key Features:
- NR sidelink token broadcasting and management
- Outage authorization with energy capping
- Policy-based certificate validation
- Local decision making during network failures
- Session reconciliation coordination
- Privacy policy enforcement

Author: Shafiq Ahmed <s.ahmed@essex.ac.uk>
Institution: University of Essex
License: MIT
"""

import os
import json
import time
import logging
import asyncio
import socket
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Set
from dataclasses import dataclass, asdict
from enum import Enum
import threading
import queue

# PQ-V2G imports  
from ...crypto.pq_crypto import PQCryptoManager, create_crypto_manager
from ...identity.pq_ca import PQCertificateAuthority, create_identity_plane
from ...control.authorization import OutageTokenManager, OutageToken, create_outage_token_manager
from ...data.metering import TelemetryCollector, create_telemetry_collector
from ...utils.config_loader import load_config
from ...utils.logger import setup_logging

# Configure logging
logger = logging.getLogger(__name__)

class PolicyNodeState(Enum):
    """Policy node operational states"""
    OFFLINE = "offline"
    STARTING = "starting" 
    ACTIVE = "active"
    DEGRADED = "degraded"
    MAINTENANCE = "maintenance"

class SidelinkStatus(Enum):
    """NR sidelink communication status"""
    UNAVAILABLE = "unavailable"
    DISCOVERING = "discovering"
    AVAILABLE = "available"
    BROADCASTING = "broadcasting"
    ERROR = "error"

@dataclass
class SidelinkDevice:
    """Discovered sidelink device information"""
    device_id: str
    device_type: str  # EVSE, EV, POLICY_NODE
    signal_strength: float
    last_seen: datetime
    capabilities: List[str]

@dataclass
class AuthorizationPolicy:
    """Authorization policy configuration"""
    policy_id: str
    max_energy_kwh: float
    max_power_kw: float
    max_duration_minutes: int
    allowed_hours: Optional[List[int]] = None  # Hours of day when allowed
    energy_price_kwh: float = 0.30
    priority_level: int = 1  # 1 = highest, 5 = lowest

@dataclass
class PolicyDecision:
    """Policy decision result"""
    decision_id: str
    ev_id: str
    evse_id: str
    policy_applied: str
    authorized: bool
    max_energy_kwh: Optional[float]
    max_power_kw: Optional[float]
    expiry_time: Optional[datetime]
    reason: str
    timestamp: datetime

class PolicyNodeController:
    """Policy Node Controller for outage management and local authorization"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Policy node configuration
        self.node_id = config.get('policy_node_id', 'POLICY001')
        self.coverage_radius_m = config.get('coverage_radius_meters', 300)
        self.broadcast_interval_seconds = config.get('broadcast_interval_seconds', 10)
        
        # Network configuration
        self.sidelink_port = config.get('sidelink_port', 8844)
        self.discovery_port = config.get('discovery_port', 8845)
        
        # Initialize components
        self.crypto_manager = create_crypto_manager(config.get('crypto', {}))
        self.outage_token_manager = None
        self.telemetry_collector = None
        
        # State management
        self.current_state = PolicyNodeState.OFFLINE
        self.sidelink_status = SidelinkStatus.UNAVAILABLE
        
        # Device management
        self.discovered_devices: Dict[str, SidelinkDevice] = {}
        self.authorized_evses: Set[str] = set()
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        
        # Policy management
        self.authorization_policies: Dict[str, AuthorizationPolicy] = {}
        self.policy_decisions: List[PolicyDecision] = []
        
        # Communication
        self.sidelink_socket = None
        self.discovery_socket = None
        self.message_queue = queue.Queue()
        
        # Tasks
        self.running = False
        self.broadcast_task = None
        self.discovery_task = None
        self.monitoring_task = None
        
        # Load default policies
        self._load_default_policies()
        
        logger.info(f"Policy Node Controller initialized: {self.node_id}")
    
    def _load_default_policies(self):
        """Load default authorization policies"""
        try:
            # Emergency policy - very restrictive
            emergency_policy = AuthorizationPolicy(
                policy_id="EMERGENCY",
                max_energy_kwh=10.0,  # 10 kWh max
                max_power_kw=7.0,     # 7 kW max (single phase)
                max_duration_minutes=60,
                energy_price_kwh=0.50,  # Higher price for emergency
                priority_level=1
            )
            
            # Standard outage policy
            standard_policy = AuthorizationPolicy(
                policy_id="STANDARD",
                max_energy_kwh=25.0,  # 25 kWh max
                max_power_kw=22.0,    # 22 kW max (three phase)
                max_duration_minutes=120,
                energy_price_kwh=0.35,
                priority_level=2
            )
            
            # Generous policy (for trusted vehicles)
            generous_policy = AuthorizationPolicy(
                policy_id="GENEROUS", 
                max_energy_kwh=50.0,  # 50 kWh max
                max_power_kw=50.0,    # 50 kW max (DC fast charge)
                max_duration_minutes=180,
                energy_price_kwh=0.30,
                priority_level=3
            )
            
            self.authorization_policies["EMERGENCY"] = emergency_policy
            self.authorization_policies["STANDARD"] = standard_policy
            self.authorization_policies["GENEROUS"] = generous_policy
            
            logger.info(f"Loaded {len(self.authorization_policies)} authorization policies")
            
        except Exception as e:
            logger.error(f"Failed to load default policies: {e}")
    
    async def start(self):
        """Start policy node controller"""
        try:
            logger.info("Starting Policy Node Controller")
            self.running = True
            self._change_state(PolicyNodeState.STARTING)
            
            # Initialize crypto and identity
            await self._initialize_crypto_identity()
            
            # Initialize outage token manager
            self.outage_token_manager = create_outage_token_manager(self.config, self.crypto_manager)
            
            # Initialize telemetry collector
            self.telemetry_collector = create_telemetry_collector(self.config.get('telemetry', {}))
            await self.telemetry_collector.start_collection()
            
            # Initialize sidelink communication
            await self._initialize_sidelink()
            
            # Start background tasks
            await self._start_background_tasks()
            
            self._change_state(PolicyNodeState.ACTIVE)
            logger.info("Policy Node Controller started successfully")
            
        except Exception as e:
            logger.error(f"Policy Node startup failed: {e}")
            self._change_state(PolicyNodeState.OFFLINE)
            raise
    
    async def _initialize_crypto_identity(self):
        """Initialize cryptographic and identity components"""
        try:
            # Create identity plane (shared with other components)
            self.ca, self.pseudonym_manager = create_identity_plane(self.config)
            
            logger.info("Policy Node crypto/identity initialized")
        except Exception as e:
            logger.error(f"Crypto/identity initialization failed: {e}")
            raise
    
    async def _initialize_sidelink(self):
        """Initialize NR sidelink communication"""
        try:
            # Initialize sidelink broadcast socket
            self.sidelink_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sidelink_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.sidelink_socket.bind(('', self.sidelink_port))
            self.sidelink_socket.setblocking(False)
            
            # Initialize device discovery socket
            self.discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.discovery_socket.bind(('', self.discovery_port))
            self.discovery_socket.setblocking(False)
            
            self.sidelink_status = SidelinkStatus.AVAILABLE
            logger.info(f"Sidelink initialized - broadcast: {self.sidelink_port}, discovery: {self.discovery_port}")
            
        except Exception as e:
            logger.error(f"Sidelink initialization failed: {e}")
            self.sidelink_status = SidelinkStatus.ERROR
            raise
    
    async def _start_background_tasks(self):
        """Start background monitoring and communication tasks"""
        try:
            # Token broadcasting task
            self.broadcast_task = asyncio.create_task(self._token_broadcast_loop())
            
            # Device discovery task
            self.discovery_task = asyncio.create_task(self._device_discovery_loop())
            
            # Monitoring task
            self.monitoring_task = asyncio.create_task(self._monitoring_loop())
            
            logger.info("Background tasks started")
            
        except Exception as e:
            logger.error(f"Background task startup failed: {e}")
            raise
    
    async def _token_broadcast_loop(self):
        """Main token broadcasting loop"""
        try:
            while self.running:
                await asyncio.sleep(self.broadcast_interval_seconds)
                
                if self.sidelink_status == SidelinkStatus.AVAILABLE:
                    await self._broadcast_availability()
                    
                # Process pending token requests
                await self._process_token_requests()
                
        except Exception as e:
            logger.error(f"Token broadcast loop error: {e}")
    
    async def _device_discovery_loop(self):
        """Device discovery and communication loop"""
        try:
            while self.running:
                await asyncio.sleep(5)  # Check every 5 seconds
                
                # Listen for device announcements
                await self._listen_for_devices()
                
                # Clean up stale devices
                self._cleanup_stale_devices()
                
        except Exception as e:
            logger.error(f"Device discovery loop error: {e}")
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        try:
            while self.running:
                await asyncio.sleep(30)  # Check every 30 seconds
                
                # Update telemetry
                await self._collect_telemetry()
                
                # Check policy compliance
                await self._enforce_policies()
                
                # Update node status
                await self._update_node_status()
                
        except Exception as e:
            logger.error(f"Monitoring loop error: {e}")
    
    async def _broadcast_availability(self):
        """Broadcast policy node availability via sidelink"""
        try:
            availability_message = {
                "type": "POLICY_AVAILABILITY",
                "node_id": self.node_id,
                "timestamp": datetime.utcnow().isoformat(),
                "services": ["OUTAGE_TOKENS", "LOCAL_AUTH"],
                "coverage_radius_m": self.coverage_radius_m,
                "policies": list(self.authorization_policies.keys())
            }
            
            # Sign message with policy node key
            message_json = json.dumps(availability_message, sort_keys=True)
            signature = self.crypto_manager.sign(
                self.outage_token_manager.policy_private_key, 
                message_json.encode(), 
                "ML-DSA-65"
            )
            
            signed_message = {
                "message": availability_message,
                "signature": signature.hex(),
                "signature_algorithm": "ML-DSA-65"
            }
            
            # Broadcast via UDP
            broadcast_data = json.dumps(signed_message).encode()
            self.sidelink_socket.sendto(broadcast_data, ('<broadcast>', self.sidelink_port))
            
            logger.debug("Policy node availability broadcasted")
            
        except Exception as e:
            logger.error(f"Availability broadcast error: {e}")
    
    async def _listen_for_devices(self):
        """Listen for device announcements and authorization requests"""
        try:
            # Check for incoming messages (non-blocking)
            try:
                data, addr = self.discovery_socket.recvfrom(4096)
                message = json.loads(data.decode())
                
                await self._process_sidelink_message(message, addr)
                
            except socket.error:
                # No data available, continue
                pass
                
        except Exception as e:
            logger.error(f"Device listening error: {e}")
    
    async def _process_sidelink_message(self, message: Dict[str, Any], sender_addr: tuple):
        """Process incoming sidelink message"""
        try:
            message_type = message.get("type")
            
            if message_type == "DEVICE_ANNOUNCEMENT":
                await self._handle_device_announcement(message, sender_addr)
                
            elif message_type == "TOKEN_REQUEST":
                await self._handle_token_request(message, sender_addr)
                
            elif message_type == "AUTHORIZATION_REQUEST":
                await self._handle_authorization_request(message, sender_addr)
                
            elif message_type == "SESSION_UPDATE":
                await self._handle_session_update(message, sender_addr)
                
            else:
                logger.debug(f"Unknown sidelink message type: {message_type}")
                
        except Exception as e:
            logger.error(f"Sidelink message processing error: {e}")
    
    async def _handle_device_announcement(self, message: Dict[str, Any], sender_addr: tuple):
        """Handle device announcement"""
        try:
            device_id = message.get("device_id")
            device_type = message.get("device_type")
            capabilities = message.get("capabilities", [])
            
            if device_id and device_type:
                device = SidelinkDevice(
                    device_id=device_id,
                    device_type=device_type,
                    signal_strength=-50.0,  # Simulated RSRP
                    last_seen=datetime.utcnow(),
                    capabilities=capabilities
                )
                
                self.discovered_devices[device_id] = device
                
                if device_type == "EVSE":
                    self.authorized_evses.add(device_id)
                
                logger.info(f"Device discovered: {device_id} ({device_type})")
                
        except Exception as e:
            logger.error(f"Device announcement handling error: {e}")
    
    async def _handle_token_request(self, message: Dict[str, Any], sender_addr: tuple):
        """Handle outage token request"""
        try:
            evse_id = message.get("evse_id")
            ev_pseudonym = message.get("ev_pseudonym")
            requested_energy_kwh = message.get("requested_energy_kwh", 25.0)
            
            if not evse_id or not ev_pseudonym:
                logger.warning("Invalid token request - missing EVSE ID or EV pseudonym")
                return
            
            # Check if EVSE is authorized
            if evse_id not in self.authorized_evses:
                logger.warning(f"Token request from unauthorized EVSE: {evse_id}")
                return
            
            # Apply policy and generate token
            policy_decision = await self._apply_authorization_policy(ev_pseudonym, evse_id, requested_energy_kwh)
            
            if policy_decision.authorized:
                # Issue outage token
                token = await self.outage_token_manager.issue_outage_token(
                    evse_id, ev_pseudonym, policy_decision.max_energy_kwh
                )
                
                if token:
                    # Send token response
                    response = {
                        "type": "TOKEN_RESPONSE",
                        "node_id": self.node_id,
                        "status": "GRANTED",
                        "token": token.to_dict(),
                        "policy_applied": policy_decision.policy_applied,
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    
                    # Send response
                    response_data = json.dumps(response).encode()
                    self.discovery_socket.sendto(response_data, sender_addr)
                    
                    logger.info(f"Outage token granted: {token.token_id} for {evse_id}")
                else:
                    logger.error("Failed to issue outage token")
            else:
                # Send denial response
                response = {
                    "type": "TOKEN_RESPONSE", 
                    "node_id": self.node_id,
                    "status": "DENIED",
                    "reason": policy_decision.reason,
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                response_data = json.dumps(response).encode()
                self.discovery_socket.sendto(response_data, sender_addr)
                
                logger.info(f"Token request denied: {policy_decision.reason}")
                
        except Exception as e:
            logger.error(f"Token request handling error: {e}")
    
    async def _handle_authorization_request(self, message: Dict[str, Any], sender_addr: tuple):
        """Handle direct authorization request"""
        try:
            evse_id = message.get("evse_id")
            ev_id = message.get("ev_id")
            certificate = message.get("certificate")
            requested_energy_kwh = message.get("requested_energy_kwh", 25.0)
            
            # Validate certificate (simplified)
            if not self._validate_ev_certificate(certificate):
                response = {
                    "type": "AUTHORIZATION_RESPONSE",
                    "status": "DENIED",
                    "reason": "Invalid certificate"
                }
            else:
                # Apply policy
                policy_decision = await self._apply_authorization_policy(ev_id, evse_id, requested_energy_kwh)
                
                if policy_decision.authorized:
                    session_id = f"LOCAL_{self.node_id}_{int(time.time())}"
                    
                    # Create local session
                    self.active_sessions[session_id] = {
                        "session_id": session_id,
                        "evse_id": evse_id,
                        "ev_id": ev_id,
                        "start_time": datetime.utcnow(),
                        "policy_applied": policy_decision.policy_applied,
                        "max_energy_kwh": policy_decision.max_energy_kwh,
                        "max_power_kw": policy_decision.max_power_kw,
                        "expiry_time": policy_decision.expiry_time
                    }
                    
                    response = {
                        "type": "AUTHORIZATION_RESPONSE",
                        "status": "AUTHORIZED",
                        "session_id": session_id,
                        "max_energy_kwh": policy_decision.max_energy_kwh,
                        "max_power_kw": policy_decision.max_power_kw,
                        "expiry_time": policy_decision.expiry_time.isoformat(),
                        "tariff_per_kwh": self.authorization_policies[policy_decision.policy_applied].energy_price_kwh
                    }
                    
                    logger.info(f"Local authorization granted: {session_id}")
                else:
                    response = {
                        "type": "AUTHORIZATION_RESPONSE",
                        "status": "DENIED",
                        "reason": policy_decision.reason
                    }
            
            # Send response
            response_data = json.dumps(response).encode()
            self.discovery_socket.sendto(response_data, sender_addr)
            
        except Exception as e:
            logger.error(f"Authorization request handling error: {e}")
    
    async def _handle_session_update(self, message: Dict[str, Any], sender_addr: tuple):
        """Handle session status update"""
        try:
            session_id = message.get("session_id")
            status = message.get("status")
            energy_delivered_kwh = message.get("energy_delivered_kwh")
            
            if session_id in self.active_sessions:
                session = self.active_sessions[session_id]
                session["last_update"] = datetime.utcnow()
                session["status"] = status
                
                if energy_delivered_kwh is not None:
                    session["energy_delivered_kwh"] = energy_delivered_kwh
                
                if status == "COMPLETED":
                    session["end_time"] = datetime.utcnow()
                    logger.info(f"Session completed: {session_id} ({energy_delivered_kwh}kWh)")
                
                logger.debug(f"Session updated: {session_id} - {status}")
            
        except Exception as e:
            logger.error(f"Session update handling error: {e}")
    
    async def _apply_authorization_policy(self, ev_id: str, evse_id: str, 
                                        requested_energy_kwh: float) -> PolicyDecision:
        """Apply authorization policy and make decision"""
        try:
            # Select appropriate policy
            policy = self._select_policy(ev_id, evse_id, requested_energy_kwh)
            
            # Check current conditions
            current_hour = datetime.utcnow().hour
            
            # Apply policy checks
            if policy.allowed_hours and current_hour not in policy.allowed_hours:
                return PolicyDecision(
                    decision_id=f"DEC_{int(time.time())}",
                    ev_id=ev_id,
                    evse_id=evse_id,
                    policy_applied=policy.policy_id,
                    authorized=False,
                    max_energy_kwh=None,
                    max_power_kw=None,
                    expiry_time=None,
                    reason="Outside allowed hours",
                    timestamp=datetime.utcnow()
                )
            
            # Check energy limits
            authorized_energy = min(requested_energy_kwh, policy.max_energy_kwh)
            
            # Check concurrent session limits
            active_count = len([s for s in self.active_sessions.values() 
                              if s.get("status") not in ["COMPLETED", "EXPIRED"]])
            
            if active_count >= 5:  # Max 5 concurrent sessions
                return PolicyDecision(
                    decision_id=f"DEC_{int(time.time())}",
                    ev_id=ev_id,
                    evse_id=evse_id,
                    policy_applied=policy.policy_id,
                    authorized=False,
                    max_energy_kwh=None,
                    max_power_kw=None,
                    expiry_time=None,
                    reason="Maximum concurrent sessions reached",
                    timestamp=datetime.utcnow()
                )
            
            # Authorization granted
            expiry_time = datetime.utcnow() + timedelta(minutes=policy.max_duration_minutes)
            
            decision = PolicyDecision(
                decision_id=f"DEC_{int(time.time())}",
                ev_id=ev_id,
                evse_id=evse_id,
                policy_applied=policy.policy_id,
                authorized=True,
                max_energy_kwh=authorized_energy,
                max_power_kw=policy.max_power_kw,
                expiry_time=expiry_time,
                reason="Policy conditions met",
                timestamp=datetime.utcnow()
            )
            
            # Store decision for audit
            self.policy_decisions.append(decision)
            
            # Trim old decisions
            if len(self.policy_decisions) > 1000:
                self.policy_decisions = self.policy_decisions[-500:]
            
            return decision
            
        except Exception as e:
            logger.error(f"Policy application error: {e}")
            
            return PolicyDecision(
                decision_id=f"DEC_{int(time.time())}",
                ev_id=ev_id,
                evse_id=evse_id,
                policy_applied="ERROR",
                authorized=False,
                max_energy_kwh=None,
                max_power_kw=None,
                expiry_time=None,
                reason=f"Policy error: {str(e)}",
                timestamp=datetime.utcnow()
            )
    
    def _select_policy(self, ev_id: str, evse_id: str, requested_energy_kwh: float) -> AuthorizationPolicy:
        """Select appropriate authorization policy"""
        try:
            # Policy selection logic
            if requested_energy_kwh <= 10.0:
                return self.authorization_policies["EMERGENCY"]
            elif requested_energy_kwh <= 30.0:
                return self.authorization_policies["STANDARD"]
            else:
                return self.authorization_policies["GENEROUS"]
                
        except Exception as e:
            logger.error(f"Policy selection error: {e}")
            return self.authorization_policies["EMERGENCY"]  # Default to most restrictive
    
    def _validate_ev_certificate(self, certificate: str) -> bool:
        """Validate EV certificate"""
        try:
            if not certificate:
                return False
                
            # In production, would perform full certificate validation
            # For simulation, basic checks
            if isinstance(certificate, str) and len(certificate) > 50:
                return True
                
            return False
            
        except Exception as e:
            logger.error(f"Certificate validation error: {e}")
            return False
    
    async def _process_token_requests(self):
        """Process pending token requests from queue"""
        try:
            while not self.message_queue.empty():
                try:
                    request = self.message_queue.get_nowait()
                    await self._handle_token_request(request["message"], request["sender"])
                except queue.Empty:
                    break
                    
        except Exception as e:
            logger.error(f"Token request processing error: {e}")
    
    def _cleanup_stale_devices(self):
        """Remove devices that haven't been seen recently"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(minutes=10)
            stale_devices = []
            
            for device_id, device in self.discovered_devices.items():
                if device.last_seen < cutoff_time:
                    stale_devices.append(device_id)
            
            for device_id in stale_devices:
                del self.discovered_devices[device_id]
                if device_id in self.authorized_evses:
                    self.authorized_evses.remove(device_id)
                logger.info(f"Removed stale device: {device_id}")
                
        except Exception as e:
            logger.error(f"Device cleanup error: {e}")
    
    async def _collect_telemetry(self):
        """Collect and report telemetry data"""
        try:
            from ...data.metering import TelemetryData, TelemetryType
            
            # Collect policy node telemetry
            telemetry_points = [
                TelemetryData(
                    source_id=self.node_id,
                    telemetry_type=TelemetryType.STATUS,
                    timestamp=datetime.utcnow(),
                    value=self.current_state.value,
                    unit="",
                    metadata={"sidelink_status": self.sidelink_status.value}
                ),
                TelemetryData(
                    source_id=self.node_id,
                    telemetry_type=TelemetryType.PERFORMANCE,
                    timestamp=datetime.utcnow(),
                    value=len(self.discovered_devices),
                    unit="count",
                    metadata={"metric": "discovered_devices"}
                ),
                TelemetryData(
                    source_id=self.node_id,
                    telemetry_type=TelemetryType.PERFORMANCE,
                    timestamp=datetime.utcnow(),
                    value=len(self.active_sessions),
                    unit="count",
                    metadata={"metric": "active_sessions"}
                )
            ]
            
            # Add to telemetry collector
            for telemetry in telemetry_points:
                self.telemetry_collector.add_telemetry_data(telemetry)
                
        except Exception as e:
            logger.error(f"Telemetry collection error: {e}")
    
    async def _enforce_policies(self):
        """Enforce policy compliance for active sessions"""
        try:
            now = datetime.utcnow()
            expired_sessions = []
            
            for session_id, session in self.active_sessions.items():
                # Check expiry
                if "expiry_time" in session and now > session["expiry_time"]:
                    expired_sessions.append(session_id)
                    continue
                
                # Check energy limits
                if "energy_delivered_kwh" in session and "max_energy_kwh" in session:
                    if session["energy_delivered_kwh"] > session["max_energy_kwh"]:
                        logger.warning(f"Energy limit exceeded for session: {session_id}")
                        # Could send stop command here
            
            # Remove expired sessions
            for session_id in expired_sessions:
                session = self.active_sessions[session_id]
                session["status"] = "EXPIRED"
                session["end_time"] = now
                del self.active_sessions[session_id]
                logger.info(f"Session expired: {session_id}")
                
        except Exception as e:
            logger.error(f"Policy enforcement error: {e}")
    
    async def _update_node_status(self):
        """Update policy node status based on current conditions"""
        try:
            # Check sidelink health
            if self.sidelink_status == SidelinkStatus.ERROR:
                self._change_state(PolicyNodeState.DEGRADED)
            elif len(self.discovered_devices) == 0:
                # No devices found - might be isolated
                if self.current_state == PolicyNodeState.ACTIVE:
                    logger.warning("No devices discovered - possible isolation")
            else:
                if self.current_state == PolicyNodeState.DEGRADED:
                    self._change_state(PolicyNodeState.ACTIVE)
                    
        except Exception as e:
            logger.error(f"Status update error: {e}")
    
    def _change_state(self, new_state: PolicyNodeState):
        """Change policy node state"""
        if new_state != self.current_state:
            old_state = self.current_state
            self.current_state = new_state
            logger.info(f"Policy Node state change: {old_state.value} -> {new_state.value}")
    
    # Public API methods
    def get_status(self) -> Dict[str, Any]:
        """Get policy node status"""
        return {
            "node_id": self.node_id,
            "state": self.current_state.value,
            "sidelink_status": self.sidelink_status.value,
            "discovered_devices": len(self.discovered_devices),
            "authorized_evses": len(self.authorized_evses),
            "active_sessions": len(self.active_sessions),
            "policies": list(self.authorization_policies.keys()),
            "coverage_radius_m": self.coverage_radius_m
        }
    
    def get_discovered_devices(self) -> List[Dict[str, Any]]:
        """Get list of discovered devices"""
        return [
            {
                "device_id": device.device_id,
                "device_type": device.device_type,
                "signal_strength": device.signal_strength,
                "last_seen": device.last_seen.isoformat(),
                "capabilities": device.capabilities
            }
            for device in self.discovered_devices.values()
        ]
    
    def get_active_sessions(self) -> List[Dict[str, Any]]:
        """Get list of active sessions"""
        sessions = []
        for session in self.active_sessions.values():
            session_copy = session.copy()
            # Convert datetime objects to strings
            for key in ["start_time", "expiry_time", "last_update", "end_time"]:
                if key in session_copy and isinstance(session_copy[key], datetime):
                    session_copy[key] = session_copy[key].isoformat()
            sessions.append(session_copy)
        return sessions
    
    def get_policy_decisions(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent policy decisions"""
        recent_decisions = self.policy_decisions[-limit:] if self.policy_decisions else []
        return [
            {
                **asdict(decision),
                "timestamp": decision.timestamp.isoformat(),
                "expiry_time": decision.expiry_time.isoformat() if decision.expiry_time else None
            }
            for decision in recent_decisions
        ]
    
    async def stop(self):
        """Stop policy node controller"""
        try:
            logger.info("Stopping Policy Node Controller")
            self.running = False
            
            # Cancel background tasks
            if self.broadcast_task:
                self.broadcast_task.cancel()
            if self.discovery_task:
                self.discovery_task.cancel()
            if self.monitoring_task:
                self.monitoring_task.cancel()
            
            # Stop telemetry collection
            if self.telemetry_collector:
                await self.telemetry_collector.stop_collection()
            
            # Close sockets
            if self.sidelink_socket:
                self.sidelink_socket.close()
            if self.discovery_socket:
                self.discovery_socket.close()
            
            self._change_state(PolicyNodeState.OFFLINE)
            logger.info("Policy Node Controller stopped")
            
        except Exception as e:
            logger.error(f"Policy Node stop error: {e}")

# Main Policy Node Application
class PolicyNodeApplication:
    """Main Policy Node Application"""
    
    def __init__(self, config_path: str):
        # Load configuration
        self.config = load_config(config_path)
        
        # Setup logging
        setup_logging(self.config.get('logging', {}))
        
        # Create policy node controller
        self.policy_controller = PolicyNodeController(self.config.get('policy_node', {}))
        
        # Application state
        self.running = False
        
        logger.info("Policy Node Application initialized")
    
    async def start(self):
        """Start policy node application"""
        try:
            logger.info("Starting Policy Node Application")
            self.running = True
            
            # Start policy controller
            await self.policy_controller.start()
            
            # Keep running until stopped
            while self.running:
                await asyncio.sleep(1)
                
        except Exception as e:
            logger.error(f"Policy Node Application error: {e}")
        finally:
            await self.stop()
    
    async def stop(self):
        """Stop policy node application"""
        logger.info("Stopping Policy Node Application")
        self.running = False
        
        if self.policy_controller:
            await self.policy_controller.stop()

# CLI entry point
async def main():
    """Main entry point for Policy Node"""
    import argparse
    
    parser = argparse.ArgumentParser(description='PQ-V2G Policy Node')
    parser.add_argument('--config', required=True, help='Configuration file path')
    
    args = parser.parse_args()
    
    # Create and start Policy Node application
    app = PolicyNodeApplication(args.config)
    
    try:
        await app.start()
    except KeyboardInterrupt:
        logger.info("Policy Node interrupted by user")
        await app.stop()

if __name__ == "__main__":
    asyncio.run(main())

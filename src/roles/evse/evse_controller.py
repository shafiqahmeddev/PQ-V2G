"""
PQ-V2G EVSE Controller Implementation
====================================

This module implements the Electric Vehicle Supply Equipment (EVSE) controller
for the PQ-V2G system, coordinating ISO 15118 communication, OCPP reporting,
energy metering, and post-quantum security features.

Key Features:
- ISO 15118-20 and OCPP 2.0.1 protocol coordination
- Post-quantum TLS and certificate management
- Real-time energy metering and billing
- Load management and charging profiles
- Fault detection and safety monitoring
- Remote monitoring and control capabilities

Author: Shafiq Ahmed <s.ahmed@essex.ac.uk>
Institution: University of Essex
License: MIT
"""

import os
import json
import time
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict
from enum import Enum
import threading

# PQ-V2G imports
from ...crypto.pq_crypto import PQCryptoManager, create_crypto_manager
from ...identity.pq_ca import PQCertificateAuthority, CertificateInfo
from ...session.pq_tls import PQTLSContext, PQTLSServer, create_tls_context, create_tls_server
from ...control.authorization import AuthorizationEngine, create_authorization_engine
from ...data.metering import EnergyMeter, MeterType, SessionMeterData, TelemetryCollector, SessionReconciliation
from ...protocols.iso15118.evse_server import ISO15118EVSEServer, EVSEState, ConnectorType
from ...protocols.ocpp.ocpp_client import OCPPClient
from ...utils.config_loader import load_config
from ...utils.logger import setup_logging, get_logger

# Configure logging
logger = logging.getLogger(__name__)

class EVSEOperationalStatus(Enum):
    """EVSE operational status"""
    OPERATIVE = "Operative"
    INOPERATIVE = "Inoperative"

class ChargingSessionPhase(Enum):
    """Charging session phases"""
    IDLE = "idle"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    PREPARATION = "preparation"
    CHARGING = "charging"
    SUSPENSION = "suspension"
    TERMINATION = "termination"
    COMPLETED = "completed"

@dataclass
class EVSEStatus:
    """EVSE status information"""
    evse_id: str
    state: EVSEState
    operational_status: EVSEOperationalStatus
    connector_status: str
    current_power_kw: float
    energy_delivered_kwh: float
    active_session: Optional[str]
    last_update: datetime

class EVSEController:
    """Main EVSE Controller coordinating all subsystems"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # EVSE configuration
        self.evse_id = config['evse_id']
        self.evse_config = config.get('evse_config', {})
        
        # Initialize logging
        self.logger = get_logger(f'pq_v2g.evse.{self.evse_id}')
        
        # Core components
        self.crypto_manager = create_crypto_manager(config.get('crypto', {}))
        self.tls_context = None
        self.tls_server = None
        
        # Protocol handlers
        self.iso15118_server = None
        self.ocpp_client = None
        
        # Control and data components
        self.auth_engine = None
        self.energy_meter = None
        self.telemetry_collector = None
        self.session_reconciliation = None
        
        # EVSE state
        self.current_state = EVSEState.UNAVAILABLE
        self.operational_status = EVSEOperationalStatus.INOPERATIVE
        self.connector_status = "Unavailable"
        
        # Session management
        self.active_session_id = None
        self.session_phase = ChargingSessionPhase.IDLE
        self.session_start_time = None
        self.current_power_kw = 0.0
        self.total_energy_kwh = 0.0
        
        # Performance monitoring
        self.session_metrics = {}
        self.fault_conditions = {}
        
        # Threading
        self.running = False
        self.monitor_task = None
        
        self.logger.info(f"EVSE Controller initialized: {self.evse_id}")
    
    async def initialize(self, ca: PQCertificateAuthority):
        """Initialize EVSE controller with all subsystems"""
        try:
            self.logger.info("Initializing EVSE controller")
            
            # Initialize TLS context
            tls_config = self.config.get('tls', {})
            tls_config['mutual_auth_required'] = True
            self.tls_context = create_tls_context(tls_config, self.crypto_manager, ca)
            
            # Load EVSE certificates
            evse_cert_pem = ca.issue_evse_certificate(
                self.evse_id,
                self.crypto_manager.generate_dsa_keypair("ML-DSA-65")[0]
            )
            
            cert_chain = ca.get_certificate_chain(
                json.loads(evse_cert_pem)["certificate"]["serial_number"]
            )
            
            self.tls_context.load_certificate_chain(cert_chain)
            
            # Initialize authorization engine
            self.auth_engine = create_authorization_engine(self.config, self.crypto_manager)
            
            # Initialize energy meter
            meter_config = self.config.get('metering', {})
            self.energy_meter = EnergyMeter(
                meter_id=f"{self.evse_id}_METER",
                meter_type=MeterType.DC_METER,
                config=meter_config
            )
            
            # Initialize telemetry collector
            self.telemetry_collector = TelemetryCollector(self.config.get('telemetry', {}))
            
            # Initialize session reconciliation
            self.session_reconciliation = SessionReconciliation(self.config.get('reconciliation', {}))
            
            # Initialize ISO 15118 server
            self.iso15118_server = ISO15118EVSEServer(self.config.get('iso15118', {}), self)
            self.iso15118_server.set_authorization_engine(self.auth_engine)
            self.iso15118_server.set_energy_meter(self.energy_meter)
            
            # Initialize OCPP client
            ocpp_config = self.config.get('ocpp', {})
            ocpp_config['charge_point_id'] = self.evse_id
            self.ocpp_client = OCPPClient(ocpp_config, self)
            
            # Start TLS server for ISO 15118 communication
            tls_port = self.config.get('iso15118_port', 8444)
            self.tls_server = create_tls_server(self.tls_context, "0.0.0.0", tls_port)
            
            # Update operational status
            self.operational_status = EVSEOperationalStatus.OPERATIVE
            self.current_state = EVSEState.AVAILABLE
            self.connector_status = "Available"
            
            self.logger.info("EVSE controller initialization completed")
            return True
            
        except Exception as e:
            self.logger.error(f"EVSE controller initialization failed: {e}")
            return False
    
    async def start(self):
        """Start EVSE controller and all subsystems"""
        try:
            if self.running:
                return
            
            self.logger.info("Starting EVSE controller")
            self.running = True
            
            # Start telemetry collection
            await self.telemetry_collector.start_collection()
            
            # Connect to CSMS via OCPP
            if await self.ocpp_client.connect():
                self.logger.info("Connected to CSMS via OCPP")
                
                # Send initial status notification
                await self.ocpp_client.send_status_notification(
                    evse_id=1,
                    connector_id=1,
                    status=self.connector_status
                )
            else:
                self.logger.error("Failed to connect to CSMS")
            
            # Start TLS server for ISO 15118
            if self.tls_server:
                asyncio.create_task(self.tls_server.start())
                self.logger.info(f"ISO 15118 TLS server started on port {self.config.get('iso15118_port', 8444)}")
            
            # Start monitoring task
            self.monitor_task = asyncio.create_task(self._monitoring_loop())
            
            self.logger.info("EVSE controller started successfully")
            
        except Exception as e:
            self.logger.error(f"EVSE controller start failed: {e}")
            await self.stop()
    
    async def stop(self):
        """Stop EVSE controller and all subsystems"""
        try:
            self.logger.info("Stopping EVSE controller")
            self.running = False
            
            # Stop monitoring
            if self.monitor_task:
                self.monitor_task.cancel()
                try:
                    await self.monitor_task
                except asyncio.CancelledError:
                    pass
            
            # Stop telemetry collection
            if self.telemetry_collector:
                await self.telemetry_collector.stop_collection()
            
            # Disconnect OCPP
            if self.ocpp_client:
                await self.ocpp_client.disconnect()
            
            # Update status
            self.operational_status = EVSEOperationalStatus.INOPERATIVE
            self.current_state = EVSEState.UNAVAILABLE
            
            self.logger.info("EVSE controller stopped")
            
        except Exception as e:
            self.logger.error(f"EVSE controller stop error: {e}")
    
    async def _monitoring_loop(self):
        """Main monitoring and maintenance loop"""
        try:
            while self.running:
                await asyncio.sleep(10)  # 10-second monitoring interval
                
                # Update telemetry
                await self._collect_telemetry()
                
                # Check fault conditions
                await self._check_faults()
                
                # Update OCPP status if needed
                await self._update_ocpp_status()
                
                # Process reconciliations
                await self._process_reconciliations()
                
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.error(f"Monitoring loop error: {e}")
    
    async def _collect_telemetry(self):
        """Collect and report telemetry data"""
        try:
            from ...data.metering import TelemetryData, TelemetryType
            
            # Collect basic telemetry
            telemetry_points = [
                TelemetryData(
                    source_id=self.evse_id,
                    telemetry_type=TelemetryType.POWER_METER,
                    timestamp=datetime.utcnow(),
                    value=self.current_power_kw,
                    unit="kW",
                    session_id=self.active_session_id
                ),
                TelemetryData(
                    source_id=self.evse_id,
                    telemetry_type=TelemetryType.ENERGY_METER,
                    timestamp=datetime.utcnow(),
                    value=self.total_energy_kwh,
                    unit="kWh",
                    session_id=self.active_session_id
                ),
                TelemetryData(
                    source_id=self.evse_id,
                    telemetry_type=TelemetryType.STATUS,
                    timestamp=datetime.utcnow(),
                    value=self.current_state.value,
                    unit="",
                    session_id=self.active_session_id
                )
            ]
            
            # Add to telemetry collector
            for telemetry in telemetry_points:
                self.telemetry_collector.add_telemetry_data(telemetry)
            
        except Exception as e:
            self.logger.error(f"Telemetry collection error: {e}")
    
    async def _check_faults(self):
        """Check for fault conditions"""
        try:
            # Check for over-temperature
            # Check for ground fault
            # Check for over-current
            # Check communication faults
            
            # Placeholder fault detection
            current_faults = {}
            
            # Check if new faults detected
            new_faults = set(current_faults.keys()) - set(self.fault_conditions.keys())
            cleared_faults = set(self.fault_conditions.keys()) - set(current_faults.keys())
            
            # Handle new faults
            for fault in new_faults:
                self.logger.warning(f"Fault detected: {fault}")
                await self._handle_fault(fault, current_faults[fault])
            
            # Handle cleared faults
            for fault in cleared_faults:
                self.logger.info(f"Fault cleared: {fault}")
                await self._handle_fault_cleared(fault)
            
            self.fault_conditions = current_faults
            
        except Exception as e:
            self.logger.error(f"Fault checking error: {e}")
    
    async def _handle_fault(self, fault_type: str, fault_data: Dict[str, Any]):
        """Handle detected fault condition"""
        try:
            # Stop charging if safety-critical fault
            if fault_type in ["over_current", "ground_fault", "over_temperature"]:
                if self.current_state == EVSEState.CHARGING:
                    await self.emergency_stop()
                
                # Set EVSE to faulted state
                await self._change_state(EVSEState.FAULTED)
            
            # Report fault via OCPP
            if self.ocpp_client and self.ocpp_client.is_connected():
                await self.ocpp_client.send_status_notification(
                    evse_id=1,
                    connector_id=1,
                    status="Faulted"
                )
            
        except Exception as e:
            self.logger.error(f"Fault handling error: {e}")
    
    async def _handle_fault_cleared(self, fault_type: str):
        """Handle fault condition cleared"""
        try:
            # If no remaining faults, return to available state
            if not self.fault_conditions:
                await self._change_state(EVSEState.AVAILABLE)
                
                # Report status via OCPP
                if self.ocpp_client and self.ocpp_client.is_connected():
                    await self.ocpp_client.send_status_notification(
                        evse_id=1,
                        connector_id=1,
                        status="Available"
                    )
            
        except Exception as e:
            self.logger.error(f"Fault cleared handling error: {e}")
    
    async def _update_ocpp_status(self):
        """Update OCPP status if changed"""
        try:
            # Implementation would track status changes and report via OCPP
            pass
        except Exception as e:
            self.logger.error(f"OCPP status update error: {e}")
    
    async def _process_reconciliations(self):
        """Process pending session reconciliations"""
        try:
            pending = self.session_reconciliation.get_pending_reconciliations()
            
            for session_id in pending:
                report = await self.session_reconciliation.process_reconciliation(session_id)
                if report:
                    self.logger.info(f"Session reconciled: {session_id}")
                    # Send reconciliation report via OCPP if needed
            
            # Cleanup expired reconciliations
            self.session_reconciliation.cleanup_expired_reconciliations()
            
        except Exception as e:
            self.logger.error(f"Reconciliation processing error: {e}")
    
    async def start_charging_session(self, session_id: str):
        """Start new charging session"""
        try:
            if self.current_state != EVSEState.CHARGING:
                return
            
            self.active_session_id = session_id
            self.session_phase = ChargingSessionPhase.CHARGING
            self.session_start_time = datetime.utcnow()
            
            # Report transaction start via OCPP
            if self.ocpp_client and self.ocpp_client.is_connected():
                await self.ocpp_client.send_transaction_event(
                    event_type="Started",
                    transaction_id=session_id,
                    trigger_reason="CablePluggedIn",
                    evse={"id": 1, "connectorId": 1}
                )
            
            self.logger.info(f"Charging session started: {session_id}")
            
        except Exception as e:
            self.logger.error(f"Charging session start error: {e}")
    
    async def stop_charging_session(self, session_id: str):
        """Stop active charging session"""
        try:
            if self.active_session_id != session_id:
                self.logger.warning(f"Attempted to stop non-active session: {session_id}")
                return
            
            self.session_phase = ChargingSessionPhase.TERMINATION
            
            # Report transaction end via OCPP
            if self.ocpp_client and self.ocpp_client.is_connected():
                meter_values = []
                if self.energy_meter and self.energy_meter.last_reading:
                    reading = self.energy_meter.last_reading
                    meter_values = [{
                        "timestamp": reading.timestamp.isoformat(),
                        "sampledValue": [
                            {"value": reading.energy_kwh, "measurand": "Energy.Active.Import.Register"},
                            {"value": reading.power_kw, "measurand": "Power.Active.Import"}
                        ]
                    }]
                
                await self.ocpp_client.send_transaction_event(
                    event_type="Ended",
                    transaction_id=session_id,
                    trigger_reason="StopAuthorized",
                    evse={"id": 1, "connectorId": 1},
                    meter_value=meter_values
                )
            
            # Clear session data
            self.active_session_id = None
            self.session_phase = ChargingSessionPhase.COMPLETED
            self.current_power_kw = 0.0
            
            await self._change_state(EVSEState.FINISHING)
            
            self.logger.info(f"Charging session stopped: {session_id}")
            
        except Exception as e:
            self.logger.error(f"Charging session stop error: {e}")
    
    async def process_session_reconciliation(self, session_data: SessionMeterData):
        """Process session for reconciliation"""
        try:
            # Add to reconciliation system
            success = self.session_reconciliation.add_session_for_reconciliation(session_data)
            
            if success:
                self.logger.info(f"Session added for reconciliation: {session_data.session_id}")
            else:
                self.logger.error(f"Failed to add session for reconciliation: {session_data.session_id}")
            
        except Exception as e:
            self.logger.error(f"Session reconciliation error: {e}")
    
    async def emergency_stop(self):
        """Emergency stop all charging"""
        try:
            self.logger.warning("Emergency stop triggered")
            
            # Stop charging immediately
            self.current_power_kw = 0.0
            
            # Stop energy meter
            if self.energy_meter and self.energy_meter.is_active:
                self.energy_meter.end_session()
            
            # Set faulted state
            await self._change_state(EVSEState.FAULTED)
            
            # Report emergency stop via OCPP
            if self.ocpp_client and self.ocpp_client.is_connected():
                await self.ocpp_client.send_status_notification(
                    evse_id=1,
                    connector_id=1,
                    status="Faulted"
                )
            
        except Exception as e:
            self.logger.error(f"Emergency stop error: {e}")
    
    async def _change_state(self, new_state: EVSEState):
        """Change EVSE state with proper notifications"""
        try:
            if new_state == self.current_state:
                return
            
            old_state = self.current_state
            self.current_state = new_state
            
            # Map EVSE state to connector status
            status_map = {
                EVSEState.AVAILABLE: "Available",
                EVSEState.OCCUPIED: "Occupied", 
                EVSEState.CHARGING: "Occupied",
                EVSEState.SUSPENDED_EVSE: "Occupied",
                EVSEState.SUSPENDED_EV: "Occupied",
                EVSEState.FINISHING: "Occupied",
                EVSEState.RESERVED: "Reserved",
                EVSEState.UNAVAILABLE: "Unavailable",
                EVSEState.FAULTED: "Faulted"
            }
            
            self.connector_status = status_map.get(new_state, "Unavailable")
            
            self.logger.info(f"EVSE state change: {old_state.value} -> {new_state.value}")
            
            # Report status change via OCPP
            if self.ocpp_client and self.ocpp_client.is_connected():
                await self.ocpp_client.send_status_notification(
                    evse_id=1,
                    connector_id=1,
                    status=self.connector_status
                )
            
        except Exception as e:
            self.logger.error(f"State change error: {e}")
    
    # OCPP Remote Control Methods
    async def start_remote_transaction(self, evse_id: int, id_token: Dict[str, Any], 
                                     charging_profile: Optional[Dict[str, Any]] = None) -> bool:
        """Start remote transaction"""
        try:
            if self.current_state != EVSEState.AVAILABLE:
                return False
            
            # Simulate remote authorization
            await self._change_state(EVSEState.OCCUPIED)
            
            # Would implement actual remote start logic here
            self.logger.info(f"Remote transaction started for EVSE {evse_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Remote start transaction error: {e}")
            return False
    
    async def stop_remote_transaction(self, transaction_id: str) -> bool:
        """Stop remote transaction"""
        try:
            if self.active_session_id == transaction_id:
                await self.stop_charging_session(transaction_id)
                return True
            return False
            
        except Exception as e:
            self.logger.error(f"Remote stop transaction error: {e}")
            return False
    
    async def unlock_connector(self, evse_id: int, connector_id: int) -> bool:
        """Unlock connector"""
        try:
            # Simulate connector unlock
            self.logger.info(f"Connector unlocked: EVSE {evse_id}, Connector {connector_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Unlock connector error: {e}")
            return False
    
    async def schedule_reset(self, reset_type: str, evse_id: Optional[int] = None) -> bool:
        """Schedule EVSE reset"""
        try:
            self.logger.info(f"Reset scheduled: {reset_type}")
            
            if reset_type == "Soft":
                # Schedule soft reset
                asyncio.create_task(self._perform_soft_reset())
            elif reset_type == "Hard":
                # Schedule hard reset
                asyncio.create_task(self._perform_hard_reset())
            
            return True
            
        except Exception as e:
            self.logger.error(f"Reset scheduling error: {e}")
            return False
    
    async def change_availability(self, evse_id: Optional[int], operational_status: str) -> bool:
        """Change EVSE availability"""
        try:
            if operational_status == "Operative":
                self.operational_status = EVSEOperationalStatus.OPERATIVE
                if self.current_state == EVSEState.UNAVAILABLE:
                    await self._change_state(EVSEState.AVAILABLE)
            elif operational_status == "Inoperative":
                self.operational_status = EVSEOperationalStatus.INOPERATIVE
                await self._change_state(EVSEState.UNAVAILABLE)
            
            self.logger.info(f"Availability changed to: {operational_status}")
            return True
            
        except Exception as e:
            self.logger.error(f"Change availability error: {e}")
            return False
    
    async def get_configuration(self, keys: List[str]) -> Dict[str, Any]:
        """Get configuration values"""
        try:
            # Implementation would return actual configuration values
            known = {}
            unknown = []
            
            config_values = {
                "HeartbeatInterval": str(self.ocpp_client.heartbeat_interval) if self.ocpp_client else "300",
                "MeterValuesSampleInterval": "60",
                "ClockAlignedDataInterval": "900",
                "StopTransactionOnEVSideDisconnect": "true",
                "StopTransactionOnInvalidId": "true"
            }
            
            if not keys:  # Return all configuration
                known = config_values
            else:
                for key in keys:
                    if key in config_values:
                        known[key] = config_values[key]
                    else:
                        unknown.append(key)
            
            return {"known": known, "unknown": unknown}
            
        except Exception as e:
            self.logger.error(f"Get configuration error: {e}")
            return {"known": {}, "unknown": keys}
    
    async def change_configuration(self, key: str, value: str) -> bool:
        """Change configuration value"""
        try:
            # Implementation would update actual configuration
            self.logger.info(f"Configuration change: {key} = {value}")
            return True
            
        except Exception as e:
            self.logger.error(f"Change configuration error: {e}")
            return False
    
    async def clear_charging_profile(self, charging_profile_id: Optional[int]) -> bool:
        """Clear charging profile"""
        try:
            if self.iso15118_server:
                if charging_profile_id:
                    self.iso15118_server.remove_charging_profile(str(charging_profile_id))
                else:
                    # Clear all profiles
                    self.iso15118_server.charging_profiles.clear()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Clear charging profile error: {e}")
            return False
    
    async def set_charging_profile(self, evse_id: int, charging_profile: Dict[str, Any]) -> bool:
        """Set charging profile"""
        try:
            # Implementation would set actual charging profile
            self.logger.info(f"Charging profile set for EVSE {evse_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Set charging profile error: {e}")
            return False
    
    async def install_certificate(self, certificate: str, certificate_type: str) -> bool:
        """Install certificate"""
        try:
            # Implementation would install actual certificate
            self.logger.info(f"Certificate installed: {certificate_type}")
            return True
            
        except Exception as e:
            self.logger.error(f"Install certificate error: {e}")
            return False
    
    async def _perform_soft_reset(self):
        """Perform soft reset"""
        try:
            await asyncio.sleep(5)  # Delay before reset
            self.logger.info("Performing soft reset")
            # Implementation would restart software components
            
        except Exception as e:
            self.logger.error(f"Soft reset error: {e}")
    
    async def _perform_hard_reset(self):
        """Perform hard reset"""
        try:
            await asyncio.sleep(5)  # Delay before reset
            self.logger.info("Performing hard reset")
            # Implementation would restart entire system
            
        except Exception as e:
            self.logger.error(f"Hard reset error: {e}")
    
    def get_status(self) -> EVSEStatus:
        """Get current EVSE status"""
        return EVSEStatus(
            evse_id=self.evse_id,
            state=self.current_state,
            operational_status=self.operational_status,
            connector_status=self.connector_status,
            current_power_kw=self.current_power_kw,
            energy_delivered_kwh=self.total_energy_kwh,
            active_session=self.active_session_id,
            last_update=datetime.utcnow()
        )
    
    def get_detailed_status(self) -> Dict[str, Any]:
        """Get detailed status information"""
        status = self.get_status()
        
        return {
            "evse_id": status.evse_id,
            "state": status.state.value,
            "operational_status": status.operational_status.value,
            "connector_status": status.connector_status,
            "current_power_kw": status.current_power_kw,
            "energy_delivered_kwh": status.energy_delivered_kwh,
            "active_session": status.active_session,
            "session_phase": self.session_phase.value,
            "last_update": status.last_update.isoformat(),
            "fault_conditions": list(self.fault_conditions.keys()),
            "ocpp_connected": self.ocpp_client.is_connected() if self.ocpp_client else False,
            "iso15118_active": bool(self.iso15118_server and self.iso15118_server.active_sessions),
            "telemetry_stats": self.telemetry_collector.get_telemetry_stats() if self.telemetry_collector else {}
        }

# Main EVSE Application
class EVSEApplication:
    """Main EVSE Application"""
    
    def __init__(self, config_path: str, evse_id: str):
        # Load configuration
        self.config = load_config(config_path)
        self.config['evse_id'] = evse_id
        
        # Setup logging
        setup_logging(self.config.get('logging', {}))
        
        # Create EVSE controller
        self.evse_controller = EVSEController(self.config)
        
        # Application state
        self.running = False
        
        logger.info(f"EVSE Application initialized: {evse_id}")
    
    async def start(self):
        """Start EVSE application"""
        try:
            logger.info("Starting EVSE application")
            self.running = True
            
            # Initialize crypto and identity components (simulation)
            from ...identity.pq_ca import create_identity_plane
            ca, pseudonym_manager = create_identity_plane(self.config)
            
            # Initialize EVSE controller
            if not await self.evse_controller.initialize(ca):
                logger.error("EVSE controller initialization failed")
                return
            
            # Start EVSE controller
            await self.evse_controller.start()
            
            # Keep running until stopped
            while self.running:
                await asyncio.sleep(1)
                
        except Exception as e:
            logger.error(f"EVSE application error: {e}")
        finally:
            await self.stop()
    
    async def stop(self):
        """Stop EVSE application"""
        logger.info("Stopping EVSE application")
        self.running = False
        
        if self.evse_controller:
            await self.evse_controller.stop()

# CLI entry point
async def main():
    """Main entry point for EVSE controller"""
    import argparse
    
    parser = argparse.ArgumentParser(description='PQ-V2G EVSE Controller')
    parser.add_argument('--config', required=True, help='Configuration file path')
    parser.add_argument('--evse-id', required=True, help='EVSE ID')
    
    args = parser.parse_args()
    
    # Create and start EVSE application
    app = EVSEApplication(args.config, args.evse_id)
    
    try:
        await app.start()
    except KeyboardInterrupt:
        logger.info("EVSE application interrupted by user")
        await app.stop()

if __name__ == "__main__":
    asyncio.run(main())

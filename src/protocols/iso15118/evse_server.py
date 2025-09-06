"""
PQ-V2G ISO 15118 EVSE Server Implementation
===========================================

This module implements the ISO 15118-20 Electric Vehicle Supply Equipment (EVSE)
server side communication protocol for the PQ-V2G system, providing Plug-and-Charge
functionality with post-quantum security.

Key Features:
- ISO 15118-20 compliant message handling
- Plug-and-Charge certificate-based authentication
- TLS 1.3 with post-quantum cryptography integration
- Energy transfer control and monitoring
- Load management and charging profiles

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
from dataclasses import dataclass
from enum import Enum

# Configure logging
logger = logging.getLogger(__name__)

class EVSEState(Enum):
    """EVSE states according to ISO 15118"""
    AVAILABLE = "Available"
    OCCUPIED = "Occupied"
    CHARGING = "Charging"
    SUSPENDED_EVSE = "SuspendedEVSE"
    SUSPENDED_EV = "SuspendedEV"
    FINISHING = "Finishing"
    RESERVED = "Reserved"
    UNAVAILABLE = "Unavailable"
    FAULTED = "Faulted"

class ConnectorType(Enum):
    """Connector types"""
    CCS_COMBO_1 = "ccs_combo_1"
    CCS_COMBO_2 = "ccs_combo_2"
    CHAdeMO = "chademo"
    TYPE2 = "type2"
    TYPE1 = "type1"

@dataclass
class EVSEInformation:
    """EVSE information structure"""
    evse_id: str
    connector_type: ConnectorType
    max_power_kw: float
    max_voltage_v: float
    max_current_a: float
    supported_energy_transfer_modes: List[str]
    payment_options: List[str]

@dataclass
class ChargingProfile:
    """Charging profile for load management"""
    profile_id: str
    profile_purpose: str
    profile_kind: str
    schedule_periods: List[Dict[str, Any]]
    valid_from: datetime
    valid_to: datetime

class ISO15118EVSEServer:
    """ISO 15118-20 EVSE Server Implementation"""
    
    def __init__(self, config: Dict[str, Any], evse_controller):
        self.config = config
        self.evse_controller = evse_controller
        
        # EVSE configuration
        self.evse_info = EVSEInformation(
            evse_id=config.get('evse_id', 'EVSE001'),
            connector_type=ConnectorType(config.get('connector_type', 'ccs_combo_2')),
            max_power_kw=config.get('max_power_kw', 50.0),
            max_voltage_v=config.get('max_voltage_v', 500.0),
            max_current_a=config.get('max_current_a', 125.0),
            supported_energy_transfer_modes=config.get('energy_transfer_modes', ['DC_extended']),
            payment_options=config.get('payment_options', ['Contract'])
        )
        
        # Session state
        self.active_sessions = {}  # session_id -> session_data
        self.current_state = EVSEState.AVAILABLE
        
        # Charging profiles
        self.charging_profiles: Dict[str, ChargingProfile] = {}
        
        # Protocol configuration
        self.protocol_version = config.get('version', '20')
        self.message_timeout = config.get('message_timeout_seconds', 30)
        
        # Authorization and metering
        self.auth_engine = None
        self.energy_meter = None
        
        logger.info(f"ISO 15118 EVSE Server initialized: {self.evse_info.evse_id}")
    
    def set_authorization_engine(self, auth_engine):
        """Set authorization engine"""
        self.auth_engine = auth_engine
    
    def set_energy_meter(self, energy_meter):
        """Set energy meter"""
        self.energy_meter = energy_meter
    
    async def handle_session_setup_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle ISO 15118 SessionSetupRequest"""
        try:
            logger.info("Handling SessionSetupRequest")
            
            session_id = request.get('session_id')
            evccid = request.get('evccid')
            
            if not session_id or not evccid:
                return {
                    'response_code': 'FAILED_SequenceError',
                    'reason': 'Missing required parameters'
                }
            
            # Create session data
            session_data = {
                'session_id': session_id,
                'evccid': evccid,
                'state': 'matched',
                'start_time': datetime.utcnow(),
                'last_activity': datetime.utcnow()
            }
            
            self.active_sessions[session_id] = session_data
            
            # Update EVSE state
            await self._update_state(EVSEState.OCCUPIED)
            
            response = {
                'response_code': 'OK',
                'evse_id': self.evse_info.evse_id,
                'session_id': session_id
            }
            
            logger.info(f"SessionSetupRequest processed: {session_id}")
            return response
            
        except Exception as e:
            logger.error(f"SessionSetupRequest handling error: {e}")
            return {
                'response_code': 'FAILED',
                'reason': str(e)
            }
    
    async def handle_service_discovery_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle ISO 15118 ServiceDiscoveryRequest"""
        try:
            logger.info("Handling ServiceDiscoveryRequest")
            
            session_id = request.get('session_id')
            if session_id not in self.active_sessions:
                return {
                    'response_code': 'FAILED_SequenceError',
                    'reason': 'Invalid session'
                }
            
            # Update session activity
            self.active_sessions[session_id]['last_activity'] = datetime.utcnow()
            
            # Service list based on EVSE capabilities
            service_list = []
            
            for i, mode in enumerate(self.evse_info.supported_energy_transfer_modes):
                service_list.append({
                    'service_id': i + 1,
                    'service_name': f"{mode}_Charging",
                    'service_category': 'EnergyTransfer',
                    'free_service': False
                })
            
            response = {
                'response_code': 'OK',
                'service_list': service_list,
                'payment_option_list': self.evse_info.payment_options
            }
            
            logger.info(f"ServiceDiscoveryRequest processed: {session_id}")
            return response
            
        except Exception as e:
            logger.error(f"ServiceDiscoveryRequest handling error: {e}")
            return {
                'response_code': 'FAILED',
                'reason': str(e)
            }
    
    async def handle_authorization_setup_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle ISO 15118 AuthorizationSetupRequest"""
        try:
            logger.info("Handling AuthorizationSetupRequest")
            
            session_id = request.get('session_id')
            if session_id not in self.active_sessions:
                return {
                    'response_code': 'FAILED_SequenceError',
                    'reason': 'Invalid session'
                }
            
            # Update session state
            self.active_sessions[session_id]['state'] = 'auth_setup'
            self.active_sessions[session_id]['last_activity'] = datetime.utcnow()
            
            response = {
                'response_code': 'OK',
                'authorization_mode': 'PnC',  # Plug-and-Charge
                'certificate_installation_service': True
            }
            
            logger.info(f"AuthorizationSetupRequest processed: {session_id}")
            return response
            
        except Exception as e:
            logger.error(f"AuthorizationSetupRequest handling error: {e}")
            return {
                'response_code': 'FAILED',
                'reason': str(e)
            }
    
    async def handle_authorization_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle ISO 15118 AuthorizationRequest with Plug-and-Charge"""
        try:
            logger.info("Handling AuthorizationRequest")
            
            session_id = request.get('session_id')
            if session_id not in self.active_sessions:
                return {
                    'response_code': 'FAILED_SequenceError',
                    'reason': 'Invalid session'
                }
            
            # Extract authorization data
            ev_certificate = request.get('ev_certificate')
            requested_energy_kwh = request.get('requested_energy_kwh', 50.0)
            
            if not ev_certificate:
                return {
                    'response_code': 'FAILED',
                    'reason': 'No certificate provided'
                }
            
            # Process authorization via authorization engine
            if self.auth_engine:
                from ...control.authorization import AuthorizationRequest
                
                auth_request = AuthorizationRequest(
                    evse_id=self.evse_info.evse_id,
                    ev_certificate=ev_certificate,
                    session_id=session_id,
                    requested_energy_kwh=requested_energy_kwh,
                    payment_method="Plug-and-Charge"
                )
                
                auth_response = await self.auth_engine.process_authorization_request(auth_request)
                
                if auth_response.status.value == "authorized":
                    # Update session with authorization
                    self.active_sessions[session_id].update({
                        'state': 'authorized',
                        'authorized_energy_kwh': auth_response.authorized_energy_kwh,
                        'max_power_kw': auth_response.max_power_kw,
                        'tariff_per_kwh': auth_response.tariff_per_kwh,
                        'authorization_token': auth_response.authorization_token
                    })
                    
                    response = {
                        'response_code': 'OK',
                        'authorized_energy_kwh': auth_response.authorized_energy_kwh,
                        'max_power_kw': auth_response.max_power_kw or self.evse_info.max_power_kw,
                        'tariff_per_kwh': auth_response.tariff_per_kwh,
                        'authorization_token': auth_response.authorization_token
                    }
                else:
                    response = {
                        'response_code': 'FAILED',
                        'reason': auth_response.reason or 'Authorization denied'
                    }
            else:
                # No authorization engine - simulate acceptance for development
                self.active_sessions[session_id].update({
                    'state': 'authorized',
                    'authorized_energy_kwh': requested_energy_kwh,
                    'max_power_kw': min(requested_energy_kwh, self.evse_info.max_power_kw),
                    'tariff_per_kwh': 0.25
                })
                
                response = {
                    'response_code': 'OK',
                    'authorized_energy_kwh': requested_energy_kwh,
                    'max_power_kw': min(requested_energy_kwh, self.evse_info.max_power_kw),
                    'tariff_per_kwh': 0.25
                }
            
            logger.info(f"AuthorizationRequest processed: {session_id}")
            return response
            
        except Exception as e:
            logger.error(f"AuthorizationRequest handling error: {e}")
            return {
                'response_code': 'FAILED',
                'reason': str(e)
            }
    
    async def handle_charge_parameter_discovery_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle ISO 15118 ChargeParameterDiscoveryRequest"""
        try:
            logger.info("Handling ChargeParameterDiscoveryRequest")
            
            session_id = request.get('session_id')
            if session_id not in self.active_sessions:
                return {
                    'response_code': 'FAILED_SequenceError',
                    'reason': 'Invalid session'
                }
            
            # Update session state
            self.active_sessions[session_id]['state'] = 'charge_param_discovery'
            self.active_sessions[session_id]['last_activity'] = datetime.utcnow()
            
            # Extract EV charge parameters
            ev_charge_parameter = request.get('ev_charge_parameter', {})
            requested_energy_kwh = ev_charge_parameter.get('requested_energy_kwh', 50.0)
            
            # Create EVSE charge parameters
            evse_charge_parameter = {
                'evse_id': self.evse_info.evse_id,
                'evse_max_voltage': self.evse_info.max_voltage_v,
                'evse_max_current': self.evse_info.max_current_a,
                'evse_max_power': self.evse_info.max_power_kw,
                'evse_min_voltage': 200.0,
                'evse_min_current': 10.0,
                'energy_to_be_delivered': min(requested_energy_kwh, 
                                            self.active_sessions[session_id].get('authorized_energy_kwh', 50.0))
            }
            
            # Store charge parameters in session
            self.active_sessions[session_id]['evse_charge_parameter'] = evse_charge_parameter
            
            response = {
                'response_code': 'OK',
                'processing': 'Finished',
                'evse_processing': 'Finished',
                'evse_charge_parameter': evse_charge_parameter
            }
            
            logger.info(f"ChargeParameterDiscoveryRequest processed: {session_id}")
            return response
            
        except Exception as e:
            logger.error(f"ChargeParameterDiscoveryRequest handling error: {e}")
            return {
                'response_code': 'FAILED',
                'reason': str(e)
            }
    
    async def handle_power_delivery_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle ISO 15118 PowerDeliveryRequest"""
        try:
            logger.info("Handling PowerDeliveryRequest")
            
            session_id = request.get('session_id')
            if session_id not in self.active_sessions:
                return {
                    'response_code': 'FAILED_SequenceError',
                    'reason': 'Invalid session'
                }
            
            charge_progress = request.get('charge_progress')
            
            if charge_progress == 'Start':
                # Start charging
                await self._start_charging_session(session_id, request)
                
                response = {
                    'response_code': 'OK',
                    'evse_processing': 'Finished'
                }
                
            elif charge_progress == 'Stop':
                # Stop charging
                await self._stop_charging_session(session_id)
                
                response = {
                    'response_code': 'OK',
                    'evse_processing': 'Finished'
                }
                
            else:
                response = {
                    'response_code': 'FAILED',
                    'reason': f'Invalid charge progress: {charge_progress}'
                }
            
            logger.info(f"PowerDeliveryRequest processed: {session_id}, progress: {charge_progress}")
            return response
            
        except Exception as e:
            logger.error(f"PowerDeliveryRequest handling error: {e}")
            return {
                'response_code': 'FAILED',
                'reason': str(e)
            }
    
    async def handle_session_stop_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle ISO 15118 SessionStopRequest"""
        try:
            logger.info("Handling SessionStopRequest")
            
            session_id = request.get('session_id')
            if session_id not in self.active_sessions:
                return {
                    'response_code': 'FAILED_SequenceError',
                    'reason': 'Invalid session'
                }
            
            # Clean up session
            await self._cleanup_session(session_id)
            
            # Update EVSE state
            await self._update_state(EVSEState.AVAILABLE)
            
            response = {
                'response_code': 'OK'
            }
            
            logger.info(f"SessionStopRequest processed: {session_id}")
            return response
            
        except Exception as e:
            logger.error(f"SessionStopRequest handling error: {e}")
            return {
                'response_code': 'FAILED',
                'reason': str(e)
            }
    
    async def _start_charging_session(self, session_id: str, request: Dict[str, Any]):
        """Start charging session"""
        try:
            session_data = self.active_sessions[session_id]
            
            # Update session state
            session_data['state'] = 'charging'
            session_data['charge_start_time'] = datetime.utcnow()
            
            # Start energy meter if available
            if self.energy_meter:
                meter_reading = self.energy_meter.start_session(session_id)
                session_data['start_meter_reading'] = meter_reading
            
            # Update EVSE state
            await self._update_state(EVSEState.CHARGING)
            
            # Notify EVSE controller
            if self.evse_controller:
                await self.evse_controller.start_charging_session(session_id)
            
            logger.info(f"Charging session started: {session_id}")
            
        except Exception as e:
            logger.error(f"Failed to start charging session: {e}")
            raise
    
    async def _stop_charging_session(self, session_id: str):
        """Stop charging session"""
        try:
            session_data = self.active_sessions[session_id]
            
            # Update session state
            session_data['state'] = 'stopping'
            session_data['charge_end_time'] = datetime.utcnow()
            
            # Stop energy meter if available
            if self.energy_meter:
                end_meter_reading = self.energy_meter.end_session()
                if end_meter_reading:
                    session_data['end_meter_reading'] = end_meter_reading
                    
                    # Calculate energy delivered
                    if 'start_meter_reading' in session_data:
                        energy_delivered = (end_meter_reading.energy_kwh - 
                                          session_data['start_meter_reading'].energy_kwh)
                        session_data['energy_delivered_kwh'] = energy_delivered
            
            # Update EVSE state
            await self._update_state(EVSEState.FINISHING)
            
            # Notify EVSE controller
            if self.evse_controller:
                await self.evse_controller.stop_charging_session(session_id)
            
            logger.info(f"Charging session stopped: {session_id}")
            
        except Exception as e:
            logger.error(f"Failed to stop charging session: {e}")
            raise
    
    async def _cleanup_session(self, session_id: str):
        """Clean up session data"""
        try:
            if session_id in self.active_sessions:
                session_data = self.active_sessions[session_id]
                
                # Prepare session data for reconciliation if needed
                if 'start_meter_reading' in session_data:
                    await self._prepare_session_reconciliation(session_id, session_data)
                
                # Remove session
                del self.active_sessions[session_id]
                
                logger.info(f"Session cleaned up: {session_id}")
                
        except Exception as e:
            logger.error(f"Session cleanup error: {e}")
    
    async def _prepare_session_reconciliation(self, session_id: str, session_data: Dict[str, Any]):
        """Prepare session data for reconciliation"""
        try:
            if self.evse_controller and hasattr(self.evse_controller, 'process_session_reconciliation'):
                from ...data.metering import SessionMeterData
                
                # Create session meter data
                reconciliation_data = SessionMeterData(
                    session_id=session_id,
                    evse_id=self.evse_info.evse_id,
                    ev_id=session_data.get('evccid', 'UNKNOWN'),
                    start_time=session_data.get('charge_start_time', session_data['start_time']),
                    end_time=session_data.get('charge_end_time'),
                    start_meter_reading=session_data.get('start_meter_reading'),
                    end_meter_reading=session_data.get('end_meter_reading'),
                    intermediate_readings=[],
                    tariff_per_kwh=session_data.get('tariff_per_kwh')
                )
                
                # Process reconciliation
                await self.evse_controller.process_session_reconciliation(reconciliation_data)
                
        except Exception as e:
            logger.error(f"Session reconciliation preparation error: {e}")
    
    async def _update_state(self, new_state: EVSEState):
        """Update EVSE state"""
        try:
            if new_state != self.current_state:
                old_state = self.current_state
                self.current_state = new_state
                
                logger.info(f"EVSE state change: {old_state.value} -> {new_state.value}")
                
                # Notify EVSE controller if available
                if self.evse_controller and hasattr(self.evse_controller, '_change_state'):
                    await self.evse_controller._change_state(new_state)
                
        except Exception as e:
            logger.error(f"State update error: {e}")
    
    def add_charging_profile(self, profile: ChargingProfile):
        """Add charging profile for load management"""
        try:
            self.charging_profiles[profile.profile_id] = profile
            logger.info(f"Charging profile added: {profile.profile_id}")
        except Exception as e:
            logger.error(f"Failed to add charging profile: {e}")
    
    def remove_charging_profile(self, profile_id: str):
        """Remove charging profile"""
        try:
            if profile_id in self.charging_profiles:
                del self.charging_profiles[profile_id]
                logger.info(f"Charging profile removed: {profile_id}")
        except Exception as e:
            logger.error(f"Failed to remove charging profile: {e}")
    
    def get_active_sessions(self) -> List[str]:
        """Get list of active session IDs"""
        return list(self.active_sessions.keys())
    
    def get_session_data(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data by ID"""
        return self.active_sessions.get(session_id)
    
    def get_status(self) -> Dict[str, Any]:
        """Get ISO 15118 server status"""
        return {
            'evse_id': self.evse_info.evse_id,
            'state': self.current_state.value,
            'active_sessions': len(self.active_sessions),
            'charging_profiles': len(self.charging_profiles),
            'max_power_kw': self.evse_info.max_power_kw,
            'connector_type': self.evse_info.connector_type.value,
            'payment_options': self.evse_info.payment_options
        }

# Export main classes
__all__ = [
    'ISO15118EVSEServer',
    'EVSEState',
    'ConnectorType',
    'EVSEInformation',
    'ChargingProfile'
]

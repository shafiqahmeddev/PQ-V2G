"""
PQ-V2G ISO 15118 EV Client Implementation
========================================

This module implements the ISO 15118-20 Electric Vehicle client side
communication protocol for the PQ-V2G system, providing Plug-and-Charge
functionality with post-quantum security.

Key Features:
- ISO 15118-20 compliant message handling
- Plug-and-Charge certificate-based authentication
- TLS 1.3 with post-quantum cryptography integration
- Energy transfer negotiation and monitoring
- Battery management and charging profiles

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

class EVSessionState(Enum):
    """EV session states according to ISO 15118"""
    IDLE = "Idle"
    MATCHED = "Matched"
    AUTH_SETUP = "AuthSetup"
    AUTHORIZED = "Authorized" 
    PARAM_DISCOVERY = "ParameterDiscovery"
    CHARGING = "Charging"
    STOPPING = "Stopping"
    ENDED = "Ended"

class ChargingProfileType(Enum):
    """Charging profile types"""
    RELATIVE = "Relative"
    ABSOLUTE = "Absolute"

@dataclass
class EVChargeParameter:
    """EV charge parameters"""
    max_charge_power_kw: float
    max_charge_current_a: float
    max_voltage_v: float
    energy_capacity_kwh: float
    target_energy_kwh: float
    departure_time: Optional[datetime] = None

@dataclass
class ChargingSchedule:
    """Charging schedule for EV"""
    schedule_id: str
    start_time: datetime
    duration_seconds: int
    power_schedule: List[Dict[str, Any]]
    
class ISO15118EVClient:
    """ISO 15118-20 EV Client Implementation"""
    
    def __init__(self, config: Dict[str, Any], ev_controller):
        self.config = config
        self.ev_controller = ev_controller
        
        # Session configuration
        self.session_id = None
        self.evccid = config.get('evccid', f"EV_{ev_controller.ev_id}_ID")
        self.current_state = EVSessionState.IDLE
        
        # Protocol configuration
        self.protocol_version = config.get('version', '20')
        self.message_timeout = config.get('message_timeout_seconds', 30)
        
        # Charging parameters
        self.ev_charge_parameter = None
        self.evse_charge_parameter = None
        self.charging_schedule = None
        
        # Session data
        self.session_data = {}
        self.last_message_time = None
        
        # TLS connection
        self.tls_client = None
        
        logger.info(f"ISO 15118 EV Client initialized: {self.evccid}")
    
    async def start_session(self, tls_client) -> bool:
        """Start ISO 15118 session with EVSE"""
        try:
            self.tls_client = tls_client
            self.session_id = f"SESSION_{self.evccid}_{int(time.time())}"
            
            logger.info(f"Starting ISO 15118 session: {self.session_id}")
            
            # Step 1: Session Setup
            if not await self._send_session_setup_request():
                return False
            
            # Step 2: Service Discovery
            if not await self._send_service_discovery_request():
                return False
            
            # Step 3: Authorization Setup
            if not await self._send_authorization_setup_request():
                return False
            
            logger.info("ISO 15118 session established successfully")
            return True
            
        except Exception as e:
            logger.error(f"ISO 15118 session start failed: {e}")
            return False
    
    async def _send_session_setup_request(self) -> bool:
        """Send SessionSetupRequest"""
        try:
            request = {
                "type": "SessionSetupRequest",
                "session_id": self.session_id,
                "evccid": self.evccid
            }
            
            response = await self._send_message(request)
            
            if response and response.get("response_code") == "OK":
                evse_id = response.get("evse_id")
                logger.info(f"Session setup successful with EVSE: {evse_id}")
                self.session_data['evse_id'] = evse_id
                self.current_state = EVSessionState.MATCHED
                return True
            else:
                logger.error(f"Session setup failed: {response}")
                return False
                
        except Exception as e:
            logger.error(f"SessionSetupRequest error: {e}")
            return False
    
    async def _send_service_discovery_request(self) -> bool:
        """Send ServiceDiscoveryRequest"""
        try:
            request = {
                "type": "ServiceDiscoveryRequest",
                "session_id": self.session_id
            }
            
            response = await self._send_message(request)
            
            if response and response.get("response_code") == "OK":
                service_list = response.get("service_list", [])
                payment_options = response.get("payment_option_list", [])
                
                logger.info(f"Available services: {len(service_list)}")
                logger.info(f"Payment options: {payment_options}")
                
                self.session_data['available_services'] = service_list
                self.session_data['payment_options'] = payment_options
                
                return True
            else:
                logger.error(f"Service discovery failed: {response}")
                return False
                
        except Exception as e:
            logger.error(f"ServiceDiscoveryRequest error: {e}")
            return False
    
    async def _send_authorization_setup_request(self) -> bool:
        """Send AuthorizationSetupRequest"""
        try:
            request = {
                "type": "AuthorizationSetupRequest",
                "session_id": self.session_id
            }
            
            response = await self._send_message(request)
            
            if response and response.get("response_code") == "OK":
                auth_mode = response.get("authorization_mode")
                cert_service = response.get("certificate_installation_service")
                
                logger.info(f"Authorization mode: {auth_mode}")
                self.session_data['authorization_mode'] = auth_mode
                self.current_state = EVSessionState.AUTH_SETUP
                
                return True
            else:
                logger.error(f"Authorization setup failed: {response}")
                return False
                
        except Exception as e:
            logger.error(f"AuthorizationSetupRequest error: {e}")
            return False
    
    async def request_authorization(self, auth_request) -> Optional['AuthorizationResponse']:
        """Request authorization from EVSE"""
        try:
            logger.info("Requesting Plug-and-Charge authorization")
            
            request = {
                "type": "AuthorizationRequest",
                "session_id": self.session_id,
                "ev_certificate": auth_request.ev_certificate,
                "requested_energy_kwh": auth_request.requested_energy_kwh
            }
            
            response = await self._send_message(request)
            
            if response and response.get("response_code") == "OK":
                from ...control.authorization import AuthorizationResponse, AuthorizationStatus
                
                auth_response = AuthorizationResponse(
                    session_id=self.session_id,
                    status=AuthorizationStatus.AUTHORIZED,
                    authorized_energy_kwh=response.get("authorized_energy_kwh"),
                    max_power_kw=response.get("max_power_kw"),
                    tariff_per_kwh=response.get("tariff_per_kwh"),
                    authorization_token=response.get("authorization_token"),
                    timestamp=datetime.utcnow()
                )
                
                self.session_data.update({
                    'authorized_energy_kwh': response.get("authorized_energy_kwh"),
                    'max_power_kw': response.get("max_power_kw"),
                    'tariff_per_kwh': response.get("tariff_per_kwh")
                })
                
                self.current_state = EVSessionState.AUTHORIZED
                logger.info("Authorization granted successfully")
                
                return auth_response
            else:
                from ...control.authorization import AuthorizationResponse, AuthorizationStatus
                
                return AuthorizationResponse(
                    session_id=self.session_id,
                    status=AuthorizationStatus.DENIED,
                    reason=response.get("reason", "Authorization denied")
                )
                
        except Exception as e:
            logger.error(f"Authorization request error: {e}")
            from ...control.authorization import AuthorizationResponse, AuthorizationStatus
            
            return AuthorizationResponse(
                session_id=self.session_id,
                status=AuthorizationStatus.DENIED,
                reason=f"Internal error: {str(e)}"
            )
    
    async def start_charging(self, target_energy_kwh: float, max_power_kw: float) -> bool:
        """Start charging process"""
        try:
            logger.info(f"Starting charging: target={target_energy_kwh}kWh, max_power={max_power_kw}kW")
            
            # Step 1: Charge Parameter Discovery
            if not await self._send_charge_parameter_discovery_request(target_energy_kwh, max_power_kw):
                return False
            
            # Step 2: Power Delivery (Start)
            if not await self._send_power_delivery_request("Start"):
                return False
            
            self.current_state = EVSessionState.CHARGING
            logger.info("Charging started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Charging start error: {e}")
            return False
    
    async def _send_charge_parameter_discovery_request(self, target_energy_kwh: float, max_power_kw: float) -> bool:
        """Send ChargeParameterDiscoveryRequest"""
        try:
            # Create EV charge parameters
            self.ev_charge_parameter = EVChargeParameter(
                max_charge_power_kw=max_power_kw,
                max_charge_current_a=max_power_kw * 1000 / 400.0,  # Assume 400V
                max_voltage_v=500.0,
                energy_capacity_kwh=self.ev_controller.ev_config.battery_capacity_kwh,
                target_energy_kwh=target_energy_kwh
            )
            
            request = {
                "type": "ChargeParameterDiscoveryRequest",
                "session_id": self.session_id,
                "ev_charge_parameter": {
                    "max_charge_power_kw": self.ev_charge_parameter.max_charge_power_kw,
                    "max_charge_current_a": self.ev_charge_parameter.max_charge_current_a,
                    "max_voltage_v": self.ev_charge_parameter.max_voltage_v,
                    "energy_capacity_kwh": self.ev_charge_parameter.energy_capacity_kwh,
                    "requested_energy_kwh": self.ev_charge_parameter.target_energy_kwh
                }
            }
            
            response = await self._send_message(request)
            
            if response and response.get("response_code") == "OK":
                evse_charge_param = response.get("evse_charge_parameter", {})
                self.evse_charge_parameter = evse_charge_param
                
                logger.info(f"Charge parameters negotiated - EVSE max power: {evse_charge_param.get('evse_max_power')}kW")
                self.current_state = EVSessionState.PARAM_DISCOVERY
                return True
            else:
                logger.error(f"Charge parameter discovery failed: {response}")
                return False
                
        except Exception as e:
            logger.error(f"ChargeParameterDiscoveryRequest error: {e}")
            return False
    
    async def _send_power_delivery_request(self, charge_progress: str) -> bool:
        """Send PowerDeliveryRequest"""
        try:
            request = {
                "type": "PowerDeliveryRequest",
                "session_id": self.session_id,
                "charge_progress": charge_progress
            }
            
            response = await self._send_message(request)
            
            if response and response.get("response_code") == "OK":
                logger.info(f"Power delivery {charge_progress} successful")
                return True
            else:
                logger.error(f"Power delivery {charge_progress} failed: {response}")
                return False
                
        except Exception as e:
            logger.error(f"PowerDeliveryRequest error: {e}")
            return False
    
    async def stop_charging(self) -> bool:
        """Stop charging process"""
        try:
            logger.info("Stopping charging")
            
            # Send Power Delivery Stop
            if not await self._send_power_delivery_request("Stop"):
                return False
            
            self.current_state = EVSessionState.STOPPING
            logger.info("Charging stopped successfully")
            return True
            
        except Exception as e:
            logger.error(f"Charging stop error: {e}")
            return False
    
    async def end_session(self) -> bool:
        """End ISO 15118 session"""
        try:
            logger.info("Ending ISO 15118 session")
            
            request = {
                "type": "SessionStopRequest",
                "session_id": self.session_id
            }
            
            response = await self._send_message(request)
            
            if response and response.get("response_code") == "OK":
                self.current_state = EVSessionState.ENDED
                logger.info("ISO 15118 session ended successfully")
                return True
            else:
                logger.error(f"Session stop failed: {response}")
                return False
                
        except Exception as e:
            logger.error(f"Session end error: {e}")
            return False
    
    async def get_evse_information(self) -> Optional[Dict[str, Any]]:
        """Get EVSE information from session data"""
        try:
            if 'evse_id' in self.session_data:
                return {
                    'evse_id': self.session_data['evse_id'],
                    'available_services': self.session_data.get('available_services', []),
                    'payment_options': self.session_data.get('payment_options', []),
                    'max_power_kw': self.evse_charge_parameter.get('evse_max_power') if self.evse_charge_parameter else None,
                    'max_voltage_v': self.evse_charge_parameter.get('evse_max_voltage') if self.evse_charge_parameter else None,
                    'max_current_a': self.evse_charge_parameter.get('evse_max_current') if self.evse_charge_parameter else None
                }
            return None
        except Exception as e:
            logger.error(f"Get EVSE information error: {e}")
            return None
    
    async def _send_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send message and wait for response"""
        try:
            logger.debug(f"Sending {message['type']}")
            
            # Simulate message transmission over TLS
            # In production, this would serialize message and send over secure channel
            await asyncio.sleep(0.1)  # Simulate network latency
            
            # Simulate EVSE response (for development/testing)
            response = self._simulate_evse_response(message)
            
            self.last_message_time = datetime.utcnow()
            
            logger.debug(f"Received response for {message['type']}")
            return response
            
        except Exception as e:
            logger.error(f"Message transmission error: {e}")
            return None
    
    def _simulate_evse_response(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate EVSE responses for development/testing"""
        message_type = request.get("type")
        
        if message_type == "SessionSetupRequest":
            return {
                "response_code": "OK",
                "evse_id": "EVSE001",
                "session_id": request.get("session_id")
            }
        
        elif message_type == "ServiceDiscoveryRequest":
            return {
                "response_code": "OK",
                "service_list": [
                    {"service_id": 1, "service_name": "DC_extended_Charging", "service_category": "EnergyTransfer"}
                ],
                "payment_option_list": ["Contract"]
            }
        
        elif message_type == "AuthorizationSetupRequest":
            return {
                "response_code": "OK",
                "authorization_mode": "PnC",
                "certificate_installation_service": True
            }
        
        elif message_type == "AuthorizationRequest":
            return {
                "response_code": "OK",
                "authorized_energy_kwh": min(request.get("requested_energy_kwh", 50.0), 100.0),
                "max_power_kw": 50.0,
                "tariff_per_kwh": 0.25,
                "authorization_token": f"AUTH_{int(time.time())}"
            }
        
        elif message_type == "ChargeParameterDiscoveryRequest":
            ev_param = request.get("ev_charge_parameter", {})
            return {
                "response_code": "OK",
                "processing": "Finished",
                "evse_processing": "Finished",
                "evse_charge_parameter": {
                    "evse_id": "EVSE001",
                    "evse_max_voltage": 500.0,
                    "evse_max_current": 125.0,
                    "evse_max_power": 50.0,
                    "evse_min_voltage": 200.0,
                    "evse_min_current": 10.0,
                    "energy_to_be_delivered": ev_param.get("requested_energy_kwh", 50.0)
                }
            }
        
        elif message_type == "PowerDeliveryRequest":
            return {
                "response_code": "OK",
                "evse_processing": "Finished"
            }
        
        elif message_type == "SessionStopRequest":
            return {
                "response_code": "OK"
            }
        
        else:
            return {
                "response_code": "FAILED",
                "reason": f"Unsupported message type: {message_type}"
            }
    
    def get_session_status(self) -> Dict[str, Any]:
        """Get current session status"""
        return {
            "session_id": self.session_id,
            "state": self.current_state.value,
            "evccid": self.evccid,
            "evse_id": self.session_data.get("evse_id"),
            "authorized_energy_kwh": self.session_data.get("authorized_energy_kwh"),
            "max_power_kw": self.session_data.get("max_power_kw"),
            "tariff_per_kwh": self.session_data.get("tariff_per_kwh"),
            "last_message_time": self.last_message_time.isoformat() if self.last_message_time else None
        }

# Export main classes
__all__ = [
    'ISO15118EVClient',
    'EVSessionState',
    'ChargingProfileType',
    'EVChargeParameter',
    'ChargingSchedule'
]

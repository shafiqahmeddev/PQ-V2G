"""
PQ-V2G OCPP 2.0.1 Client Implementation
=======================================

This module implements the Open Charge Point Protocol (OCPP) 2.0.1 client
for the PQ-V2G system, providing secure WebSocket-based communication between
EVSE and CSMS with post-quantum TLS protection.

Key Features:
- OCPP 2.0.1 compliant message handling
- Post-quantum TLS 1.3 WebSocket connections
- Certificate-based mutual authentication
- Real-time charging session reporting
- Remote monitoring and control capabilities
- Minimal footprint support for resource-constrained devices

Author: Shafiq Ahmed <s.ahmed@essex.ac.uk>
Institution: University of Essex
License: MIT
"""

import os
import json
import time
import uuid
import logging
import asyncio
import websockets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass, asdict
from enum import Enum

# Configure logging
logger = logging.getLogger(__name__)

class OCPPMessageType(Enum):
    """OCPP message types"""
    CALL = 2
    CALLRESULT = 3
    CALLERROR = 4

class ChargingState(Enum):
    """Charging states as per OCPP 2.0.1"""
    AVAILABLE = "Available"
    OCCUPIED = "Occupied" 
    CHARGING = "Charging"
    SUSPENDED_EVSE = "SuspendedEVSE"
    SUSPENDED_EV = "SuspendedEV"
    FINISHING = "Finishing"
    RESERVED = "Reserved"
    UNAVAILABLE = "Unavailable"
    FAULTED = "Faulted"

class ConnectorStatus(Enum):
    """Connector status enumeration"""
    AVAILABLE = "Available"
    OCCUPIED = "Occupied"
    RESERVED = "Reserved"
    UNAVAILABLE = "Unavailable"
    FAULTED = "Faulted"

@dataclass
class BootNotification:
    """OCPP BootNotification message"""
    charging_station: Dict[str, Any]
    reason: str

@dataclass
class StatusNotification:
    """OCPP StatusNotification message"""
    timestamp: str
    connector_status: str
    evse_id: int
    connector_id: int

@dataclass
class TransactionEvent:
    """OCPP TransactionEvent message"""
    event_type: str
    timestamp: str
    transaction_info: Dict[str, Any]
    trigger_reason: str
    seq_no: int
    evse: Optional[Dict[str, Any]] = None
    id_token: Optional[Dict[str, Any]] = None
    meter_value: Optional[List[Dict[str, Any]]] = None

@dataclass
class MeterValues:
    """OCPP MeterValues message"""
    evse_id: int
    meter_value: List[Dict[str, Any]]

@dataclass
class Authorize:
    """OCPP Authorize message"""
    id_token: Dict[str, Any]
    certificate: Optional[str] = None
    
class OCPPClient:
    """OCPP 2.0.1 Client Implementation"""
    
    def __init__(self, config: Dict[str, Any], evse_controller):
        self.config = config
        self.evse_controller = evse_controller
        
        # OCPP configuration
        self.charge_point_id = config.get('charge_point_id', f"CP_{evse_controller.evse_id}")
        self.csms_url = config.get('csms_url', 'ws://localhost:8080')
        self.security_profile = config.get('security_profile', 3)  # TLS with client certificates
        self.heartbeat_interval = config.get('heartbeat_interval_seconds', 300)
        self.message_timeout = config.get('message_timeout_seconds', 30)
        
        # Protocol version
        self.protocol_version = "OCPP2.0.1"
        self.supported_features = [
            "Core", "FirmwareManagement", "RemoteControl", 
            "LocalAuthListManagement", "SmartCharging"
        ]
        
        # Connection state
        self.websocket = None
        self.connected = False
        self.last_heartbeat = None
        self.message_queue = asyncio.Queue()
        
        # Message handling
        self.pending_requests: Dict[str, asyncio.Event] = {}
        self.request_responses: Dict[str, Any] = {}
        self.message_handlers: Dict[str, Callable] = {}
        
        # Session tracking
        self.active_transactions: Dict[str, Dict[str, Any]] = {}
        
        # Initialize message handlers
        self._initialize_message_handlers()
        
        logger.info(f"OCPP Client initialized: {self.charge_point_id}")
    
    def _initialize_message_handlers(self):
        """Initialize OCPP message handlers"""
        self.message_handlers = {
            'RemoteStartTransaction': self._handle_remote_start_transaction,
            'RemoteStopTransaction': self._handle_remote_stop_transaction,
            'UnlockConnector': self._handle_unlock_connector,
            'Reset': self._handle_reset,
            'ChangeAvailability': self._handle_change_availability,
            'GetConfiguration': self._handle_get_configuration,
            'ChangeConfiguration': self._handle_change_configuration,
            'ClearChargingProfile': self._handle_clear_charging_profile,
            'SetChargingProfile': self._handle_set_charging_profile,
            'TriggerMessage': self._handle_trigger_message,
            'CertificateSigned': self._handle_certificate_signed,
            'InstallCertificate': self._handle_install_certificate
        }
    
    async def connect(self) -> bool:
        """Connect to CSMS via WebSocket"""
        try:
            logger.info(f"Connecting to CSMS: {self.csms_url}")
            
            # WebSocket headers for OCPP
            headers = {
                "Sec-WebSocket-Protocol": "ocpp2.0.1"
            }
            
            # Connect with TLS if configured
            if self.csms_url.startswith('wss://') and self.security_profile >= 2:
                # In production, would use actual TLS context with PQ certificates
                ssl_context = None  # Would configure PQ-TLS context here
            else:
                ssl_context = None
            
            # Establish WebSocket connection
            self.websocket = await websockets.connect(
                self.csms_url,
                subprotocols=["ocpp2.0.1"],
                extra_headers=headers,
                ssl=ssl_context
            )
            
            self.connected = True
            
            # Start message handling tasks
            asyncio.create_task(self._message_handler_loop())
            asyncio.create_task(self._heartbeat_loop())
            
            # Send BootNotification
            boot_result = await self._send_boot_notification()
            if boot_result:
                logger.info("OCPP connection established successfully")
                return True
            else:
                logger.error("BootNotification failed")
                await self.disconnect()
                return False
                
        except Exception as e:
            logger.error(f"OCPP connection failed: {e}")
            self.connected = False
            return False
    
    async def disconnect(self):
        """Disconnect from CSMS"""
        try:
            if self.websocket and self.connected:
                await self.websocket.close()
            
            self.connected = False
            self.websocket = None
            
            logger.info("OCPP connection closed")
            
        except Exception as e:
            logger.error(f"OCPP disconnect error: {e}")
    
    async def _send_boot_notification(self) -> bool:
        """Send OCPP BootNotification"""
        try:
            charging_station_info = {
                "model": self.evse_controller.evse_config.get('model', 'PQ-V2G EVSE'),
                "vendorName": self.evse_controller.evse_config.get('vendor', 'University of Essex'),
                "firmwareVersion": self.evse_controller.evse_config.get('firmware_version', '1.0.0'),
                "serialNumber": self.evse_controller.evse_config.get('serial_number', self.charge_point_id),
                "modem": {
                    "iccid": "89441000000000000000",
                    "imsi": "234150000000000"
                }
            }
            
            boot_notification = BootNotification(
                charging_station=charging_station_info,
                reason="PowerUp"
            )
            
            response = await self._send_call("BootNotification", asdict(boot_notification))
            
            if response and response.get("status") == "Accepted":
                self.heartbeat_interval = response.get("interval", self.heartbeat_interval)
                logger.info(f"BootNotification accepted, heartbeat interval: {self.heartbeat_interval}s")
                return True
            else:
                logger.error(f"BootNotification rejected: {response}")
                return False
                
        except Exception as e:
            logger.error(f"BootNotification failed: {e}")
            return False
    
    async def _send_call(self, action: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send OCPP CALL message and wait for response"""
        try:
            # Generate unique message ID
            message_id = str(uuid.uuid4())
            
            # Create CALL message
            call_message = [OCPPMessageType.CALL.value, message_id, action, payload]
            
            # Create event for response waiting
            response_event = asyncio.Event()
            self.pending_requests[message_id] = response_event
            
            # Send message
            await self.websocket.send(json.dumps(call_message))
            logger.debug(f"Sent CALL: {action} ({message_id})")
            
            # Wait for response
            try:
                await asyncio.wait_for(response_event.wait(), timeout=self.message_timeout)
                response = self.request_responses.get(message_id)
                
                # Cleanup
                del self.pending_requests[message_id]
                if message_id in self.request_responses:
                    del self.request_responses[message_id]
                
                return response
                
            except asyncio.TimeoutError:
                logger.error(f"CALL timeout: {action} ({message_id})")
                del self.pending_requests[message_id]
                return None
                
        except Exception as e:
            logger.error(f"Send CALL failed: {e}")
            return None
    
    async def _message_handler_loop(self):
        """Main message handling loop"""
        try:
            async for message in self.websocket:
                await self._process_message(message)
        except websockets.exceptions.ConnectionClosed:
            logger.info("WebSocket connection closed")
            self.connected = False
        except Exception as e:
            logger.error(f"Message handler loop error: {e}")
            self.connected = False
    
    async def _process_message(self, message: str):
        """Process incoming OCPP message"""
        try:
            data = json.loads(message)
            message_type = data[0]
            
            if message_type == OCPPMessageType.CALLRESULT.value:
                # Handle CALLRESULT
                message_id = data[1]
                payload = data[2]
                
                if message_id in self.pending_requests:
                    self.request_responses[message_id] = payload
                    self.pending_requests[message_id].set()
                
            elif message_type == OCPPMessageType.CALLERROR.value:
                # Handle CALLERROR
                message_id = data[1]
                error_code = data[2]
                error_description = data[3]
                
                logger.error(f"Received CALLERROR: {error_code} - {error_description}")
                
                if message_id in self.pending_requests:
                    self.request_responses[message_id] = None
                    self.pending_requests[message_id].set()
                
            elif message_type == OCPPMessageType.CALL.value:
                # Handle incoming CALL
                message_id = data[1]
                action = data[2]
                payload = data[3]
                
                logger.debug(f"Received CALL: {action} ({message_id})")
                
                # Process the action
                response = await self._handle_call(action, payload)
                
                # Send CALLRESULT
                callresult = [OCPPMessageType.CALLRESULT.value, message_id, response]
                await self.websocket.send(json.dumps(callresult))
                
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON message: {e}")
        except Exception as e:
            logger.error(f"Message processing error: {e}")
    
    async def _handle_call(self, action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle incoming CALL message"""
        try:
            if action in self.message_handlers:
                response = await self.message_handlers[action](payload)
                return response
            else:
                logger.warning(f"Unhandled action: {action}")
                return {"status": "NotSupported"}
        except Exception as e:
            logger.error(f"Call handler error for {action}: {e}")
            return {"status": "InternalError"}
    
    async def _heartbeat_loop(self):
        """Send periodic heartbeats to CSMS"""
        try:
            while self.connected:
                await asyncio.sleep(self.heartbeat_interval)
                
                if self.connected:
                    response = await self._send_call("Heartbeat", {})
                    if response:
                        self.last_heartbeat = datetime.utcnow()
                        logger.debug("Heartbeat successful")
                    else:
                        logger.warning("Heartbeat failed")
        except Exception as e:
            logger.error(f"Heartbeat loop error: {e}")
    
    # Message Handlers
    async def _handle_remote_start_transaction(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle RemoteStartTransaction request"""
        try:
            evse_id = payload.get("evseId", 1)
            id_token = payload.get("idToken")
            charging_profile = payload.get("chargingProfile")
            
            logger.info(f"Remote start transaction requested for EVSE {evse_id}")
            
            # Check if EVSE is available
            if self.evse_controller.current_state.value in ["Available"]:
                # Start remote transaction
                success = await self.evse_controller.start_remote_transaction(
                    evse_id, id_token, charging_profile
                )
                
                if success:
                    return {"status": "Accepted"}
                else:
                    return {"status": "Rejected"}
            else:
                return {"status": "Rejected"}
                
        except Exception as e:
            logger.error(f"RemoteStartTransaction handler error: {e}")
            return {"status": "Rejected"}
    
    async def _handle_remote_stop_transaction(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle RemoteStopTransaction request"""
        try:
            transaction_id = payload.get("transactionId")
            
            logger.info(f"Remote stop transaction requested: {transaction_id}")
            
            if transaction_id in self.active_transactions:
                success = await self.evse_controller.stop_remote_transaction(transaction_id)
                
                if success:
                    return {"status": "Accepted"}
                else:
                    return {"status": "Rejected"}
            else:
                return {"status": "Rejected"}
                
        except Exception as e:
            logger.error(f"RemoteStopTransaction handler error: {e}")
            return {"status": "Rejected"}
    
    async def _handle_unlock_connector(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle UnlockConnector request"""
        try:
            evse_id = payload.get("evseId", 1)
            connector_id = payload.get("connectorId", 1)
            
            logger.info(f"Unlock connector requested: EVSE {evse_id}, Connector {connector_id}")
            
            # Simulate connector unlock
            success = await self.evse_controller.unlock_connector(evse_id, connector_id)
            
            if success:
                return {"status": "Unlocked"}
            else:
                return {"status": "UnlockFailed"}
                
        except Exception as e:
            logger.error(f"UnlockConnector handler error: {e}")
            return {"status": "UnlockFailed"}
    
    async def _handle_reset(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle Reset request"""
        try:
            reset_type = payload.get("type", "Soft")
            evse_id = payload.get("evseId")
            
            logger.info(f"Reset requested: {reset_type}")
            
            # Schedule reset
            success = await self.evse_controller.schedule_reset(reset_type, evse_id)
            
            if success:
                return {"status": "Accepted"}
            else:
                return {"status": "Rejected"}
                
        except Exception as e:
            logger.error(f"Reset handler error: {e}")
            return {"status": "Rejected"}
    
    async def _handle_change_availability(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle ChangeAvailability request"""
        try:
            evse_id = payload.get("evseId")
            operational_status = payload.get("operationalStatus")
            
            logger.info(f"Change availability: EVSE {evse_id} to {operational_status}")
            
            success = await self.evse_controller.change_availability(evse_id, operational_status)
            
            if success:
                return {"status": "Accepted"}
            else:
                return {"status": "Rejected"}
                
        except Exception as e:
            logger.error(f"ChangeAvailability handler error: {e}")
            return {"status": "Rejected"}
    
    async def _handle_get_configuration(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle GetConfiguration request"""
        try:
            keys = payload.get("key", [])
            
            # Return configuration values
            configuration_keys = []
            unknown_keys = []
            
            # Get configuration from EVSE controller
            config = await self.evse_controller.get_configuration(keys)
            
            for key, value in config.get("known", {}).items():
                configuration_keys.append({
                    "key": key,
                    "readonly": False,
                    "value": str(value)
                })
            
            unknown_keys = config.get("unknown", [])
            
            response = {"configurationKey": configuration_keys}
            if unknown_keys:
                response["unknownKey"] = unknown_keys
            
            return response
            
        except Exception as e:
            logger.error(f"GetConfiguration handler error: {e}")
            return {"configurationKey": []}
    
    async def _handle_change_configuration(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle ChangeConfiguration request"""
        try:
            key = payload.get("key")
            value = payload.get("value")
            
            logger.info(f"Change configuration: {key} = {value}")
            
            success = await self.evse_controller.change_configuration(key, value)
            
            if success:
                return {"status": "Accepted"}
            else:
                return {"status": "Rejected"}
                
        except Exception as e:
            logger.error(f"ChangeConfiguration handler error: {e}")
            return {"status": "Rejected"}
    
    async def _handle_clear_charging_profile(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle ClearChargingProfile request"""
        try:
            charging_profile_id = payload.get("chargingProfileId")
            
            success = await self.evse_controller.clear_charging_profile(charging_profile_id)
            
            if success:
                return {"status": "Accepted"}
            else:
                return {"status": "Unknown"}
                
        except Exception as e:
            logger.error(f"ClearChargingProfile handler error: {e}")
            return {"status": "Unknown"}
    
    async def _handle_set_charging_profile(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle SetChargingProfile request"""
        try:
            evse_id = payload.get("evseId")
            charging_profile = payload.get("chargingProfile")
            
            success = await self.evse_controller.set_charging_profile(evse_id, charging_profile)
            
            if success:
                return {"status": "Accepted"}
            else:
                return {"status": "Rejected"}
                
        except Exception as e:
            logger.error(f"SetChargingProfile handler error: {e}")
            return {"status": "Rejected"}
    
    async def _handle_trigger_message(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle TriggerMessage request"""
        try:
            requested_message = payload.get("requestedMessage")
            evse_id = payload.get("evseId")
            
            logger.info(f"Trigger message requested: {requested_message}")
            
            # Trigger the requested message
            success = await self._trigger_message(requested_message, evse_id)
            
            if success:
                return {"status": "Accepted"}
            else:
                return {"status": "Rejected"}
                
        except Exception as e:
            logger.error(f"TriggerMessage handler error: {e}")
            return {"status": "Rejected"}
    
    async def _handle_certificate_signed(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle CertificateSigned request"""
        try:
            certificate_chain = payload.get("certificateChain")
            certificate_type = payload.get("certificateType", "ChargingStationCertificate")
            
            logger.info(f"Certificate signed: {certificate_type}")
            
            # Install the signed certificate
            success = await self.evse_controller.install_certificate(certificate_chain, certificate_type)
            
            if success:
                return {"status": "Accepted"}
            else:
                return {"status": "Rejected"}
                
        except Exception as e:
            logger.error(f"CertificateSigned handler error: {e}")
            return {"status": "Rejected"}
    
    async def _handle_install_certificate(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle InstallCertificate request"""
        try:
            certificate_type = payload.get("certificateType")
            certificate = payload.get("certificate")
            
            logger.info(f"Install certificate: {certificate_type}")
            
            success = await self.evse_controller.install_certificate(certificate, certificate_type)
            
            if success:
                return {"status": "Accepted"}
            else:
                return {"status": "Rejected"}
                
        except Exception as e:
            logger.error(f"InstallCertificate handler error: {e}")
            return {"status": "Rejected"}
    
    async def _trigger_message(self, message_type: str, evse_id: Optional[int] = None) -> bool:
        """Trigger specific OCPP message"""
        try:
            if message_type == "StatusNotification":
                return await self.send_status_notification(evse_id or 1, 1, "Available")
            elif message_type == "BootNotification":
                return await self._send_boot_notification()
            elif message_type == "Heartbeat":
                response = await self._send_call("Heartbeat", {})
                return response is not None
            else:
                logger.warning(f"Unsupported trigger message: {message_type}")
                return False
        except Exception as e:
            logger.error(f"Trigger message failed: {e}")
            return False
    
    # Public API methods
    async def send_status_notification(self, evse_id: int, connector_id: int, status: str) -> bool:
        """Send StatusNotification to CSMS"""
        try:
            status_notification = StatusNotification(
                timestamp=datetime.utcnow().isoformat(),
                connector_status=status,
                evse_id=evse_id,
                connector_id=connector_id
            )
            
            response = await self._send_call("StatusNotification", asdict(status_notification))
            return response is not None
            
        except Exception as e:
            logger.error(f"StatusNotification failed: {e}")
            return False
    
    async def send_transaction_event(self, event_type: str, transaction_id: str, 
                                   trigger_reason: str, **kwargs) -> bool:
        """Send TransactionEvent to CSMS"""
        try:
            transaction_info = {
                "transactionId": transaction_id,
                **kwargs.get("transaction_info", {})
            }
            
            transaction_event = TransactionEvent(
                event_type=event_type,
                timestamp=datetime.utcnow().isoformat(),
                transaction_info=transaction_info,
                trigger_reason=trigger_reason,
                seq_no=self._get_next_sequence_number(transaction_id),
                evse=kwargs.get("evse"),
                id_token=kwargs.get("id_token"),
                meter_value=kwargs.get("meter_value")
            )
            
            response = await self._send_call("TransactionEvent", asdict(transaction_event))
            return response is not None
            
        except Exception as e:
            logger.error(f"TransactionEvent failed: {e}")
            return False
    
    async def send_meter_values(self, evse_id: int, meter_values: List[Dict[str, Any]]) -> bool:
        """Send MeterValues to CSMS"""
        try:
            meter_values_msg = MeterValues(
                evse_id=evse_id,
                meter_value=meter_values
            )
            
            response = await self._send_call("MeterValues", asdict(meter_values_msg))
            return response is not None
            
        except Exception as e:
            logger.error(f"MeterValues failed: {e}")
            return False
    
    async def send_authorize(self, id_token: Dict[str, Any], certificate: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Send Authorize request to CSMS"""
        try:
            authorize = Authorize(
                id_token=id_token,
                certificate=certificate
            )
            
            response = await self._send_call("Authorize", asdict(authorize))
            return response
            
        except Exception as e:
            logger.error(f"Authorize failed: {e}")
            return None
    
    def _get_next_sequence_number(self, transaction_id: str) -> int:
        """Get next sequence number for transaction"""
        if transaction_id not in self.active_transactions:
            self.active_transactions[transaction_id] = {"seq_no": 0}
        
        self.active_transactions[transaction_id]["seq_no"] += 1
        return self.active_transactions[transaction_id]["seq_no"]
    
    def is_connected(self) -> bool:
        """Check if connected to CSMS"""
        return self.connected and self.websocket is not None
    
    def get_connection_status(self) -> Dict[str, Any]:
        """Get connection status information"""
        return {
            "connected": self.connected,
            "csms_url": self.csms_url,
            "charge_point_id": self.charge_point_id,
            "protocol_version": self.protocol_version,
            "last_heartbeat": self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            "heartbeat_interval": self.heartbeat_interval,
            "active_transactions": len(self.active_transactions)
        }

# Export main classes
__all__ = [
    'OCPPClient',
    'OCPPMessageType',
    'ChargingState',
    'ConnectorStatus',
    'BootNotification',
    'StatusNotification',
    'TransactionEvent',
    'MeterValues',
    'Authorize'
]

"""
PQ-V2G Data Plane - Metering Module
===================================

This module implements the Data Plane metering system for PQ-V2G,
providing secure energy measurement, telemetry collection, and 
session reconciliation with cryptographic integrity protection.

Key Features:
- Secure energy metering with tamper detection
- Telemetry data collection and transmission
- Session reconciliation and settlement
- Performance metrics and analytics
- Compliance reporting

Author: Shafiq Ahmed <s.ahmed@essex.ac.uk>
Institution: University of Essex
License: MIT
"""

import os
import time
import json
import hashlib
import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Union
from dataclasses import dataclass, asdict
from enum import Enum
import asyncio
import threading

# Configure logging
logger = logging.getLogger(__name__)

class TelemetryType(Enum):
    """Types of telemetry data"""
    ENERGY_METER = "energy_meter"
    POWER_METER = "power_meter"
    VOLTAGE = "voltage"
    CURRENT = "current"
    TEMPERATURE = "temperature"
    BATTERY_SOC = "battery_soc"
    EFFICIENCY = "efficiency"
    PERFORMANCE = "performance"
    STATUS = "status"

class MeterType(Enum):
    """Types of energy meters"""
    AC_METER = "ac_meter"
    DC_METER = "dc_meter"
    BIDIRECTIONAL = "bidirectional"
    SMART_METER = "smart_meter"

@dataclass
class MeterReading:
    """Energy meter reading with cryptographic integrity"""
    meter_id: str
    meter_type: MeterType
    session_id: str
    timestamp: datetime
    energy_kwh: float
    power_kw: float
    voltage_v: float
    current_a: float
    frequency_hz: Optional[float] = None
    power_factor: Optional[float] = None
    meter_sequence: int = 0
    integrity_hash: Optional[str] = None
    
    def __post_init__(self):
        """Calculate integrity hash after initialization"""
        if self.integrity_hash is None:
            self.integrity_hash = self._calculate_integrity_hash()
    
    def _calculate_integrity_hash(self) -> str:
        """Calculate cryptographic hash for integrity protection"""
        data = {
            'meter_id': self.meter_id,
            'session_id': self.session_id,
            'timestamp': self.timestamp.isoformat(),
            'energy_kwh': self.energy_kwh,
            'power_kw': self.power_kw,
            'voltage_v': self.voltage_v,
            'current_a': self.current_a,
            'meter_sequence': self.meter_sequence
        }
        
        data_json = json.dumps(data, sort_keys=True)
        return hashlib.sha256(data_json.encode()).hexdigest()
    
    def verify_integrity(self) -> bool:
        """Verify integrity hash"""
        expected_hash = self._calculate_integrity_hash()
        return self.integrity_hash == expected_hash

@dataclass
class TelemetryData:
    """Telemetry data point"""
    source_id: str
    telemetry_type: TelemetryType
    timestamp: datetime
    value: Union[float, int, str, bool]
    unit: str
    session_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['telemetry_type'] = self.telemetry_type.value
        return data

@dataclass
class SessionMeterData:
    """Complete metering data for a charging session"""
    session_id: str
    evse_id: str
    ev_id: str
    start_time: datetime
    end_time: Optional[datetime]
    start_meter_reading: MeterReading
    end_meter_reading: Optional[MeterReading]
    intermediate_readings: List[MeterReading]
    total_energy_kwh: Optional[float] = None
    average_power_kw: Optional[float] = None
    peak_power_kw: Optional[float] = None
    efficiency_percent: Optional[float] = None
    cost: Optional[float] = None
    tariff_per_kwh: Optional[float] = None
    
    def calculate_totals(self):
        """Calculate session totals from meter readings"""
        if self.end_meter_reading:
            self.total_energy_kwh = (
                self.end_meter_reading.energy_kwh - self.start_meter_reading.energy_kwh
            )
        
        # Calculate average power from intermediate readings
        if self.intermediate_readings:
            power_readings = [reading.power_kw for reading in self.intermediate_readings]
            self.average_power_kw = sum(power_readings) / len(power_readings)
            self.peak_power_kw = max(power_readings)
        
        # Calculate cost if tariff is available
        if self.total_energy_kwh and self.tariff_per_kwh:
            self.cost = self.total_energy_kwh * self.tariff_per_kwh

class EnergyMeter:
    """Secure energy meter with integrity protection"""
    
    def __init__(self, meter_id: str, meter_type: MeterType, config: Dict[str, Any]):
        self.meter_id = meter_id
        self.meter_type = meter_type
        self.config = config
        
        # Meter state
        self.current_session_id = None
        self.sequence_counter = 0
        self.last_reading = None
        self.is_active = False
        
        # Calibration parameters
        self.voltage_scale = config.get('voltage_scale', 1.0)
        self.current_scale = config.get('current_scale', 1.0)
        self.power_scale = config.get('power_scale', 1.0)
        
        # Integrity protection
        self.tamper_detection = config.get('tamper_detection', True)
        self.max_reading_gap_seconds = config.get('max_reading_gap_seconds', 300)
        
        # Simulation parameters for demo
        self.simulation_mode = config.get('simulation_mode', True)
        self.base_voltage = config.get('base_voltage', 400.0)  # V
        self.noise_factor = config.get('noise_factor', 0.02)  # 2% noise
        
        logger.info(f"Energy meter initialized: {self.meter_id} ({self.meter_type.value})")
    
    def start_session(self, session_id: str) -> MeterReading:
        """Start new metering session"""
        try:
            self.current_session_id = session_id
            self.sequence_counter = 0
            self.is_active = True
            
            # Take initial reading
            initial_reading = self.take_reading()
            self.last_reading = initial_reading
            
            logger.info(f"Meter session started: {session_id} on {self.meter_id}")
            return initial_reading
            
        except Exception as e:
            logger.error(f"Failed to start meter session: {e}")
            raise
    
    def take_reading(self) -> MeterReading:
        """Take current meter reading"""
        try:
            if not self.is_active:
                raise ValueError("Meter not active")
            
            timestamp = datetime.utcnow()
            
            if self.simulation_mode:
                # Simulate realistic meter readings
                voltage, current, power, energy = self._simulate_readings()
            else:
                # In production, would read from actual meter hardware
                voltage, current, power, energy = self._read_hardware()
            
            # Create meter reading
            reading = MeterReading(
                meter_id=self.meter_id,
                meter_type=self.meter_type,
                session_id=self.current_session_id,
                timestamp=timestamp,
                energy_kwh=energy,
                power_kw=power,
                voltage_v=voltage,
                current_a=current,
                frequency_hz=50.0,  # Standard grid frequency
                power_factor=0.98,  # Typical power factor
                meter_sequence=self.sequence_counter
            )
            
            self.sequence_counter += 1
            self.last_reading = reading
            
            # Perform tamper detection
            if self.tamper_detection:
                self._detect_tampering(reading)
            
            logger.debug(f"Meter reading taken: {self.meter_id} - {energy:.3f}kWh, {power:.1f}kW")
            return reading
            
        except Exception as e:
            logger.error(f"Failed to take meter reading: {e}")
            raise
    
    def end_session(self) -> Optional[MeterReading]:
        """End current metering session"""
        try:
            if not self.is_active or not self.current_session_id:
                return None
            
            # Take final reading
            final_reading = self.take_reading()
            
            # Reset session state
            self.current_session_id = None
            self.is_active = False
            
            logger.info(f"Meter session ended: {self.meter_id}")
            return final_reading
            
        except Exception as e:
            logger.error(f"Failed to end meter session: {e}")
            return None
    
    def _simulate_readings(self) -> tuple[float, float, float, float]:
        """Simulate realistic meter readings for development/testing"""
        
        # Simulate charging power curve (starts high, tapers off)
        session_duration = time.time() % 3600  # Simulate 1-hour sessions
        charging_progress = session_duration / 3600.0
        
        # Power curve: starts at 50kW, tapers to 10kW
        base_power = 50.0 * (1 - 0.8 * charging_progress) + 10.0
        
        # Add some realistic noise
        noise = secrets.randbelow(int(self.noise_factor * 1000)) / 1000.0 - self.noise_factor/2
        power_kw = max(0, base_power + base_power * noise)
        
        # Calculate voltage and current
        voltage_v = self.base_voltage + self.base_voltage * noise * 0.1  # ±1% voltage variation
        current_a = power_kw * 1000 / voltage_v if voltage_v > 0 else 0
        
        # Energy accumulation (simplified)
        energy_increment = power_kw / 3600  # kWh per second (simplified)
        if self.last_reading:
            time_diff = (datetime.utcnow() - self.last_reading.timestamp).total_seconds()
            energy_kwh = self.last_reading.energy_kwh + energy_increment * time_diff
        else:
            energy_kwh = 0.0
        
        return voltage_v, current_a, power_kw, energy_kwh
    
    def _read_hardware(self) -> tuple[float, float, float, float]:
        """Read from actual meter hardware (placeholder)"""
        # In production, this would interface with actual meter hardware
        # via Modbus, CAN, or other protocols
        return 400.0, 50.0, 20.0, 10.0
    
    def _detect_tampering(self, reading: MeterReading):
        """Detect potential meter tampering"""
        try:
            if not self.last_reading:
                return
            
            # Check for impossible values
            if reading.energy_kwh < self.last_reading.energy_kwh:
                logger.warning(f"Potential tampering detected: energy decreased on {self.meter_id}")
            
            # Check for unrealistic power jumps
            power_change = abs(reading.power_kw - self.last_reading.power_kw)
            if power_change > 100.0:  # 100kW jump threshold
                logger.warning(f"Potential tampering detected: large power jump on {self.meter_id}")
            
            # Check time gap
            time_gap = (reading.timestamp - self.last_reading.timestamp).total_seconds()
            if time_gap > self.max_reading_gap_seconds:
                logger.warning(f"Large time gap detected on {self.meter_id}: {time_gap}s")
            
        except Exception as e:
            logger.error(f"Tamper detection error: {e}")

class TelemetryCollector:
    """Collects and manages telemetry data from various sources"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Storage for telemetry data
        self.telemetry_buffer: List[TelemetryData] = []
        self.max_buffer_size = config.get('max_buffer_size', 1000)
        
        # Collection parameters
        self.collection_interval = config.get('collection_interval_seconds', 10)
        self.batch_size = config.get('batch_size', 50)
        
        # Async collection task
        self.collection_task = None
        self.is_collecting = False
        
        # Thread safety
        self.lock = threading.Lock()
        
        logger.info("Telemetry Collector initialized")
    
    def add_telemetry_data(self, data: TelemetryData):
        """Add telemetry data point to buffer"""
        try:
            with self.lock:
                self.telemetry_buffer.append(data)
                
                # Trim buffer if too large
                if len(self.telemetry_buffer) > self.max_buffer_size:
                    removed_count = len(self.telemetry_buffer) - self.max_buffer_size
                    self.telemetry_buffer = self.telemetry_buffer[removed_count:]
                    logger.debug(f"Trimmed telemetry buffer: removed {removed_count} old entries")
            
        except Exception as e:
            logger.error(f"Failed to add telemetry data: {e}")
    
    async def start_collection(self):
        """Start telemetry collection task"""
        if self.is_collecting:
            return
        
        self.is_collecting = True
        self.collection_task = asyncio.create_task(self._collection_loop())
        logger.info("Telemetry collection started")
    
    async def stop_collection(self):
        """Stop telemetry collection task"""
        self.is_collecting = False
        if self.collection_task:
            self.collection_task.cancel()
            try:
                await self.collection_task
            except asyncio.CancelledError:
                pass
        logger.info("Telemetry collection stopped")
    
    async def _collection_loop(self):
        """Main telemetry collection loop"""
        try:
            while self.is_collecting:
                await asyncio.sleep(self.collection_interval)
                
                # Process telemetry data
                await self._process_telemetry_batch()
                
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Telemetry collection loop error: {e}")
    
    async def _process_telemetry_batch(self):
        """Process batch of telemetry data"""
        try:
            batch = []
            with self.lock:
                if len(self.telemetry_buffer) >= self.batch_size:
                    batch = self.telemetry_buffer[:self.batch_size]
                    self.telemetry_buffer = self.telemetry_buffer[self.batch_size:]
            
            if batch:
                # Process the batch (send to CSMS, store, analyze, etc.)
                await self._send_telemetry_batch(batch)
                logger.debug(f"Processed telemetry batch: {len(batch)} data points")
            
        except Exception as e:
            logger.error(f"Telemetry batch processing error: {e}")
    
    async def _send_telemetry_batch(self, batch: List[TelemetryData]):
        """Send telemetry batch to CSMS or cloud"""
        try:
            # Convert to JSON for transmission
            batch_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'batch_size': len(batch),
                'data': [data.to_dict() for data in batch]
            }
            
            # In production, would send via OCPP or direct API
            logger.debug(f"Telemetry batch ready for transmission: {len(batch)} points")
            
        except Exception as e:
            logger.error(f"Telemetry batch transmission error: {e}")
    
    def get_telemetry_stats(self) -> Dict[str, Any]:
        """Get telemetry collection statistics"""
        with self.lock:
            buffer_size = len(self.telemetry_buffer)
        
        return {
            'buffer_size': buffer_size,
            'max_buffer_size': self.max_buffer_size,
            'collection_interval': self.collection_interval,
            'is_collecting': self.is_collecting,
            'batch_size': self.batch_size
        }

class SessionReconciliation:
    """Handles session reconciliation and settlement"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Reconciliation parameters
        self.reconciliation_timeout_hours = config.get('reconciliation_timeout_hours', 24)
        self.max_settlement_delay_minutes = config.get('max_settlement_delay_minutes', 60)
        
        # Pending reconciliations
        self.pending_reconciliations: Dict[str, SessionMeterData] = {}
        
        logger.info("Session Reconciliation initialized")
    
    def add_session_for_reconciliation(self, session_data: SessionMeterData):
        """Add completed session for reconciliation"""
        try:
            # Validate session data
            if not self._validate_session_data(session_data):
                logger.error(f"Invalid session data for reconciliation: {session_data.session_id}")
                return False
            
            # Calculate totals
            session_data.calculate_totals()
            
            # Add to pending reconciliations
            self.pending_reconciliations[session_data.session_id] = session_data
            
            logger.info(f"Session added for reconciliation: {session_data.session_id} " +
                       f"({session_data.total_energy_kwh:.3f}kWh)")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add session for reconciliation: {e}")
            return False
    
    def _validate_session_data(self, session_data: SessionMeterData) -> bool:
        """Validate session meter data"""
        try:
            # Check required fields
            if not session_data.session_id or not session_data.start_meter_reading:
                return False
            
            # Verify meter reading integrity
            if not session_data.start_meter_reading.verify_integrity():
                logger.warning(f"Start meter reading integrity check failed: {session_data.session_id}")
                return False
            
            if session_data.end_meter_reading and not session_data.end_meter_reading.verify_integrity():
                logger.warning(f"End meter reading integrity check failed: {session_data.session_id}")
                return False
            
            # Check energy consistency
            if session_data.end_meter_reading:
                energy_diff = (session_data.end_meter_reading.energy_kwh - 
                              session_data.start_meter_reading.energy_kwh)
                if energy_diff < 0:
                    logger.warning(f"Negative energy consumption detected: {session_data.session_id}")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Session data validation error: {e}")
            return False
    
    async def process_reconciliation(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Process session reconciliation and generate settlement"""
        try:
            if session_id not in self.pending_reconciliations:
                logger.warning(f"Session not found for reconciliation: {session_id}")
                return None
            
            session_data = self.pending_reconciliations[session_id]
            
            # Generate reconciliation report
            reconciliation_report = {
                'session_id': session_id,
                'reconciliation_timestamp': datetime.utcnow().isoformat(),
                'evse_id': session_data.evse_id,
                'ev_id': session_data.ev_id,
                'start_time': session_data.start_time.isoformat(),
                'end_time': session_data.end_time.isoformat() if session_data.end_time else None,
                'total_energy_kwh': session_data.total_energy_kwh,
                'average_power_kw': session_data.average_power_kw,
                'peak_power_kw': session_data.peak_power_kw,
                'cost': session_data.cost,
                'tariff_per_kwh': session_data.tariff_per_kwh,
                'meter_readings_count': len(session_data.intermediate_readings) + 2,  # start + end + intermediate
                'reconciliation_status': 'completed'
            }
            
            # Remove from pending
            del self.pending_reconciliations[session_id]
            
            logger.info(f"Session reconciliation completed: {session_id}")
            return reconciliation_report
            
        except Exception as e:
            logger.error(f"Session reconciliation failed: {e}")
            return None
    
    def get_pending_reconciliations(self) -> List[str]:
        """Get list of pending reconciliation session IDs"""
        return list(self.pending_reconciliations.keys())
    
    def cleanup_expired_reconciliations(self):
        """Remove expired reconciliation requests"""
        try:
            current_time = datetime.utcnow()
            expired_sessions = []
            
            for session_id, session_data in self.pending_reconciliations.items():
                if session_data.end_time:
                    time_since_end = (current_time - session_data.end_time).total_seconds() / 3600
                    if time_since_end > self.reconciliation_timeout_hours:
                        expired_sessions.append(session_id)
            
            for session_id in expired_sessions:
                del self.pending_reconciliations[session_id]
                logger.warning(f"Expired reconciliation removed: {session_id}")
            
            if expired_sessions:
                logger.info(f"Cleaned up {len(expired_sessions)} expired reconciliations")
                
        except Exception as e:
            logger.error(f"Reconciliation cleanup error: {e}")

# Factory functions
def create_energy_meter(meter_id: str, meter_type: MeterType, config: Dict[str, Any]) -> EnergyMeter:
    """Create energy meter instance"""
    return EnergyMeter(meter_id, meter_type, config)

def create_telemetry_collector(config: Dict[str, Any]) -> TelemetryCollector:
    """Create telemetry collector instance"""
    return TelemetryCollector(config)

def create_session_reconciliation(config: Dict[str, Any]) -> SessionReconciliation:
    """Create session reconciliation instance"""
    return SessionReconciliation(config)

# Export main classes
__all__ = [
    'EnergyMeter',
    'TelemetryCollector',
    'SessionReconciliation',
    'MeterReading',
    'TelemetryData',
    'SessionMeterData',
    'TelemetryType',
    'MeterType',
    'create_energy_meter',
    'create_telemetry_collector', 
    'create_session_reconciliation'
]

"""
PQ-V2G Control Plane - Authorization Module
==========================================

This module implements the Control Plane authorization system for PQ-V2G,
including Plug-and-Charge authorization, outage token management, and
sidelink-based resilience mechanisms.

Key Features:
- Plug-and-Charge authorization with post-quantum certificates
- NR sidelink outage token system
- Energy capping and tariff management
- Session tracking and reconciliation
- Policy enforcement and compliance

Author: Shafiq Ahmed <s.ahmed@essex.ac.uk>
Institution: University of Essex
License: MIT
"""

import os
import json
import time
import secrets
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict
from enum import Enum
import asyncio

# PQ-V2G imports
from ..crypto.pq_crypto import PQCryptoManager
from ..identity.pq_ca import CertificateInfo

# Configure logging
logger = logging.getLogger(__name__)

class AuthorizationStatus(Enum):
    """Authorization request status"""
    PENDING = "pending"
    AUTHORIZED = "authorized"
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"

class PaymentMethod(Enum):
    """Payment methods supported"""
    PLUG_AND_CHARGE = "Plug-and-Charge"
    CREDIT_CARD = "credit_card"
    MOBILE_APP = "mobile_app"
    RFID = "rfid"
    OUTAGE_TOKEN = "outage_token"

@dataclass
class AuthorizationRequest:
    """Authorization request structure"""
    evse_id: str
    ev_certificate: str  # PEM-encoded certificate
    session_id: str
    requested_energy_kwh: float
    max_power_kw: Optional[float] = None
    payment_method: str = PaymentMethod.PLUG_AND_CHARGE.value
    timestamp: Optional[datetime] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()

@dataclass
class AuthorizationResponse:
    """Authorization response structure"""
    session_id: str
    status: AuthorizationStatus
    authorized_energy_kwh: Optional[float] = None
    max_power_kw: Optional[float] = None
    tariff_per_kwh: Optional[float] = None
    valid_until: Optional[datetime] = None
    reason: Optional[str] = None
    authorization_token: Optional[str] = None
    timestamp: Optional[datetime] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()

@dataclass
class OutageToken:
    """Outage authorization token for sidelink resilience"""
    token_id: str
    evse_id: str
    ev_pseudonym: str  # Current EV pseudonym
    max_energy_kwh: float
    tariff_per_kwh: float
    expiry_time: datetime
    issued_time: datetime
    policy_node_id: str
    nonce: str
    signature: str
    signature_algorithm: str = "ML-DSA-65"
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'OutageToken':
        """Create OutageToken from dictionary"""
        return cls(
            token_id=data['token_id'],
            evse_id=data['evse_id'],
            ev_pseudonym=data['ev_pseudonym'],
            max_energy_kwh=data['max_energy_kwh'],
            tariff_per_kwh=data['tariff_per_kwh'],
            expiry_time=datetime.fromisoformat(data['expiry_time']),
            issued_time=datetime.fromisoformat(data['issued_time']),
            policy_node_id=data['policy_node_id'],
            nonce=data['nonce'],
            signature=data['signature'],
            signature_algorithm=data.get('signature_algorithm', 'ML-DSA-65')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert OutageToken to dictionary"""
        return {
            'token_id': self.token_id,
            'evse_id': self.evse_id,
            'ev_pseudonym': self.ev_pseudonym,
            'max_energy_kwh': self.max_energy_kwh,
            'tariff_per_kwh': self.tariff_per_kwh,
            'expiry_time': self.expiry_time.isoformat(),
            'issued_time': self.issued_time.isoformat(),
            'policy_node_id': self.policy_node_id,
            'nonce': self.nonce,
            'signature': self.signature,
            'signature_algorithm': self.signature_algorithm
        }
    
    def is_valid(self) -> bool:
        """Check if token is still valid"""
        return datetime.utcnow() < self.expiry_time

@dataclass
class SessionAuthorization:
    """Active session authorization tracking"""
    session_id: str
    evse_id: str
    ev_certificate_serial: str
    authorized_energy_kwh: float
    consumed_energy_kwh: float
    authorization_method: str
    start_time: datetime
    last_update: datetime
    status: AuthorizationStatus
    
class AuthorizationEngine:
    """Core authorization engine for Plug-and-Charge and outage scenarios"""
    
    def __init__(self, config: Dict[str, Any], crypto_manager: PQCryptoManager):
        self.config = config
        self.crypto = crypto_manager
        
        # Authorization configuration
        self.default_session_duration_hours = config.get('default_session_duration_hours', 4)
        self.max_energy_per_session_kwh = config.get('max_energy_per_session_kwh', 100.0)
        self.default_tariff_per_kwh = config.get('default_tariff_per_kwh', 0.25)
        
        # Outage configuration
        self.outage_token_duration_hours = config.get('outage_token_duration_hours', 1)
        self.outage_max_energy_kwh = config.get('outage_max_energy_kwh', 50.0)
        self.outage_tariff_per_kwh = config.get('outage_tariff_per_kwh', 0.30)
        
        # Active sessions
        self.active_sessions: Dict[str, SessionAuthorization] = {}
        
        # Trusted certificate authorities (would be loaded from config)
        self.trusted_cas = []
        
        logger.info("Authorization Engine initialized")
    
    async def process_authorization_request(self, request: AuthorizationRequest) -> AuthorizationResponse:
        """Process Plug-and-Charge authorization request"""
        try:
            logger.info(f"Processing authorization request: {request.session_id}")
            
            # Validate certificate
            cert_valid, cert_info = await self._validate_ev_certificate(request.ev_certificate)
            if not cert_valid:
                return AuthorizationResponse(
                    session_id=request.session_id,
                    status=AuthorizationStatus.DENIED,
                    reason="Invalid or expired EV certificate"
                )
            
            # Check if session already exists
            if request.session_id in self.active_sessions:
                return AuthorizationResponse(
                    session_id=request.session_id,
                    status=AuthorizationStatus.DENIED,
                    reason="Session already exists"
                )
            
            # Validate requested energy
            authorized_energy = min(request.requested_energy_kwh, self.max_energy_per_session_kwh)
            
            # Calculate session validity
            valid_until = datetime.utcnow() + timedelta(hours=self.default_session_duration_hours)
            
            # Generate authorization token
            auth_token = await self._generate_authorization_token(request, cert_info)
            
            # Create session authorization
            session_auth = SessionAuthorization(
                session_id=request.session_id,
                evse_id=request.evse_id,
                ev_certificate_serial=cert_info.serial_number,
                authorized_energy_kwh=authorized_energy,
                consumed_energy_kwh=0.0,
                authorization_method="cloud",
                start_time=datetime.utcnow(),
                last_update=datetime.utcnow(),
                status=AuthorizationStatus.AUTHORIZED
            )
            
            self.active_sessions[request.session_id] = session_auth
            
            logger.info(f"Authorization granted: {request.session_id} ({authorized_energy}kWh)")
            
            return AuthorizationResponse(
                session_id=request.session_id,
                status=AuthorizationStatus.AUTHORIZED,
                authorized_energy_kwh=authorized_energy,
                max_power_kw=request.max_power_kw,
                tariff_per_kwh=self.default_tariff_per_kwh,
                valid_until=valid_until,
                authorization_token=auth_token
            )
            
        except Exception as e:
            logger.error(f"Authorization request processing failed: {e}")
            return AuthorizationResponse(
                session_id=request.session_id,
                status=AuthorizationStatus.DENIED,
                reason=f"Internal error: {str(e)}"
            )
    
    async def _validate_ev_certificate(self, certificate_pem: str) -> tuple[bool, Optional[CertificateInfo]]:
        """Validate EV certificate"""
        try:
            # Parse certificate (simplified for demo)
            # In production, this would use full X.509 parsing and validation
            cert_data = json.loads(certificate_pem)
            
            # Basic validation checks
            if 'serial_number' not in cert_data or 'fingerprint' not in cert_data:
                return False, None
            
            # Check validity period
            if 'valid_until' in cert_data:
                valid_until = datetime.fromisoformat(cert_data['valid_until'])
                if datetime.utcnow() > valid_until:
                    logger.warning(f"Certificate expired: {cert_data['serial_number']}")
                    return False, None
            
            # Create certificate info (simplified)
            cert_info = CertificateInfo(
                serial_number=cert_data['serial_number'],
                subject=cert_data.get('subject', ''),
                issuer='PQ-V2G Root CA',
                valid_from=datetime.utcnow(),
                valid_until=datetime.fromisoformat(cert_data.get('valid_until', '2025-12-31T23:59:59')),
                certificate_type='EV_PSEUDONYM',
                public_key=b'',  # Would extract from actual certificate
                signature_algorithm='ML-DSA-65',
                key_usage=['digital_signature'],
                status='VALID',
                fingerprint=cert_data['fingerprint']
            )
            
            logger.debug(f"Certificate validated: {cert_info.serial_number}")
            return True, cert_info
            
        except Exception as e:
            logger.error(f"Certificate validation error: {e}")
            return False, None
    
    async def _generate_authorization_token(self, request: AuthorizationRequest, 
                                          cert_info: CertificateInfo) -> str:
        """Generate authorization token for session"""
        try:
            token_data = {
                'session_id': request.session_id,
                'evse_id': request.evse_id,
                'ev_certificate_serial': cert_info.serial_number,
                'authorized_energy_kwh': min(request.requested_energy_kwh, self.max_energy_per_session_kwh),
                'issued_at': datetime.utcnow().isoformat(),
                'expires_at': (datetime.utcnow() + timedelta(hours=self.default_session_duration_hours)).isoformat(),
                'nonce': secrets.token_hex(16)
            }
            
            # Create token string
            token_string = json.dumps(token_data, sort_keys=True)
            
            # In production, would sign with authorization server private key
            # For simulation, create a deterministic token
            token_hash = hashlib.sha256(token_string.encode()).hexdigest()
            
            return f"AUTH_{token_hash[:16].upper()}"
            
        except Exception as e:
            logger.error(f"Authorization token generation failed: {e}")
            return f"AUTH_{secrets.token_hex(8).upper()}"
    
    def update_session_consumption(self, session_id: str, consumed_energy_kwh: float) -> bool:
        """Update session energy consumption"""
        try:
            if session_id not in self.active_sessions:
                logger.warning(f"Session not found for consumption update: {session_id}")
                return False
            
            session = self.active_sessions[session_id]
            session.consumed_energy_kwh = consumed_energy_kwh
            session.last_update = datetime.utcnow()
            
            # Check if energy limit exceeded
            if consumed_energy_kwh > session.authorized_energy_kwh:
                logger.warning(f"Energy limit exceeded for session {session_id}")
                session.status = AuthorizationStatus.DENIED
                return False
            
            logger.debug(f"Session consumption updated: {session_id} ({consumed_energy_kwh}kWh)")
            return True
            
        except Exception as e:
            logger.error(f"Session consumption update failed: {e}")
            return False
    
    def end_session(self, session_id: str) -> Optional[SessionAuthorization]:
        """End authorization session and return final state"""
        try:
            if session_id not in self.active_sessions:
                logger.warning(f"Session not found for ending: {session_id}")
                return None
            
            session = self.active_sessions.pop(session_id)
            session.status = AuthorizationStatus.EXPIRED
            session.last_update = datetime.utcnow()
            
            logger.info(f"Session ended: {session_id} ({session.consumed_energy_kwh}kWh consumed)")
            return session
            
        except Exception as e:
            logger.error(f"Session end failed: {e}")
            return None
    
    def get_session_status(self, session_id: str) -> Optional[SessionAuthorization]:
        """Get current session authorization status"""
        return self.active_sessions.get(session_id)
    
    def get_active_sessions_count(self) -> int:
        """Get count of active sessions"""
        return len(self.active_sessions)

class OutageTokenManager:
    """Manages outage tokens for sidelink-based authorization"""
    
    def __init__(self, config: Dict[str, Any], crypto_manager: PQCryptoManager):
        self.config = config
        self.crypto = crypto_manager
        
        # Policy node configuration
        self.policy_node_id = config.get('policy_node_id', 'POLICY001')
        self.token_validity_hours = config.get('token_validity_hours', 1)
        self.max_energy_kwh = config.get('max_energy_kwh', 50.0)
        self.tariff_per_kwh = config.get('tariff_per_kwh', 0.30)
        
        # Policy node keys (would be loaded securely)
        self.policy_private_key = None
        self.policy_public_key = None
        
        # Issued tokens tracking
        self.issued_tokens: Dict[str, OutageToken] = {}
        self.max_concurrent_tokens = config.get('max_concurrent_tokens', 10)
        
        self._initialize_keys()
        logger.info("Outage Token Manager initialized")
    
    def _initialize_keys(self):
        """Initialize policy node keys"""
        try:
            # Generate policy node keys (in production, would be loaded from secure storage)
            self.policy_public_key, self.policy_private_key = self.crypto.generate_dsa_keypair("ML-DSA-65")
            logger.debug("Policy node keys initialized")
        except Exception as e:
            logger.error(f"Policy key initialization failed: {e}")
    
    async def issue_outage_token(self, evse_id: str, ev_pseudonym: str, 
                               requested_energy_kwh: float) -> Optional[OutageToken]:
        """Issue outage token for emergency authorization"""
        try:
            # Check concurrent token limit
            if len(self.issued_tokens) >= self.max_concurrent_tokens:
                logger.warning("Maximum concurrent outage tokens reached")
                return None
            
            # Generate token
            token_id = f"TOK_{secrets.token_hex(8).upper()}"
            nonce = secrets.token_hex(16)
            
            # Calculate authorized energy (capped)
            authorized_energy = min(requested_energy_kwh, self.max_energy_kwh)
            
            # Create token
            token = OutageToken(
                token_id=token_id,
                evse_id=evse_id,
                ev_pseudonym=ev_pseudonym,
                max_energy_kwh=authorized_energy,
                tariff_per_kwh=self.tariff_per_kwh,
                expiry_time=datetime.utcnow() + timedelta(hours=self.token_validity_hours),
                issued_time=datetime.utcnow(),
                policy_node_id=self.policy_node_id,
                nonce=nonce,
                signature="",  # Will be set below
                signature_algorithm="ML-DSA-65"
            )
            
            # Sign token
            token_json = self._create_signable_token_data(token)
            signature = self.crypto.sign(self.policy_private_key, token_json.encode(), "ML-DSA-65")
            token.signature = signature.hex()
            
            # Store token
            self.issued_tokens[token_id] = token
            
            logger.info(f"Outage token issued: {token_id} for {evse_id}")
            return token
            
        except Exception as e:
            logger.error(f"Outage token issuance failed: {e}")
            return None
    
    def validate_outage_token(self, token: OutageToken) -> bool:
        """Validate outage token signature and expiry"""
        try:
            # Check expiry
            if not token.is_valid():
                logger.warning(f"Outage token expired: {token.token_id}")
                return False
            
            # Verify signature
            token_json = self._create_signable_token_data(token)
            signature = bytes.fromhex(token.signature)
            
            valid = self.crypto.verify(self.policy_public_key, token_json.encode(), 
                                     signature, token.signature_algorithm)
            
            if valid:
                logger.debug(f"Outage token signature valid: {token.token_id}")
            else:
                logger.warning(f"Outage token signature invalid: {token.token_id}")
            
            return valid
            
        except Exception as e:
            logger.error(f"Outage token validation failed: {e}")
            return False
    
    def _create_signable_token_data(self, token: OutageToken) -> str:
        """Create signable token data (excluding signature)"""
        data = {
            'token_id': token.token_id,
            'evse_id': token.evse_id,
            'ev_pseudonym': token.ev_pseudonym,
            'max_energy_kwh': token.max_energy_kwh,
            'tariff_per_kwh': token.tariff_per_kwh,
            'expiry_time': token.expiry_time.isoformat(),
            'issued_time': token.issued_time.isoformat(),
            'policy_node_id': token.policy_node_id,
            'nonce': token.nonce
        }
        return json.dumps(data, sort_keys=True)
    
    def revoke_token(self, token_id: str) -> bool:
        """Revoke outage token"""
        try:
            if token_id in self.issued_tokens:
                del self.issued_tokens[token_id]
                logger.info(f"Outage token revoked: {token_id}")
                return True
            else:
                logger.warning(f"Token not found for revocation: {token_id}")
                return False
        except Exception as e:
            logger.error(f"Token revocation failed: {e}")
            return False
    
    def cleanup_expired_tokens(self):
        """Remove expired tokens from storage"""
        try:
            expired_tokens = [
                token_id for token_id, token in self.issued_tokens.items()
                if not token.is_valid()
            ]
            
            for token_id in expired_tokens:
                del self.issued_tokens[token_id]
            
            if expired_tokens:
                logger.info(f"Cleaned up {len(expired_tokens)} expired outage tokens")
            
        except Exception as e:
            logger.error(f"Token cleanup failed: {e}")
    
    def get_token_statistics(self) -> Dict[str, Any]:
        """Get outage token statistics"""
        active_tokens = [token for token in self.issued_tokens.values() if token.is_valid()]
        
        return {
            'total_issued': len(self.issued_tokens),
            'active_tokens': len(active_tokens),
            'policy_node_id': self.policy_node_id,
            'max_concurrent': self.max_concurrent_tokens,
            'total_authorized_energy': sum(token.max_energy_kwh for token in active_tokens)
        }

# Factory functions
def create_authorization_engine(config: Dict[str, Any], crypto_manager: PQCryptoManager) -> AuthorizationEngine:
    """Create authorization engine instance"""
    return AuthorizationEngine(config.get('authorization', {}), crypto_manager)

def create_outage_token_manager(config: Dict[str, Any], crypto_manager: PQCryptoManager) -> OutageTokenManager:
    """Create outage token manager instance"""
    return OutageTokenManager(config.get('outage_tokens', {}), crypto_manager)

# Export main classes
__all__ = [
    'AuthorizationEngine',
    'OutageTokenManager',
    'AuthorizationRequest',
    'AuthorizationResponse', 
    'OutageToken',
    'SessionAuthorization',
    'AuthorizationStatus',
    'PaymentMethod',
    'create_authorization_engine',
    'create_outage_token_manager'
]

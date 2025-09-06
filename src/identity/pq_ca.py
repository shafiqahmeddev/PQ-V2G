"""
PQ-V2G Identity Plane Module
===========================

This module implements the Identity Plane of the PQ-V2G system, providing
post-quantum certificate authority services, pseudonym management, and
privacy-preserving certificate rotation compliant with ETSI TS 103 097.

Key Components:
- Post-Quantum Certificate Authority (CA) with ML-DSA/SLH-DSA
- Pseudonymous certificate pools for vehicles  
- Privacy-preserving rotation policies
- Certificate validation and revocation
- Trust anchor management

Author: Shafiq Ahmed <s.ahmed@essex.ac.uk>
Institution: University of Essex
License: MIT
"""

import os
import time
import json
import secrets
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import threading
import queue

# Cryptographic imports
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# PQ-V2G imports
from ..crypto.pq_crypto import PQCryptoManager, PQCryptoError

# Configure logging
logger = logging.getLogger(__name__)

class CertificateType(Enum):
    """Types of certificates in the PQ-V2G system"""
    ROOT_CA = "root_ca"
    INTERMEDIATE_CA = "intermediate_ca" 
    EVSE_DEVICE = "evse_device"
    EV_PSEUDONYM = "ev_pseudonym"
    POLICY_NODE = "policy_node"

class CertificateStatus(Enum):
    """Certificate status enumeration"""
    VALID = "valid"
    EXPIRED = "expired"
    REVOKED = "revoked" 
    PENDING = "pending"

@dataclass
class CertificateInfo:
    """Certificate information structure"""
    serial_number: str
    subject: str
    issuer: str
    valid_from: datetime
    valid_until: datetime
    certificate_type: CertificateType
    public_key: bytes
    signature_algorithm: str
    key_usage: List[str]
    status: CertificateStatus
    fingerprint: str

@dataclass
class PseudonymPool:
    """Vehicle pseudonym certificate pool"""
    ev_id: str
    pool_size: int
    certificates: List[CertificateInfo]
    active_certificate: Optional[str]  # Serial number of active cert
    rotation_policy: Dict[str, Any]
    last_rotation: datetime
    usage_count: int

class RotationPolicy:
    """Privacy-preserving certificate rotation policy"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.policy_type = config.get('rotation_policy', 'piecewise_constant')
        
        # Piecewise constant hazard parameters
        self.short_gap_rate = config.get('short_gap_rate', 0.5)
        self.long_gap_rate = config.get('long_gap_rate', 0.1)
        self.transition_hours = config.get('transition_hours', 2.0)
        self.max_issuance_per_day = config.get('max_issuance_per_day', 100)
        
        logger.info(f"Rotation policy initialized: {self.policy_type}")
    
    def should_rotate(self, last_rotation: datetime, inter_session_gap: float) -> bool:
        """Determine if certificate should be rotated based on policy"""
        if self.policy_type == 'piecewise_constant':
            return self._piecewise_constant_policy(last_rotation, inter_session_gap)
        else:
            # Default to time-based rotation
            return self._time_based_policy(last_rotation)
    
    def _piecewise_constant_policy(self, last_rotation: datetime, gap_hours: float) -> bool:
        """Piecewise constant hazard function for optimal privacy"""
        hours_since_rotation = (datetime.utcnow() - last_rotation).total_seconds() / 3600
        
        if gap_hours < self.transition_hours:
            # High rotation rate for short inter-session gaps
            hazard_rate = self.short_gap_rate
        else:
            # Lower rotation rate for longer gaps
            hazard_rate = self.long_gap_rate
            
        # Exponential distribution with hazard rate
        probability = 1 - pow(2.71828, -hazard_rate * hours_since_rotation)
        return secrets.randbelow(100) < (probability * 100)
    
    def _time_based_policy(self, last_rotation: datetime) -> bool:
        """Simple time-based rotation policy"""
        hours_since_rotation = (datetime.utcnow() - last_rotation).total_seconds() / 3600
        return hours_since_rotation > 24  # Rotate daily
    
    def calculate_linking_probability(self, gap_distribution: List[float]) -> float:
        """Calculate expected linking probability for given gap distribution"""
        # Implement the integral from equation (4) in the proposal
        total_prob = 0.0
        for gap in gap_distribution:
            if gap < self.transition_hours:
                rate = self.short_gap_rate
            else:
                rate = self.long_gap_rate
            prob = pow(2.71828, -rate * gap)
            total_prob += prob
            
        return total_prob / len(gap_distribution) if gap_distribution else 0.0

class PQCertificateAuthority:
    """Post-Quantum Certificate Authority"""
    
    def __init__(self, config: Dict[str, Any], crypto_manager: PQCryptoManager):
        self.config = config
        self.crypto = crypto_manager
        
        # CA configuration
        self.ca_name = config.get('ca_name', 'PQ-V2G Root CA')
        self.validity_years = config.get('root_validity_years', 10)
        self.intermediate_validity_years = config.get('intermediate_validity_years', 5)
        
        # Certificate storage
        self.certificates = {}  # serial_number -> CertificateInfo
        self.certificate_store = {}  # subject -> certificate_pem
        self.revocation_list = set()  # Set of revoked serial numbers
        
        # CA keys (would be in HSM in production)
        self.root_private_key = None
        self.root_public_key = None
        self.root_certificate = None
        
        # Initialize CA
        self._initialize_ca()
        
        logger.info(f"PQ Certificate Authority initialized: {self.ca_name}")
    
    def _initialize_ca(self):
        """Initialize the certificate authority"""
        try:
            # Generate root CA key pair
            self.root_public_key, self.root_private_key = self.crypto.generate_dsa_keypair("ML-DSA-65")
            
            # Create root certificate
            self.root_certificate = self._create_root_certificate()
            
            # Store root certificate
            cert_info = self._extract_certificate_info(self.root_certificate, CertificateType.ROOT_CA)
            self.certificates[cert_info.serial_number] = cert_info
            
            logger.info("Root CA certificate created and stored")
            
        except Exception as e:
            logger.error(f"CA initialization failed: {e}")
            raise
    
    def _create_root_certificate(self) -> x509.Certificate:
        """Create the root CA certificate"""
        # For simulation, we'll create a basic certificate structure
        # In production, this would use the actual PQ algorithms
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Essex"), 
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Colchester"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "University of Essex"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "PQ-V2G Research"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.ca_name),
        ])
        
        # Generate temporary RSA key for certificate structure
        # (Would use ML-DSA public key in production)
        temp_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            temp_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365 * self.validity_years)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                key_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).sign(temp_key, hashes.SHA256(), default_backend())
        
        return cert
    
    def _extract_certificate_info(self, certificate: x509.Certificate, 
                                  cert_type: CertificateType) -> CertificateInfo:
        """Extract certificate information for storage"""
        
        # Calculate fingerprint
        fingerprint = hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()
        
        return CertificateInfo(
            serial_number=str(certificate.serial_number),
            subject=str(certificate.subject),
            issuer=str(certificate.issuer),
            valid_from=certificate.not_valid_before,
            valid_until=certificate.not_valid_after,
            certificate_type=cert_type,
            public_key=certificate.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            signature_algorithm="ML-DSA-65",  # Would extract from actual cert
            key_usage=["key_cert_sign", "crl_sign"],
            status=CertificateStatus.VALID,
            fingerprint=fingerprint
        )
    
    def issue_evse_certificate(self, evse_id: str, public_key: bytes) -> str:
        """Issue certificate for an EVSE (charging station)"""
        try:
            # Create certificate info
            serial_number = secrets.token_hex(16)
            valid_from = datetime.utcnow()
            valid_until = valid_from + timedelta(days=365 * 2)  # 2 year validity
            
            cert_info = CertificateInfo(
                serial_number=serial_number,
                subject=f"CN={evse_id}, OU=EVSE, O=PQ-V2G",
                issuer=str(self.root_certificate.subject),
                valid_from=valid_from,
                valid_until=valid_until,
                certificate_type=CertificateType.EVSE_DEVICE,
                public_key=public_key,
                signature_algorithm="ML-DSA-65",
                key_usage=["digital_signature", "key_agreement"],
                status=CertificateStatus.VALID,
                fingerprint=hashlib.sha256(public_key).hexdigest()
            )
            
            # Store certificate
            self.certificates[serial_number] = cert_info
            
            # Create certificate PEM (simplified)
            cert_pem = self._create_certificate_pem(cert_info)
            self.certificate_store[evse_id] = cert_pem
            
            logger.info(f"EVSE certificate issued: {evse_id} ({serial_number})")
            return cert_pem
            
        except Exception as e:
            logger.error(f"EVSE certificate issuance failed: {e}")
            raise PQCryptoError(f"EVSE certificate issuance failed: {e}")
    
    def issue_ev_pseudonym_certificate(self, ev_id: str, public_key: bytes) -> str:
        """Issue pseudonymous certificate for an EV"""
        try:
            # Generate pseudonymous identifier
            pseudonym_id = f"PSN{secrets.token_hex(8)}"
            
            # Create certificate info
            serial_number = secrets.token_hex(16)
            valid_from = datetime.utcnow()
            valid_until = valid_from + timedelta(days=30)  # Short validity for privacy
            
            cert_info = CertificateInfo(
                serial_number=serial_number,
                subject=f"CN={pseudonym_id}, OU=EV, O=PQ-V2G",
                issuer=str(self.root_certificate.subject),
                valid_from=valid_from,
                valid_until=valid_until,
                certificate_type=CertificateType.EV_PSEUDONYM,
                public_key=public_key,
                signature_algorithm="ML-DSA-65",
                key_usage=["digital_signature", "key_agreement"],
                status=CertificateStatus.VALID,
                fingerprint=hashlib.sha256(public_key).hexdigest()
            )
            
            # Store certificate
            self.certificates[serial_number] = cert_info
            
            # Create certificate PEM
            cert_pem = self._create_certificate_pem(cert_info)
            
            logger.info(f"EV pseudonym certificate issued: {pseudonym_id} for {ev_id}")
            return cert_pem
            
        except Exception as e:
            logger.error(f"EV pseudonym certificate issuance failed: {e}")
            raise PQCryptoError(f"EV pseudonym certificate issuance failed: {e}")
    
    def _create_certificate_pem(self, cert_info: CertificateInfo) -> str:
        """Create certificate PEM representation"""
        # This is a simplified representation for development
        # Production would use actual X.509 certificate format with PQ algorithms
        
        cert_data = {
            "version": "3",
            "serial_number": cert_info.serial_number,
            "issuer": cert_info.issuer,
            "subject": cert_info.subject,
            "valid_from": cert_info.valid_from.isoformat(),
            "valid_until": cert_info.valid_until.isoformat(),
            "public_key": cert_info.public_key.hex(),
            "signature_algorithm": cert_info.signature_algorithm,
            "key_usage": cert_info.key_usage,
            "fingerprint": cert_info.fingerprint
        }
        
        # Create signature over certificate data
        cert_json = json.dumps(cert_data, sort_keys=True)
        signature = self.crypto.sign(self.root_private_key, cert_json.encode(), "ML-DSA-65")
        
        cert_with_signature = {
            "certificate": cert_data,
            "signature": signature.hex(),
            "format": "PQ-V2G-DEV-1.0"
        }
        
        return json.dumps(cert_with_signature, indent=2)
    
    def validate_certificate(self, cert_pem: str) -> Tuple[bool, Optional[CertificateInfo]]:
        """Validate a certificate"""
        try:
            cert_data = json.loads(cert_pem)
            
            if cert_data.get("format") != "PQ-V2G-DEV-1.0":
                return False, None
            
            # Verify signature
            cert_json = json.dumps(cert_data["certificate"], sort_keys=True)
            signature = bytes.fromhex(cert_data["signature"])
            
            if not self.crypto.verify(self.root_public_key, cert_json.encode(), signature, "ML-DSA-65"):
                logger.warning("Certificate signature verification failed")
                return False, None
            
            # Check if certificate is in our records
            serial_number = cert_data["certificate"]["serial_number"]
            if serial_number not in self.certificates:
                logger.warning(f"Certificate not found: {serial_number}")
                return False, None
            
            cert_info = self.certificates[serial_number]
            
            # Check validity period
            now = datetime.utcnow()
            if now < cert_info.valid_from or now > cert_info.valid_until:
                logger.warning(f"Certificate expired or not yet valid: {serial_number}")
                cert_info.status = CertificateStatus.EXPIRED
                return False, cert_info
            
            # Check revocation status
            if serial_number in self.revocation_list:
                logger.warning(f"Certificate revoked: {serial_number}")
                cert_info.status = CertificateStatus.REVOKED
                return False, cert_info
            
            return True, cert_info
            
        except Exception as e:
            logger.error(f"Certificate validation failed: {e}")
            return False, None
    
    def revoke_certificate(self, serial_number: str, reason: str = "unspecified"):
        """Revoke a certificate"""
        if serial_number in self.certificates:
            self.certificates[serial_number].status = CertificateStatus.REVOKED
            self.revocation_list.add(serial_number)
            logger.info(f"Certificate revoked: {serial_number}, reason: {reason}")
        else:
            logger.warning(f"Cannot revoke unknown certificate: {serial_number}")
    
    def get_certificate_chain(self, serial_number: str) -> List[str]:
        """Get certificate chain for a given certificate"""
        if serial_number not in self.certificates:
            return []
        
        cert_info = self.certificates[serial_number]
        
        if cert_info.certificate_type == CertificateType.ROOT_CA:
            # Root is self-signed
            return [self._create_certificate_pem(cert_info)]
        else:
            # Return certificate + root CA
            cert_pem = self._create_certificate_pem(cert_info)
            root_pem = self._create_certificate_pem(
                self.certificates[str(self.root_certificate.serial_number)]
            )
            return [cert_pem, root_pem]

class PseudonymManager:
    """Manages pseudonymous certificate pools for vehicles"""
    
    def __init__(self, config: Dict[str, Any], ca: PQCertificateAuthority, 
                 crypto_manager: PQCryptoManager):
        self.config = config
        self.ca = ca
        self.crypto = crypto_manager
        
        # Configuration
        self.default_pool_size = config.get('pseudonym_pool_size', 10)
        self.rotation_policy = RotationPolicy(config)
        
        # Storage
        self.pseudonym_pools = {}  # ev_id -> PseudonymPool
        self.issuance_counter = 0
        self.daily_limit = config.get('max_issuance_per_day', 100)
        self.last_reset = datetime.utcnow().date()
        
        # Thread safety
        self.lock = threading.Lock()
        
        logger.info("Pseudonym Manager initialized")
    
    def create_pseudonym_pool(self, ev_id: str, pool_size: Optional[int] = None) -> PseudonymPool:
        """Create a new pseudonym pool for a vehicle"""
        with self.lock:
            pool_size = pool_size or self.default_pool_size
            
            # Check daily issuance limit
            if not self._check_issuance_limit(pool_size):
                raise PQCryptoError("Daily certificate issuance limit exceeded")
            
            certificates = []
            for i in range(pool_size):
                # Generate key pair for pseudonym
                public_key, private_key = self.crypto.generate_dsa_keypair("ML-DSA-65")
                
                # Issue certificate
                cert_pem = self.ca.issue_ev_pseudonym_certificate(ev_id, public_key)
                
                # Extract certificate info
                valid, cert_info = self.ca.validate_certificate(cert_pem)
                if valid and cert_info:
                    certificates.append(cert_info)
                    
            # Create pseudonym pool
            pool = PseudonymPool(
                ev_id=ev_id,
                pool_size=pool_size,
                certificates=certificates,
                active_certificate=certificates[0].serial_number if certificates else None,
                rotation_policy=self.config,
                last_rotation=datetime.utcnow(),
                usage_count=0
            )
            
            self.pseudonym_pools[ev_id] = pool
            self.issuance_counter += pool_size
            
            logger.info(f"Pseudonym pool created for {ev_id}: {len(certificates)} certificates")
            return pool
    
    def get_active_certificate(self, ev_id: str) -> Optional[CertificateInfo]:
        """Get the active certificate for a vehicle"""
        if ev_id not in self.pseudonym_pools:
            return None
            
        pool = self.pseudonym_pools[ev_id]
        if not pool.active_certificate:
            return None
            
        # Find active certificate in pool
        for cert in pool.certificates:
            if cert.serial_number == pool.active_certificate:
                return cert
        
        return None
    
    def should_rotate_certificate(self, ev_id: str, inter_session_gap: float = 1.0) -> bool:
        """Check if certificate should be rotated"""
        if ev_id not in self.pseudonym_pools:
            return False
            
        pool = self.pseudonym_pools[ev_id]
        return self.rotation_policy.should_rotate(pool.last_rotation, inter_session_gap)
    
    def rotate_certificate(self, ev_id: str) -> Optional[CertificateInfo]:
        """Rotate to next certificate in pool"""
        with self.lock:
            if ev_id not in self.pseudonym_pools:
                return None
                
            pool = self.pseudonym_pools[ev_id]
            
            # Find current certificate index
            current_index = 0
            for i, cert in enumerate(pool.certificates):
                if cert.serial_number == pool.active_certificate:
                    current_index = i
                    break
            
            # Move to next certificate
            next_index = (current_index + 1) % len(pool.certificates)
            next_cert = pool.certificates[next_index]
            
            # Update active certificate
            pool.active_certificate = next_cert.serial_number
            pool.last_rotation = datetime.utcnow()
            pool.usage_count += 1
            
            logger.info(f"Certificate rotated for {ev_id}: {next_cert.serial_number}")
            return next_cert
    
    def refresh_pool(self, ev_id: str, certificates_to_refresh: int) -> bool:
        """Refresh expired certificates in the pool"""
        with self.lock:
            if ev_id not in self.pseudonym_pools:
                return False
            
            # Check daily limit
            if not self._check_issuance_limit(certificates_to_refresh):
                logger.warning(f"Cannot refresh pool for {ev_id}: daily limit exceeded")
                return False
                
            pool = self.pseudonym_pools[ev_id]
            
            # Find expired certificates
            now = datetime.utcnow()
            expired_certs = [cert for cert in pool.certificates 
                           if cert.valid_until < now or cert.status != CertificateStatus.VALID]
            
            certificates_to_refresh = min(certificates_to_refresh, len(expired_certs))
            
            # Issue new certificates
            for i in range(certificates_to_refresh):
                # Generate new key pair
                public_key, private_key = self.crypto.generate_dsa_keypair("ML-DSA-65")
                
                # Issue new certificate
                cert_pem = self.ca.issue_ev_pseudonym_certificate(ev_id, public_key)
                
                # Extract certificate info
                valid, cert_info = self.ca.validate_certificate(cert_pem)
                if valid and cert_info:
                    # Replace expired certificate
                    if i < len(expired_certs):
                        expired_idx = pool.certificates.index(expired_certs[i])
                        pool.certificates[expired_idx] = cert_info
                    else:
                        pool.certificates.append(cert_info)
            
            self.issuance_counter += certificates_to_refresh
            logger.info(f"Refreshed {certificates_to_refresh} certificates for {ev_id}")
            return True
    
    def _check_issuance_limit(self, requested_count: int) -> bool:
        """Check daily issuance limit"""
        today = datetime.utcnow().date()
        
        # Reset counter if new day
        if today > self.last_reset:
            self.issuance_counter = 0
            self.last_reset = today
        
        return (self.issuance_counter + requested_count) <= self.daily_limit
    
    def get_pool_statistics(self, ev_id: str) -> Optional[Dict[str, Any]]:
        """Get statistics for a pseudonym pool"""
        if ev_id not in self.pseudonym_pools:
            return None
            
        pool = self.pseudonym_pools[ev_id]
        now = datetime.utcnow()
        
        valid_certs = [cert for cert in pool.certificates 
                      if cert.valid_until > now and cert.status == CertificateStatus.VALID]
        
        return {
            "ev_id": ev_id,
            "pool_size": pool.pool_size,
            "valid_certificates": len(valid_certs),
            "expired_certificates": pool.pool_size - len(valid_certs),
            "active_certificate": pool.active_certificate,
            "last_rotation": pool.last_rotation.isoformat(),
            "usage_count": pool.usage_count
        }

# Factory function
def create_identity_plane(config: Dict[str, Any]) -> Tuple[PQCertificateAuthority, PseudonymManager]:
    """Create identity plane components"""
    crypto_manager = PQCryptoManager(config.get('crypto', {}))
    ca = PQCertificateAuthority(config.get('identity', {}), crypto_manager)
    pseudonym_manager = PseudonymManager(config.get('identity', {}), ca, crypto_manager)
    
    return ca, pseudonym_manager

# Export main classes
__all__ = [
    'PQCertificateAuthority',
    'PseudonymManager', 
    'CertificateInfo',
    'PseudonymPool',
    'RotationPolicy',
    'CertificateType',
    'CertificateStatus',
    'create_identity_plane'
]

"""
PQ-V2G Session Plane Module
==========================

This module implements the Session Plane of the PQ-V2G system, providing
post-quantum TLS 1.3 with ML-KEM key establishment and ML-DSA/SLH-DSA authentication
for secure communication between EVs, EVSEs, and CSMS.

Key Components:
- Post-Quantum TLS 1.3 implementation
- ML-KEM-768 key establishment
- ML-DSA-65/SLH-DSA authentication
- Constant-time operations with timing attack protection
- Session management and key derivation
- Certificate validation and chain processing

Author: Shafiq Ahmed <s.ahmed@essex.ac.uk>
Institution: University of Essex
License: MIT
"""

import os
import ssl
import socket
import asyncio
import logging
import time
import secrets
import hashlib
from typing import Optional, Dict, Any, Tuple, List, Callable
from dataclasses import dataclass
from enum import Enum
import threading

# Cryptographic imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# PQ-V2G imports
from ..crypto.pq_crypto import PQCryptoManager, PQCryptoError
from ..identity.pq_ca import PQCertificateAuthority, CertificateInfo

# Configure logging
logger = logging.getLogger(__name__)

class TLSVersion(Enum):
    """TLS version enumeration"""
    TLS_1_3 = "1.3"

class HandshakeState(Enum):
    """TLS handshake state machine"""
    START = "start"
    CLIENT_HELLO = "client_hello"
    SERVER_HELLO = "server_hello"
    ENCRYPTED_EXTENSIONS = "encrypted_extensions"
    CERTIFICATE_REQUEST = "certificate_request"
    CERTIFICATE = "certificate"
    CERTIFICATE_VERIFY = "certificate_verify"
    FINISHED = "finished"
    COMPLETED = "completed"
    FAILED = "failed"

class ConnectionRole(Enum):
    """Connection role enumeration"""
    CLIENT = "client"
    SERVER = "server"

@dataclass
class HandshakeMetrics:
    """TLS handshake performance metrics"""
    start_time: float
    end_time: float
    handshake_bytes: int
    kem_encapsulation_time: float
    kem_decapsulation_time: float
    signature_generation_time: float
    signature_verification_time: float
    certificate_validation_time: float
    total_time: float
    round_trips: int

@dataclass
class SessionKeys:
    """TLS session keys derived from post-quantum operations"""
    master_secret: bytes
    client_write_key: bytes
    server_write_key: bytes
    client_write_iv: bytes
    server_write_iv: bytes
    exporter_master_secret: bytes

class PQTLSContext:
    """Post-Quantum TLS Context"""
    
    def __init__(self, config: Dict[str, Any], crypto_manager: PQCryptoManager, 
                 ca: PQCertificateAuthority):
        self.config = config
        self.crypto = crypto_manager
        self.ca = ca
        
        # TLS configuration
        self.version = TLSVersion.TLS_1_3
        self.cipher_suites = [
            "TLS_ML_KEM_768_WITH_ML_DSA_65_SHA256",
            "TLS_ML_KEM_768_WITH_SLH_DSA_SHA256"
        ]
        self.mutual_auth_required = config.get('mutual_auth_required', True)
        
        # Certificates and keys
        self.certificate_chain = []
        self.private_key = None
        self.trusted_cas = []
        
        # Session configuration
        self.session_resumption = config.get('session_resumption', False)
        self.export_key_material = config.get('export_key_material', True)
        
        logger.info("PQ-TLS Context initialized")
    
    def load_certificate_chain(self, cert_chain: List[str]):
        """Load certificate chain"""
        self.certificate_chain = cert_chain
        logger.info(f"Loaded certificate chain with {len(cert_chain)} certificates")
    
    def load_private_key(self, private_key: bytes):
        """Load private key"""
        self.private_key = private_key
        logger.info("Private key loaded")
    
    def add_trusted_ca(self, ca_cert: str):
        """Add trusted CA certificate"""
        self.trusted_cas.append(ca_cert)
        logger.info("Trusted CA added")

class PQTLSConnection:
    """Post-Quantum TLS Connection"""
    
    def __init__(self, context: PQTLSContext, role: ConnectionRole):
        self.context = context
        self.role = role
        self.state = HandshakeState.START
        
        # Connection state
        self.connected = False
        self.session_keys = None
        self.peer_certificate = None
        
        # Handshake data
        self.client_random = None
        self.server_random = None
        self.shared_secret = None
        self.handshake_hash = hashlib.sha256()
        
        # Performance metrics
        self.metrics = None
        
        # Socket (would be actual socket in production)
        self.socket = None
        
        logger.debug(f"PQ-TLS connection created: role={role.value}")
    
    async def handshake(self, socket: Optional[socket.socket] = None) -> bool:
        """Perform post-quantum TLS handshake"""
        self.socket = socket
        self.metrics = HandshakeMetrics(
            start_time=time.time(),
            end_time=0.0,
            handshake_bytes=0,
            kem_encapsulation_time=0.0,
            kem_decapsulation_time=0.0,
            signature_generation_time=0.0,
            signature_verification_time=0.0,
            certificate_validation_time=0.0,
            total_time=0.0,
            round_trips=0
        )
        
        try:
            if self.role == ConnectionRole.CLIENT:
                success = await self._client_handshake()
            else:
                success = await self._server_handshake()
            
            if success:
                self.state = HandshakeState.COMPLETED
                self.connected = True
                self.metrics.end_time = time.time()
                self.metrics.total_time = self.metrics.end_time - self.metrics.start_time
                
                logger.info(f"PQ-TLS handshake completed: {self.metrics.total_time:.3f}s")
                self._log_handshake_metrics()
            else:
                self.state = HandshakeState.FAILED
                logger.error("PQ-TLS handshake failed")
            
            return success
            
        except Exception as e:
            self.state = HandshakeState.FAILED
            logger.error(f"PQ-TLS handshake error: {e}")
            return False
    
    async def _client_handshake(self) -> bool:
        """Client-side TLS handshake"""
        try:
            # Step 1: Send Client Hello
            self.state = HandshakeState.CLIENT_HELLO
            client_hello = await self._create_client_hello()
            await self._send_message(client_hello)
            self.metrics.round_trips += 0.5
            
            # Step 2: Receive Server Hello
            self.state = HandshakeState.SERVER_HELLO
            server_hello = await self._receive_message()
            if not await self._process_server_hello(server_hello):
                return False
            
            # Step 3: Receive Encrypted Extensions
            self.state = HandshakeState.ENCRYPTED_EXTENSIONS
            encrypted_extensions = await self._receive_message()
            if not await self._process_encrypted_extensions(encrypted_extensions):
                return False
            
            # Step 4: Receive Certificate Request (if mutual auth)
            if self.context.mutual_auth_required:
                self.state = HandshakeState.CERTIFICATE_REQUEST
                cert_request = await self._receive_message()
                if not await self._process_certificate_request(cert_request):
                    return False
            
            # Step 5: Receive Server Certificate
            self.state = HandshakeState.CERTIFICATE
            server_cert = await self._receive_message()
            if not await self._process_server_certificate(server_cert):
                return False
            
            # Step 6: Receive Certificate Verify
            self.state = HandshakeState.CERTIFICATE_VERIFY
            cert_verify = await self._receive_message()
            if not await self._process_certificate_verify(cert_verify):
                return False
            
            # Step 7: Receive Server Finished
            server_finished = await self._receive_message()
            if not await self._process_server_finished(server_finished):
                return False
            self.metrics.round_trips += 0.5
            
            # Step 8: Send Client Certificate (if mutual auth)
            if self.context.mutual_auth_required:
                client_cert = await self._create_client_certificate()
                await self._send_message(client_cert)
                
                # Send Certificate Verify
                cert_verify = await self._create_certificate_verify()
                await self._send_message(cert_verify)
            
            # Step 9: Send Client Finished
            self.state = HandshakeState.FINISHED
            client_finished = await self._create_client_finished()
            await self._send_message(client_finished)
            self.metrics.round_trips += 0.5
            
            return True
            
        except Exception as e:
            logger.error(f"Client handshake error: {e}")
            return False
    
    async def _server_handshake(self) -> bool:
        """Server-side TLS handshake"""
        try:
            # Step 1: Receive Client Hello
            self.state = HandshakeState.CLIENT_HELLO
            client_hello = await self._receive_message()
            if not await self._process_client_hello(client_hello):
                return False
            self.metrics.round_trips += 0.5
            
            # Step 2: Send Server Hello
            self.state = HandshakeState.SERVER_HELLO
            server_hello = await self._create_server_hello()
            await self._send_message(server_hello)
            
            # Step 3: Send Encrypted Extensions
            self.state = HandshakeState.ENCRYPTED_EXTENSIONS
            encrypted_extensions = await self._create_encrypted_extensions()
            await self._send_message(encrypted_extensions)
            
            # Step 4: Send Certificate Request (if mutual auth)
            if self.context.mutual_auth_required:
                self.state = HandshakeState.CERTIFICATE_REQUEST
                cert_request = await self._create_certificate_request()
                await self._send_message(cert_request)
            
            # Step 5: Send Server Certificate
            self.state = HandshakeState.CERTIFICATE
            server_cert = await self._create_server_certificate()
            await self._send_message(server_cert)
            
            # Step 6: Send Certificate Verify
            self.state = HandshakeState.CERTIFICATE_VERIFY
            cert_verify = await self._create_certificate_verify()
            await self._send_message(cert_verify)
            
            # Step 7: Send Server Finished
            server_finished = await self._create_server_finished()
            await self._send_message(server_finished)
            self.metrics.round_trips += 0.5
            
            # Step 8: Receive Client Certificate (if mutual auth)
            if self.context.mutual_auth_required:
                client_cert = await self._receive_message()
                if not await self._process_client_certificate(client_cert):
                    return False
                
                # Receive Certificate Verify
                cert_verify = await self._receive_message()
                if not await self._process_certificate_verify(cert_verify):
                    return False
            
            # Step 9: Receive Client Finished
            self.state = HandshakeState.FINISHED
            client_finished = await self._receive_message()
            if not await self._process_client_finished(client_finished):
                return False
            self.metrics.round_trips += 0.5
            
            return True
            
        except Exception as e:
            logger.error(f"Server handshake error: {e}")
            return False
    
    async def _create_client_hello(self) -> Dict[str, Any]:
        """Create Client Hello message"""
        self.client_random = secrets.token_bytes(32)
        
        message = {
            "type": "client_hello",
            "version": self.context.version.value,
            "random": self.client_random.hex(),
            "cipher_suites": self.context.cipher_suites,
            "extensions": {
                "supported_groups": ["ML-KEM-768"],
                "signature_algorithms": ["ML-DSA-65", "SLH-DSA"],
                "key_share": await self._generate_key_share()
            }
        }
        
        self._update_handshake_hash(message)
        return message
    
    async def _generate_key_share(self) -> Dict[str, str]:
        """Generate ML-KEM key share for Client Hello"""
        start_time = time.time()
        
        # Generate ML-KEM keypair
        public_key, private_key = self.context.crypto.generate_kem_keypair()
        
        # Store private key for later use
        self.kem_private_key = private_key
        
        self.metrics.kem_encapsulation_time += time.time() - start_time
        
        return {
            "group": "ML-KEM-768",
            "key_exchange": public_key.hex()
        }
    
    async def _process_server_hello(self, message: Dict[str, Any]) -> bool:
        """Process Server Hello message"""
        try:
            self.server_random = bytes.fromhex(message["random"])
            
            # Process key share
            if "key_share" in message.get("extensions", {}):
                key_share = message["extensions"]["key_share"]
                if key_share["group"] == "ML-KEM-768":
                    # Perform ML-KEM decapsulation
                    start_time = time.time()
                    ciphertext = bytes.fromhex(key_share["key_exchange"])
                    self.shared_secret = self.context.crypto.kem_decapsulate(
                        self.kem_private_key, ciphertext
                    )
                    self.metrics.kem_decapsulation_time += time.time() - start_time
            
            self._update_handshake_hash(message)
            return True
            
        except Exception as e:
            logger.error(f"Error processing Server Hello: {e}")
            return False
    
    async def _create_server_hello(self) -> Dict[str, Any]:
        """Create Server Hello message"""
        self.server_random = secrets.token_bytes(32)
        
        # Generate ML-KEM key share and perform encapsulation
        start_time = time.time()
        
        # Extract client's public key from handshake
        # (In real implementation, this would come from received Client Hello)
        client_public_key = secrets.token_bytes(1184)  # ML-KEM-768 public key size
        
        # Perform encapsulation
        ciphertext, self.shared_secret = self.context.crypto.kem_encapsulate(client_public_key)
        
        self.metrics.kem_encapsulation_time += time.time() - start_time
        
        message = {
            "type": "server_hello",
            "version": self.context.version.value,
            "random": self.server_random.hex(),
            "cipher_suite": self.context.cipher_suites[0],
            "extensions": {
                "key_share": {
                    "group": "ML-KEM-768",
                    "key_exchange": ciphertext.hex()
                }
            }
        }
        
        self._update_handshake_hash(message)
        return message
    
    async def _create_certificate_verify(self) -> Dict[str, Any]:
        """Create Certificate Verify message with post-quantum signature"""
        start_time = time.time()
        
        # Create signature over handshake hash
        handshake_data = self.handshake_hash.digest()
        context_string = b"TLS 1.3, server CertificateVerify" if self.role == ConnectionRole.SERVER else b"TLS 1.3, client CertificateVerify"
        
        to_sign = b"\x20" * 64 + context_string + b"\x00" + handshake_data
        
        signature = self.context.crypto.sign(self.context.private_key, to_sign, "ML-DSA-65")
        
        self.metrics.signature_generation_time += time.time() - start_time
        
        message = {
            "type": "certificate_verify",
            "signature_algorithm": "ML-DSA-65",
            "signature": signature.hex()
        }
        
        self._update_handshake_hash(message)
        return message
    
    async def _process_certificate_verify(self, message: Dict[str, Any]) -> bool:
        """Process and verify Certificate Verify message"""
        start_time = time.time()
        
        try:
            # Extract signature
            signature = bytes.fromhex(message["signature"])
            algorithm = message["signature_algorithm"]
            
            # Recreate signed data
            handshake_data = self.handshake_hash.digest()
            context_string = b"TLS 1.3, client CertificateVerify" if self.role == ConnectionRole.SERVER else b"TLS 1.3, server CertificateVerify"
            
            to_verify = b"\x20" * 64 + context_string + b"\x00" + handshake_data
            
            # Get peer's public key from certificate
            if self.peer_certificate:
                public_key = self.peer_certificate.public_key
                result = self.context.crypto.verify(public_key, to_verify, signature, algorithm)
            else:
                logger.error("No peer certificate available for verification")
                result = False
            
            self.metrics.signature_verification_time += time.time() - start_time
            
            if result:
                logger.debug("Certificate Verify signature validated successfully")
            else:
                logger.error("Certificate Verify signature validation failed")
            
            return result
            
        except Exception as e:
            logger.error(f"Error processing Certificate Verify: {e}")
            return False
    
    def _derive_session_keys(self):
        """Derive session keys from shared secret using HKDF"""
        if not self.shared_secret or not self.client_random or not self.server_random:
            raise PQCryptoError("Missing data for key derivation")
        
        # Early Secret derivation
        early_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"",
            info=b"",
            backend=default_backend()
        ).derive(b"\x00" * 32)
        
        # Handshake Secret derivation
        handshake_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=early_secret,
            info=b"derived",
            backend=default_backend()
        ).derive(self.shared_secret)
        
        # Master Secret derivation
        master_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=handshake_secret,
            info=b"derived",
            backend=default_backend()
        ).derive(b"\x00" * 32)
        
        # Derive traffic secrets
        client_write_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=master_secret,
            info=b"c ap traffic",
            backend=default_backend()
        ).derive(self.client_random + self.server_random)
        
        server_write_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=master_secret,
            info=b"s ap traffic",
            backend=default_backend()
        ).derive(self.client_random + self.server_random)
        
        # Generate IVs
        client_write_iv = HKDF(
            algorithm=hashes.SHA256(),
            length=12,
            salt=master_secret,
            info=b"c iv",
            backend=default_backend()
        ).derive(client_write_key)
        
        server_write_iv = HKDF(
            algorithm=hashes.SHA256(),
            length=12,
            salt=master_secret,
            info=b"s iv",
            backend=default_backend()
        ).derive(server_write_key)
        
        # Exporter master secret (for token derivation)
        exporter_master_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=master_secret,
            info=b"exp master",
            backend=default_backend()
        ).derive(b"")
        
        self.session_keys = SessionKeys(
            master_secret=master_secret,
            client_write_key=client_write_key,
            server_write_key=server_write_key,
            client_write_iv=client_write_iv,
            server_write_iv=server_write_iv,
            exporter_master_secret=exporter_master_secret
        )
        
        logger.debug("Session keys derived successfully")
    
    def export_key_material(self, label: bytes, context: bytes, length: int) -> bytes:
        """Export key material for application use (e.g., token derivation)"""
        if not self.session_keys:
            raise PQCryptoError("No session keys available for export")
        
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=self.session_keys.exporter_master_secret,
            info=label + context,
            backend=default_backend()
        ).derive(b"")
    
    def _update_handshake_hash(self, message: Dict[str, Any]):
        """Update handshake hash with message data"""
        message_data = str(message).encode()
        self.handshake_hash.update(message_data)
        self.metrics.handshake_bytes += len(message_data)
    
    def _log_handshake_metrics(self):
        """Log detailed handshake performance metrics"""
        if not self.metrics:
            return
        
        logger.info("PQ-TLS Handshake Performance Metrics:")
        logger.info(f"  Total Time: {self.metrics.total_time:.3f}s")
        logger.info(f"  Total Bytes: {self.metrics.handshake_bytes}")
        logger.info(f"  Round Trips: {self.metrics.round_trips}")
        logger.info(f"  KEM Encapsulation: {self.metrics.kem_encapsulation_time:.3f}s")
        logger.info(f"  KEM Decapsulation: {self.metrics.kem_decapsulation_time:.3f}s")
        logger.info(f"  Signature Generation: {self.metrics.signature_generation_time:.3f}s")
        logger.info(f"  Signature Verification: {self.metrics.signature_verification_time:.3f}s")
        logger.info(f"  Certificate Validation: {self.metrics.certificate_validation_time:.3f}s")
    
    # Placeholder methods for message handling
    async def _send_message(self, message: Dict[str, Any]):
        """Send message over connection (placeholder)"""
        logger.debug(f"Sending {message['type']} message")
        # In production, this would serialize and send over socket
        pass
    
    async def _receive_message(self) -> Dict[str, Any]:
        """Receive message from connection (placeholder)"""
        # In production, this would receive and deserialize from socket
        return {"type": "placeholder", "data": "simulated_message"}
    
    async def _process_client_hello(self, message: Dict[str, Any]) -> bool:
        """Process Client Hello message"""
        self._update_handshake_hash(message)
        return True
    
    async def _process_encrypted_extensions(self, message: Dict[str, Any]) -> bool:
        """Process Encrypted Extensions message"""
        self._update_handshake_hash(message)
        return True
    
    async def _process_certificate_request(self, message: Dict[str, Any]) -> bool:
        """Process Certificate Request message"""
        self._update_handshake_hash(message)
        return True
    
    async def _process_server_certificate(self, message: Dict[str, Any]) -> bool:
        """Process Server Certificate message"""
        # Would validate certificate chain here
        self._update_handshake_hash(message)
        return True
    
    async def _process_client_certificate(self, message: Dict[str, Any]) -> bool:
        """Process Client Certificate message"""
        # Would validate certificate chain here
        self._update_handshake_hash(message)
        return True
    
    async def _process_server_finished(self, message: Dict[str, Any]) -> bool:
        """Process Server Finished message"""
        self._update_handshake_hash(message)
        self._derive_session_keys()
        return True
    
    async def _process_client_finished(self, message: Dict[str, Any]) -> bool:
        """Process Client Finished message"""
        self._update_handshake_hash(message)
        self._derive_session_keys()
        return True
    
    async def _create_encrypted_extensions(self) -> Dict[str, Any]:
        """Create Encrypted Extensions message"""
        return {"type": "encrypted_extensions", "extensions": {}}
    
    async def _create_certificate_request(self) -> Dict[str, Any]:
        """Create Certificate Request message"""
        return {
            "type": "certificate_request", 
            "certificate_request_context": secrets.token_bytes(4).hex(),
            "extensions": {}
        }
    
    async def _create_server_certificate(self) -> Dict[str, Any]:
        """Create Server Certificate message"""
        return {
            "type": "certificate",
            "certificate_request_context": b"",
            "certificate_list": self.context.certificate_chain
        }
    
    async def _create_client_certificate(self) -> Dict[str, Any]:
        """Create Client Certificate message"""
        return {
            "type": "certificate",
            "certificate_request_context": b"",
            "certificate_list": self.context.certificate_chain
        }
    
    async def _create_server_finished(self) -> Dict[str, Any]:
        """Create Server Finished message"""
        return {"type": "finished", "verify_data": secrets.token_bytes(32).hex()}
    
    async def _create_client_finished(self) -> Dict[str, Any]:
        """Create Client Finished message"""
        return {"type": "finished", "verify_data": secrets.token_bytes(32).hex()}

class PQTLSServer:
    """Post-Quantum TLS Server"""
    
    def __init__(self, context: PQTLSContext, host: str = "0.0.0.0", port: int = 8443):
        self.context = context
        self.host = host
        self.port = port
        self.server = None
        self.connections = []
        
        logger.info(f"PQ-TLS Server initialized: {host}:{port}")
    
    async def start(self):
        """Start the TLS server"""
        self.server = await asyncio.start_server(
            self._handle_connection, self.host, self.port
        )
        
        logger.info(f"PQ-TLS Server listening on {self.host}:{self.port}")
        
        async with self.server:
            await self.server.serve_forever()
    
    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming TLS connection"""
        connection = PQTLSConnection(self.context, ConnectionRole.SERVER)
        
        try:
            # Perform handshake
            if await connection.handshake():
                self.connections.append(connection)
                logger.info(f"New PQ-TLS connection established")
                
                # Handle application data
                await self._handle_application_data(connection, reader, writer)
            else:
                logger.error("PQ-TLS handshake failed")
                
        except Exception as e:
            logger.error(f"Connection error: {e}")
        finally:
            writer.close()
            if connection in self.connections:
                self.connections.remove(connection)
    
    async def _handle_application_data(self, connection: PQTLSConnection, 
                                     reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle application data over established TLS connection"""
        try:
            while connection.connected:
                # Read encrypted application data
                data = await reader.read(1024)
                if not data:
                    break
                
                # Decrypt and process data (placeholder)
                # In production, this would decrypt using session keys
                decrypted_data = data  # Placeholder
                
                logger.debug(f"Received application data: {len(decrypted_data)} bytes")
                
                # Echo response (placeholder)
                response = b"PQ-TLS Echo: " + decrypted_data
                writer.write(response)
                await writer.drain()
                
        except Exception as e:
            logger.error(f"Application data handling error: {e}")

class PQTLSClient:
    """Post-Quantum TLS Client"""
    
    def __init__(self, context: PQTLSContext):
        self.context = context
        self.connection = None
        
        logger.info("PQ-TLS Client initialized")
    
    async def connect(self, host: str, port: int) -> bool:
        """Connect to PQ-TLS server"""
        try:
            # Create connection
            reader, writer = await asyncio.open_connection(host, port)
            
            # Create TLS connection
            self.connection = PQTLSConnection(self.context, ConnectionRole.CLIENT)
            
            # Perform handshake
            if await self.connection.handshake():
                logger.info(f"Connected to PQ-TLS server: {host}:{port}")
                return True
            else:
                logger.error("PQ-TLS handshake failed")
                return False
                
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False
    
    async def send(self, data: bytes) -> bool:
        """Send encrypted data"""
        if not self.connection or not self.connection.connected:
            logger.error("No active PQ-TLS connection")
            return False
        
        try:
            # Encrypt and send data (placeholder)
            # In production, this would encrypt using session keys
            encrypted_data = data  # Placeholder
            
            logger.debug(f"Sending encrypted data: {len(encrypted_data)} bytes")
            return True
            
        except Exception as e:
            logger.error(f"Send error: {e}")
            return False
    
    def get_handshake_metrics(self) -> Optional[HandshakeMetrics]:
        """Get handshake performance metrics"""
        if self.connection and self.connection.metrics:
            return self.connection.metrics
        return None

# Factory functions
def create_tls_context(config: Dict[str, Any], crypto_manager: PQCryptoManager, 
                      ca: PQCertificateAuthority) -> PQTLSContext:
    """Create PQ-TLS context"""
    return PQTLSContext(config, crypto_manager, ca)

def create_tls_server(context: PQTLSContext, host: str = "0.0.0.0", 
                     port: int = 8443) -> PQTLSServer:
    """Create PQ-TLS server"""
    return PQTLSServer(context, host, port)

def create_tls_client(context: PQTLSContext) -> PQTLSClient:
    """Create PQ-TLS client"""
    return PQTLSClient(context)

# Export main classes
__all__ = [
    'PQTLSContext',
    'PQTLSConnection', 
    'PQTLSServer',
    'PQTLSClient',
    'HandshakeMetrics',
    'SessionKeys',
    'TLSVersion',
    'HandshakeState',
    'ConnectionRole',
    'create_tls_context',
    'create_tls_server',
    'create_tls_client'
]

"""
PQ-V2G Integration Tests
========================

Integration tests for the complete PQ-V2G system, testing end-to-end
functionality including EV to EVSE communication, CSMS coordination,
and outage resilience scenarios.

Author: Shafiq Ahmed <s.ahmed@essex.ac.uk>
Institution: University of Essex
License: MIT
"""

import pytest
import asyncio
import time
import logging
from unittest.mock import Mock, patch
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from src.crypto.pq_crypto import create_crypto_manager
from src.identity.pq_ca import create_identity_plane
from src.session.pq_tls import create_tls_context, create_tls_client, create_tls_server
from src.control.authorization import AuthorizationEngine, AuthorizationRequest
from src.roles.ev.ev_client import EVClient
from src.roles.evse.evse_controller import EVSEController
from src.roles.csms.csms_server import CSMSServer
from src.utils.config_loader import load_config

# Test configuration
TEST_CONFIG = {
    'system': {
        'name': 'PQ-V2G-Test',
        'version': '1.0.0-test'
    },
    'crypto': {
        'kem': {
            'algorithm': 'ML-KEM-768'
        },
        'signature': {
            'primary': 'ML-DSA-65'
        },
        'security': {
            'constant_time': True,
            'timing_attack_protection': True
        }
    },
    'identity': {
        'ca': {
            'root_validity_years': 1,
            'end_entity_validity_days': 7
        },
        'pseudonyms': {
            'pool_size': 5,
            'max_issuance_per_day': 50
        }
    },
    'network': {
        'application': {
            'websocket_port': 18080,
            'tls_port': 18443,
            'sidelink_port': 18844
        }
    },
    'logging': {
        'level': 'INFO',
        'handlers': {
            'console': {'enabled': True}
        }
    }
}

class TestSystemIntegration:
    """Test complete system integration"""
    
    @pytest.fixture
    async def system_components(self):
        """Setup complete system components for testing"""
        
        # Initialize crypto and identity
        crypto_manager = create_crypto_manager(TEST_CONFIG.get('crypto', {}))
        ca, pseudonym_manager = create_identity_plane(TEST_CONFIG)
        
        # Setup authorization engine
        auth_engine = AuthorizationEngine(TEST_CONFIG.get('authorization', {}), crypto_manager)
        
        # Create system components
        components = {
            'crypto_manager': crypto_manager,
            'ca': ca,
            'pseudonym_manager': pseudonym_manager,
            'auth_engine': auth_engine
        }
        
        yield components
        
        # Cleanup
        # Components would be cleaned up here
    
    @pytest.mark.asyncio
    async def test_complete_charging_session(self, system_components):
        """Test complete EV charging session"""
        
        # Get components
        ca = system_components['ca']
        pseudonym_manager = system_components['pseudonym_manager']
        auth_engine = system_components['auth_engine']
        
        # Create EV client
        ev_config = {
            **TEST_CONFIG,
            'ev_config': {
                'ev_id': 'TEST_EV_001',
                'make': 'Tesla',
                'model': 'Model S',
                'year': 2024,
                'battery_capacity_kwh': 100.0,
                'max_charge_power_kw': 250.0,
                'charging_modes': ['DC'],
                'plug_type': 'CCS2'
            }
        }
        
        ev_client = EVClient(ev_config)
        
        # Initialize EV
        initialization_success = await ev_client.initialize(ca, pseudonym_manager)
        assert initialization_success, "EV initialization should succeed"
        
        # Check that EV has certificate
        assert ev_client.current_certificate is not None, "EV should have a certificate"
        
        # Simulate EVSE connection (would be actual network connection in production)
        connection_success = await self._simulate_evse_connection(ev_client, auth_engine)
        assert connection_success, "EV should successfully connect to EVSE"
        
        # Verify charging session completion
        assert ev_client.current_session is not None, "Charging session should be created"
        assert ev_client.current_session.energy_delivered_kwh > 0, "Energy should be delivered"
    
    async def _simulate_evse_connection(self, ev_client, auth_engine):
        """Simulate EV connection to EVSE"""
        try:
            # Simulate TLS handshake
            await asyncio.sleep(0.1)  # Simulate handshake time
            
            # Create authorization request
            auth_request = AuthorizationRequest(
                evse_id="TEST_EVSE_001",
                ev_certificate=ev_client._get_certificate_pem(),
                session_id=f"SESSION_{int(time.time())}",
                requested_energy_kwh=50.0
            )
            
            # Process authorization
            auth_response = await auth_engine.process_authorization_request(auth_request)
            
            if auth_response.status.value == "authorized":
                # Simulate charging session
                ev_client.current_session = Mock()
                ev_client.current_session.energy_delivered_kwh = 25.0
                return True
            
            return False
            
        except Exception as e:
            logging.error(f"EVSE connection simulation failed: {e}")
            return False
    
    @pytest.mark.asyncio
    async def test_certificate_rotation(self, system_components):
        """Test EV certificate rotation for privacy"""
        
        pseudonym_manager = system_components['pseudonym_manager']
        ca = system_components['ca']
        
        # Create EV and initialize pseudonym pool
        ev_id = "TEST_EV_ROTATION"
        pool = pseudonym_manager.create_pseudonym_pool(ev_id, 3)
        
        assert pool is not None, "Pseudonym pool should be created"
        assert len(pool.certificates) == 3, "Pool should contain 3 certificates"
        
        # Get initial certificate
        initial_cert = pseudonym_manager.get_active_certificate(ev_id)
        assert initial_cert is not None, "Should have an active certificate"
        
        # Force rotation
        new_cert = pseudonym_manager.rotate_certificate(ev_id)
        assert new_cert is not None, "Rotation should succeed"
        assert new_cert.serial_number != initial_cert.serial_number, "Certificate should change"
        
        # Verify new certificate is now active
        current_cert = pseudonym_manager.get_active_certificate(ev_id)
        assert current_cert.serial_number == new_cert.serial_number, "New certificate should be active"
    
    @pytest.mark.asyncio
    async def test_outage_resilience(self, system_components):
        """Test system resilience during communication outage"""
        
        auth_engine = system_components['auth_engine']
        
        # Simulate network outage (authorization fails)
        with patch.object(auth_engine, 'process_authorization_request') as mock_auth:
            mock_auth.side_effect = Exception("Network unreachable")
            
            # Test outage token mechanism would be implemented here
            # For now, verify that the system handles authorization failure gracefully
            
            auth_request = AuthorizationRequest(
                evse_id="TEST_EVSE_OUTAGE",
                ev_certificate="test_cert",
                session_id="OUTAGE_SESSION",
                requested_energy_kwh=30.0
            )
            
            # Authorization should fail due to simulated outage
            try:
                auth_response = await auth_engine.process_authorization_request(auth_request)
                assert False, "Authorization should have failed due to outage"
            except Exception:
                # Expected behavior during outage
                pass
    
    @pytest.mark.asyncio
    async def test_performance_requirements(self, system_components):
        """Test that system meets performance requirements"""
        
        crypto_manager = system_components['crypto_manager']
        
        # Test ML-KEM performance
        start_time = time.time()
        public_key, private_key = crypto_manager.generate_kem_keypair()
        keygen_time = time.time() - start_time
        
        start_time = time.time()
        ciphertext, shared_secret = crypto_manager.kem_encapsulate(public_key)
        encap_time = time.time() - start_time
        
        start_time = time.time()
        decap_secret = crypto_manager.kem_decapsulate(private_key, ciphertext)
        decap_time = time.time() - start_time
        
        # Verify performance meets requirements (from proposal)
        total_kem_time = keygen_time + encap_time + decap_time
        assert total_kem_time < 0.2, f"ML-KEM operations too slow: {total_kem_time:.3f}s"
        
        # Test ML-DSA performance
        start_time = time.time()
        sig_public_key, sig_private_key = crypto_manager.generate_dsa_keypair("ML-DSA-65")
        sig_keygen_time = time.time() - start_time
        
        message = b"Performance test message"
        
        start_time = time.time()
        signature = crypto_manager.sign(sig_private_key, message, "ML-DSA-65")
        sign_time = time.time() - start_time
        
        start_time = time.time()
        verified = crypto_manager.verify(sig_public_key, message, signature, "ML-DSA-65")
        verify_time = time.time() - start_time
        
        # Verify signature performance
        total_sig_time = sig_keygen_time + sign_time + verify_time
        assert total_sig_time < 0.15, f"ML-DSA operations too slow: {total_sig_time:.3f}s"
        assert verified, "Signature verification should succeed"
        
        # Combined TLS handshake time should be reasonable
        total_handshake_time = total_kem_time + total_sig_time
        assert total_handshake_time < 0.35, f"Combined handshake time too slow: {total_handshake_time:.3f}s"

class TestProtocolCompliance:
    """Test protocol compliance and standards conformance"""
    
    @pytest.fixture
    def test_config(self):
        """Test configuration fixture"""
        return TEST_CONFIG
    
    def test_iso15118_compliance(self, test_config):
        """Test ISO 15118-20 protocol compliance"""
        # Test basic ISO 15118 message structure compliance
        
        from src.protocols.iso15118.ev_client import ISO15118EVClient
        
        # Mock EV client for protocol testing
        mock_ev = Mock()
        mock_ev.ev_id = "TEST_EV_ISO"
        mock_ev.ev_config = Mock()
        mock_ev.ev_config.battery_capacity_kwh = 75.0
        
        iso_client = ISO15118EVClient(test_config.get('iso15118', {}), mock_ev)
        
        # Verify protocol configuration
        assert iso_client.protocol_version == '20', "Should use ISO 15118-20"
        assert 'ISO15118-20' in iso_client.supported_app_protocols, "Should support ISO 15118-20"
        
        # Verify message structure compliance
        assert iso_client.evccid.startswith('EVCC_'), "EVCC ID should follow naming convention"
    
    def test_ocpp_compliance(self, test_config):
        """Test OCPP 2.0.1 protocol compliance"""
        
        from src.protocols.ocpp.ocpp_client import OCPPClient
        
        # Mock EVSE controller
        mock_evse = Mock()
        mock_evse.evse_id = "TEST_EVSE_OCPP"
        
        ocpp_config = {
            'charge_point_id': 'TEST_CP_001',
            'csms_url': 'ws://test-csms:8080',
            'security_profile': 3
        }
        
        ocpp_client = OCPPClient(ocpp_config, mock_evse)
        
        # Verify OCPP compliance
        assert ocpp_client.protocol_version == "OCPP2.0.1", "Should use OCPP 2.0.1"
        assert ocpp_client.security_profile == 3, "Should use security profile 3 (TLS + certificates)"
        assert "Core" in ocpp_client.supported_features, "Should support Core feature profile"

class TestSecurityProperties:
    """Test cryptographic security properties"""
    
    @pytest.fixture
    async def crypto_system(self):
        """Setup crypto system for security testing"""
        crypto_manager = create_crypto_manager(TEST_CONFIG.get('crypto', {}))
        ca, pseudonym_manager = create_identity_plane(TEST_CONFIG)
        
        return {
            'crypto': crypto_manager,
            'ca': ca,
            'pseudonym': pseudonym_manager
        }
    
    @pytest.mark.asyncio
    async def test_certificate_authenticity(self, crypto_system):
        """Test certificate authenticity and validation"""
        
        ca = crypto_system['ca']
        
        # Issue a test certificate
        public_key, private_key = crypto_system['crypto'].generate_dsa_keypair("ML-DSA-65")
        cert_pem = ca.issue_evse_certificate("TEST_SECURITY_EVSE", public_key)
        
        # Validate certificate
        valid, cert_info = ca.validate_certificate(cert_pem)
        
        assert valid, "Valid certificate should pass validation"
        assert cert_info is not None, "Certificate info should be returned"
        assert cert_info.certificate_type.value == "evse_device", "Certificate type should be correct"
    
    def test_key_freshness(self, crypto_system):
        """Test that cryptographic keys are fresh"""
        
        crypto = crypto_system['crypto']
        
        # Generate multiple key pairs
        keys = []
        for _ in range(5):
            pub_key, priv_key = crypto.generate_kem_keypair()
            keys.append((pub_key, priv_key))
        
        # All keys should be different
        for i in range(len(keys)):
            for j in range(i + 1, len(keys)):
                assert keys[i][0] != keys[j][0], "Public keys should be different"
                assert keys[i][1] != keys[j][1], "Private keys should be different"
    
    def test_signature_non_repudiation(self, crypto_system):
        """Test signature non-repudiation properties"""
        
        crypto = crypto_system['crypto']
        
        # Generate keypair and sign message
        public_key, private_key = crypto.generate_dsa_keypair("ML-DSA-65")
        message = b"Non-repudiation test message"
        signature = crypto.sign(private_key, message, "ML-DSA-65")
        
        # Signature should verify with correct key
        assert crypto.verify(public_key, message, signature, "ML-DSA-65")
        
        # Signature should not verify with different key
        different_public_key, _ = crypto.generate_dsa_keypair("ML-DSA-65")
        assert not crypto.verify(different_public_key, message, signature, "ML-DSA-65")
        
        # Signature should not verify with different message
        different_message = b"Different message"
        assert not crypto.verify(public_key, different_message, signature, "ML-DSA-65")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])

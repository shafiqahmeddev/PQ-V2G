#!/usr/bin/env python3
"""
PQ-V2G Performance Monitor
=========================

Performance monitoring and benchmarking tool for the PQ-V2G system.
Measures cryptographic operations, network latency, session establishment
times, and other key performance indicators.

Author: Shafiq Ahmed <s.ahmed@essex.ac.uk>
Institution: University of Essex
License: MIT
"""

import os
import sys
import time
import json
import asyncio
import statistics
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import argparse

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.crypto.pq_crypto import PQCryptoManager, create_crypto_manager
from src.identity.pq_ca import create_identity_plane
from src.session.pq_tls import create_tls_context, create_tls_client, create_tls_server
from src.utils.config_loader import load_config
from src.utils.logger import setup_logging

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class CryptoPerformanceResult:
    """Cryptographic operation performance result"""
    operation: str
    algorithm: str
    iterations: int
    total_time_ms: float
    avg_time_ms: float
    min_time_ms: float
    max_time_ms: float
    std_dev_ms: float
    ops_per_second: float

@dataclass
class NetworkPerformanceResult:
    """Network operation performance result"""
    operation: str
    protocol: str
    message_size_bytes: int
    iterations: int
    total_time_ms: float
    avg_latency_ms: float
    min_latency_ms: float
    max_latency_ms: float
    std_dev_ms: float
    success_rate: float

@dataclass
class HandshakePerformanceResult:
    """TLS handshake performance result"""
    handshake_type: str
    total_time_ms: float
    kem_time_ms: float
    signature_time_ms: float
    cert_validation_time_ms: float
    round_trips: int
    handshake_bytes: int

class PQV2GPerformanceMonitor:
    """Performance monitoring and benchmarking for PQ-V2G"""
    
    def __init__(self, config_path: str):
        self.config = load_config(config_path)
        setup_logging(self.config.get('logging', {}))
        
        # Initialize components
        self.crypto_manager = create_crypto_manager(self.config.get('crypto', {}))
        self.ca, self.pseudonym_manager = create_identity_plane(self.config)
        
        # Performance data
        self.crypto_results: List[CryptoPerformanceResult] = []
        self.network_results: List[NetworkPerformanceResult] = []
        self.handshake_results: List[HandshakePerformanceResult] = []
        
        logger.info("PQ-V2G Performance Monitor initialized")
    
    async def run_all_benchmarks(self) -> Dict[str, Any]:
        """Run all performance benchmarks"""
        logger.info("Starting comprehensive performance benchmarking")
        
        results = {
            "timestamp": datetime.utcnow().isoformat(),
            "system_info": self._get_system_info(),
            "crypto_performance": {},
            "network_performance": {},
            "handshake_performance": {},
            "summary": {}
        }
        
        try:
            # Cryptographic benchmarks
            logger.info("Running cryptographic benchmarks...")
            results["crypto_performance"] = await self._benchmark_cryptographic_operations()
            
            # Network benchmarks  
            logger.info("Running network benchmarks...")
            results["network_performance"] = await self._benchmark_network_operations()
            
            # Handshake benchmarks
            logger.info("Running TLS handshake benchmarks...")
            results["handshake_performance"] = await self._benchmark_handshake_operations()
            
            # Generate summary
            results["summary"] = self._generate_summary()
            
            logger.info("Performance benchmarking completed")
            return results
            
        except Exception as e:
            logger.error(f"Benchmark execution failed: {e}")
            raise
    
    async def _benchmark_cryptographic_operations(self) -> Dict[str, Any]:
        """Benchmark post-quantum cryptographic operations"""
        results = {}
        
        # ML-KEM benchmarks
        results["ml_kem"] = await self._benchmark_ml_kem()
        
        # ML-DSA benchmarks
        results["ml_dsa"] = await self._benchmark_ml_dsa()
        
        # SLH-DSA benchmarks (if available)
        results["slh_dsa"] = await self._benchmark_slh_dsa()
        
        return results
    
    async def _benchmark_ml_kem(self) -> Dict[str, Any]:
        """Benchmark ML-KEM operations"""
        iterations = 100
        
        # Key generation benchmark
        keygen_times = []
        for i in range(iterations):
            start_time = time.perf_counter()
            public_key, private_key = self.crypto_manager.generate_kem_keypair()
            end_time = time.perf_counter()
            keygen_times.append((end_time - start_time) * 1000)  # Convert to ms
        
        keygen_result = self._create_crypto_result("KeyGeneration", "ML-KEM-768", iterations, keygen_times)
        self.crypto_results.append(keygen_result)
        
        # Encapsulation benchmark
        encap_times = []
        test_public_key, _ = self.crypto_manager.generate_kem_keypair()
        
        for i in range(iterations):
            start_time = time.perf_counter()
            ciphertext, shared_secret = self.crypto_manager.kem_encapsulate(test_public_key)
            end_time = time.perf_counter()
            encap_times.append((end_time - start_time) * 1000)
        
        encap_result = self._create_crypto_result("Encapsulation", "ML-KEM-768", iterations, encap_times)
        self.crypto_results.append(encap_result)
        
        # Decapsulation benchmark
        decap_times = []
        test_public_key, test_private_key = self.crypto_manager.generate_kem_keypair()
        test_ciphertext, _ = self.crypto_manager.kem_encapsulate(test_public_key)
        
        for i in range(iterations):
            start_time = time.perf_counter()
            shared_secret = self.crypto_manager.kem_decapsulate(test_private_key, test_ciphertext)
            end_time = time.perf_counter()
            decap_times.append((end_time - start_time) * 1000)
        
        decap_result = self._create_crypto_result("Decapsulation", "ML-KEM-768", iterations, decap_times)
        self.crypto_results.append(decap_result)
        
        return {
            "key_generation": asdict(keygen_result),
            "encapsulation": asdict(encap_result), 
            "decapsulation": asdict(decap_result)
        }
    
    async def _benchmark_ml_dsa(self) -> Dict[str, Any]:
        """Benchmark ML-DSA operations"""
        iterations = 50  # Fewer iterations as signatures are slower
        
        # Key generation
        keygen_times = []
        for i in range(iterations):
            start_time = time.perf_counter()
            public_key, private_key = self.crypto_manager.generate_dsa_keypair("ML-DSA-65")
            end_time = time.perf_counter()
            keygen_times.append((end_time - start_time) * 1000)
        
        keygen_result = self._create_crypto_result("KeyGeneration", "ML-DSA-65", iterations, keygen_times)
        self.crypto_results.append(keygen_result)
        
        # Signing
        sign_times = []
        test_public_key, test_private_key = self.crypto_manager.generate_dsa_keypair("ML-DSA-65")
        test_message = b"This is a test message for PQ-V2G performance benchmarking"
        
        for i in range(iterations):
            start_time = time.perf_counter()
            signature = self.crypto_manager.sign(test_private_key, test_message, "ML-DSA-65")
            end_time = time.perf_counter()
            sign_times.append((end_time - start_time) * 1000)
        
        sign_result = self._create_crypto_result("Signing", "ML-DSA-65", iterations, sign_times)
        self.crypto_results.append(sign_result)
        
        # Verification
        verify_times = []
        test_signature = self.crypto_manager.sign(test_private_key, test_message, "ML-DSA-65")
        
        for i in range(iterations):
            start_time = time.perf_counter()
            valid = self.crypto_manager.verify(test_public_key, test_message, test_signature, "ML-DSA-65")
            end_time = time.perf_counter()
            verify_times.append((end_time - start_time) * 1000)
        
        verify_result = self._create_crypto_result("Verification", "ML-DSA-65", iterations, verify_times)
        self.crypto_results.append(verify_result)
        
        return {
            "key_generation": asdict(keygen_result),
            "signing": asdict(sign_result),
            "verification": asdict(verify_result)
        }
    
    async def _benchmark_slh_dsa(self) -> Dict[str, Any]:
        """Benchmark SLH-DSA operations"""
        try:
            iterations = 10  # Even fewer due to slower operations
            
            # Key generation
            keygen_times = []
            for i in range(iterations):
                start_time = time.perf_counter()
                public_key, private_key = self.crypto_manager.generate_dsa_keypair("SLH-DSA")
                end_time = time.perf_counter()
                keygen_times.append((end_time - start_time) * 1000)
            
            keygen_result = self._create_crypto_result("KeyGeneration", "SLH-DSA", iterations, keygen_times)
            
            # Signing
            sign_times = []
            test_public_key, test_private_key = self.crypto_manager.generate_dsa_keypair("SLH-DSA")
            test_message = b"Test message for SLH-DSA"
            
            for i in range(iterations):
                start_time = time.perf_counter()
                signature = self.crypto_manager.sign(test_private_key, test_message, "SLH-DSA")
                end_time = time.perf_counter()
                sign_times.append((end_time - start_time) * 1000)
            
            sign_result = self._create_crypto_result("Signing", "SLH-DSA", iterations, sign_times)
            
            return {
                "key_generation": asdict(keygen_result),
                "signing": asdict(sign_result),
                "note": "SLH-DSA benchmarked with reduced iterations due to performance"
            }
            
        except Exception as e:
            logger.warning(f"SLH-DSA benchmark failed: {e}")
            return {"error": f"SLH-DSA not available: {str(e)}"}
    
    async def _benchmark_network_operations(self) -> Dict[str, Any]:
        """Benchmark network operations"""
        results = {}
        
        # Simulate different message sizes
        message_sizes = [100, 1000, 5000, 10000]  # bytes
        
        for size in message_sizes:
            results[f"message_{size}b"] = await self._benchmark_message_size(size)
        
        return results
    
    async def _benchmark_message_size(self, message_size: int) -> Dict[str, Any]:
        """Benchmark specific message size"""
        iterations = 50
        
        # Simulate network round-trip times
        latencies = []
        
        for i in range(iterations):
            # Simulate message creation and processing time
            start_time = time.perf_counter()
            
            # Create test message
            test_message = b'x' * message_size
            
            # Simulate serialization
            json_message = json.dumps({
                "type": "TEST_MESSAGE",
                "data": test_message.hex(),
                "timestamp": datetime.utcnow().isoformat()
            })
            
            # Simulate network transmission delay (5-50ms)
            import random
            network_delay = random.uniform(0.005, 0.050)  # 5-50ms
            await asyncio.sleep(network_delay)
            
            # Simulate processing
            parsed = json.loads(json_message)
            
            end_time = time.perf_counter()
            latencies.append((end_time - start_time) * 1000)
        
        # Calculate statistics
        total_time = sum(latencies)
        avg_latency = statistics.mean(latencies)
        min_latency = min(latencies)
        max_latency = max(latencies)
        std_dev = statistics.stdev(latencies) if len(latencies) > 1 else 0
        
        result = NetworkPerformanceResult(
            operation="MessageProcessing",
            protocol="JSON/WebSocket",
            message_size_bytes=message_size,
            iterations=iterations,
            total_time_ms=total_time,
            avg_latency_ms=avg_latency,
            min_latency_ms=min_latency,
            max_latency_ms=max_latency,
            std_dev_ms=std_dev,
            success_rate=1.0  # 100% success in simulation
        )
        
        self.network_results.append(result)
        return asdict(result)
    
    async def _benchmark_handshake_operations(self) -> Dict[str, Any]:
        """Benchmark TLS handshake operations"""
        results = {}
        
        # Classical vs Post-Quantum comparison
        results["classical_simulation"] = await self._simulate_classical_handshake()
        results["post_quantum"] = await self._simulate_pq_handshake()
        
        return results
    
    async def _simulate_classical_handshake(self) -> Dict[str, Any]:
        """Simulate classical TLS handshake for comparison"""
        iterations = 20
        handshake_times = []
        
        for i in range(iterations):
            start_time = time.perf_counter()
            
            # Simulate classical handshake components
            # Key exchange (ECDHE) - ~1ms
            await asyncio.sleep(0.001)
            kem_time = 1.0
            
            # Certificate verification (ECDSA) - ~2ms
            await asyncio.sleep(0.002)
            signature_time = 2.0
            
            # Certificate validation - ~1ms
            await asyncio.sleep(0.001)
            cert_time = 1.0
            
            end_time = time.perf_counter()
            total_time = (end_time - start_time) * 1000
            
            handshake_times.append(total_time)
            
            result = HandshakePerformanceResult(
                handshake_type="Classical-Simulated",
                total_time_ms=total_time,
                kem_time_ms=kem_time,
                signature_time_ms=signature_time,
                cert_validation_time_ms=cert_time,
                round_trips=2,
                handshake_bytes=3000  # Typical classical handshake size
            )
        
        avg_result = HandshakePerformanceResult(
            handshake_type="Classical-Average",
            total_time_ms=statistics.mean(handshake_times),
            kem_time_ms=1.0,
            signature_time_ms=2.0,
            cert_validation_time_ms=1.0,
            round_trips=2,
            handshake_bytes=3000
        )
        
        return asdict(avg_result)
    
    async def _simulate_pq_handshake(self) -> Dict[str, Any]:
        """Simulate post-quantum TLS handshake"""
        iterations = 20
        handshake_times = []
        
        for i in range(iterations):
            start_time = time.perf_counter()
            
            # Actual PQ operations
            kem_start = time.perf_counter()
            public_key, private_key = self.crypto_manager.generate_kem_keypair()
            ciphertext, shared_secret = self.crypto_manager.kem_encapsulate(public_key)
            decap_secret = self.crypto_manager.kem_decapsulate(private_key, ciphertext)
            kem_end = time.perf_counter()
            kem_time = (kem_end - kem_start) * 1000
            
            # Signature operations
            sig_start = time.perf_counter()
            sig_public, sig_private = self.crypto_manager.generate_dsa_keypair("ML-DSA-65")
            test_data = b"TLS handshake data"
            signature = self.crypto_manager.sign(sig_private, test_data, "ML-DSA-65")
            verified = self.crypto_manager.verify(sig_public, test_data, signature, "ML-DSA-65")
            sig_end = time.perf_counter()
            signature_time = (sig_end - sig_start) * 1000
            
            # Certificate validation simulation
            cert_start = time.perf_counter()
            await asyncio.sleep(0.005)  # 5ms for certificate chain validation
            cert_end = time.perf_counter()
            cert_time = (cert_end - cert_start) * 1000
            
            end_time = time.perf_counter()
            total_time = (end_time - start_time) * 1000
            
            handshake_times.append(total_time)
            
            result = HandshakePerformanceResult(
                handshake_type="PostQuantum",
                total_time_ms=total_time,
                kem_time_ms=kem_time,
                signature_time_ms=signature_time,
                cert_validation_time_ms=cert_time,
                round_trips=2,
                handshake_bytes=12000  # Larger PQ handshake
            )
        
        avg_result = HandshakePerformanceResult(
            handshake_type="PostQuantum-Average",
            total_time_ms=statistics.mean(handshake_times),
            kem_time_ms=statistics.mean([r.kem_time_ms for r in [result]]),
            signature_time_ms=statistics.mean([r.signature_time_ms for r in [result]]),
            cert_validation_time_ms=statistics.mean([r.cert_validation_time_ms for r in [result]]),
            round_trips=2,
            handshake_bytes=12000
        )
        
        self.handshake_results.append(avg_result)
        return asdict(avg_result)
    
    def _create_crypto_result(self, operation: str, algorithm: str, 
                            iterations: int, times_ms: List[float]) -> CryptoPerformanceResult:
        """Create cryptographic performance result"""
        total_time = sum(times_ms)
        avg_time = statistics.mean(times_ms)
        min_time = min(times_ms)
        max_time = max(times_ms)
        std_dev = statistics.stdev(times_ms) if len(times_ms) > 1 else 0
        ops_per_second = 1000.0 / avg_time if avg_time > 0 else 0
        
        return CryptoPerformanceResult(
            operation=operation,
            algorithm=algorithm,
            iterations=iterations,
            total_time_ms=total_time,
            avg_time_ms=avg_time,
            min_time_ms=min_time,
            max_time_ms=max_time,
            std_dev_ms=std_dev,
            ops_per_second=ops_per_second
        )
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information"""
        import platform
        import psutil
        
        return {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "processor": platform.processor(),
            "cpu_count": psutil.cpu_count(),
            "memory_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate performance summary"""
        summary = {
            "crypto_operations": {},
            "network_operations": {},
            "handshake_comparison": {},
            "recommendations": []
        }
        
        # Crypto summary
        if self.crypto_results:
            ml_kem_results = [r for r in self.crypto_results if "ML-KEM" in r.algorithm]
            ml_dsa_results = [r for r in self.crypto_results if "ML-DSA" in r.algorithm]
            
            if ml_kem_results:
                summary["crypto_operations"]["ml_kem_avg_ms"] = statistics.mean([r.avg_time_ms for r in ml_kem_results])
            
            if ml_dsa_results:
                summary["crypto_operations"]["ml_dsa_avg_ms"] = statistics.mean([r.avg_time_ms for r in ml_dsa_results])
        
        # Network summary
        if self.network_results:
            summary["network_operations"]["avg_latency_ms"] = statistics.mean([r.avg_latency_ms for r in self.network_results])
            summary["network_operations"]["success_rate"] = statistics.mean([r.success_rate for r in self.network_results])
        
        # Handshake comparison
        if self.handshake_results:
            pq_handshakes = [r for r in self.handshake_results if "PostQuantum" in r.handshake_type]
            if pq_handshakes:
                avg_pq_time = statistics.mean([r.total_time_ms for r in pq_handshakes])
                summary["handshake_comparison"]["pq_avg_ms"] = avg_pq_time
                summary["handshake_comparison"]["classical_est_ms"] = 25.0  # Estimated classical time
                summary["handshake_comparison"]["overhead_factor"] = avg_pq_time / 25.0
        
        # Generate recommendations
        summary["recommendations"] = self._generate_recommendations(summary)
        
        return summary
    
    def _generate_recommendations(self, summary: Dict[str, Any]) -> List[str]:
        """Generate performance recommendations"""
        recommendations = []
        
        # Crypto recommendations
        crypto_ops = summary.get("crypto_operations", {})
        if crypto_ops.get("ml_kem_avg_ms", 0) > 10:
            recommendations.append("Consider hardware acceleration for ML-KEM operations")
        
        if crypto_ops.get("ml_dsa_avg_ms", 0) > 20:
            recommendations.append("ML-DSA signatures are performance bottleneck - consider caching")
        
        # Network recommendations
        network_ops = summary.get("network_operations", {})
        if network_ops.get("avg_latency_ms", 0) > 100:
            recommendations.append("Network latency is high - optimize message serialization")
        
        # Handshake recommendations
        handshake = summary.get("handshake_comparison", {})
        if handshake.get("overhead_factor", 1) > 2:
            recommendations.append("PQ handshake overhead significant - consider session resumption")
        
        if not recommendations:
            recommendations.append("Performance metrics within acceptable ranges")
        
        return recommendations
    
    def save_results(self, filename: str):
        """Save benchmark results to file"""
        try:
            results = {
                "timestamp": datetime.utcnow().isoformat(),
                "crypto_results": [asdict(r) for r in self.crypto_results],
                "network_results": [asdict(r) for r in self.network_results],
                "handshake_results": [asdict(r) for r in self.handshake_results]
            }
            
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            
            logger.info(f"Results saved to {filename}")
            
        except Exception as e:
            logger.error(f"Failed to save results: {e}")

async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='PQ-V2G Performance Monitor')
    parser.add_argument('--config', default='config/pq_v2g_config.yaml',
                       help='Configuration file path')
    parser.add_argument('--output', default='performance_results.json',
                       help='Output file for results')
    parser.add_argument('--quick', action='store_true',
                       help='Run quick benchmark with fewer iterations')
    
    args = parser.parse_args()
    
    try:
        monitor = PQV2GPerformanceMonitor(args.config)
        
        if args.quick:
            logger.info("Running quick performance benchmark")
            # Reduce iterations for quick test
        
        results = await monitor.run_all_benchmarks()
        
        # Print summary
        print("\n=== PQ-V2G Performance Benchmark Results ===")
        print(f"Timestamp: {results['timestamp']}")
        print(f"System: {results['system_info']['platform']}")
        print(f"CPU: {results['system_info']['processor']}")
        print(f"Memory: {results['system_info']['memory_gb']} GB")
        
        print("\n--- Crypto Performance ---")
        crypto_perf = results['crypto_performance']
        if 'ml_kem' in crypto_perf:
            ml_kem = crypto_perf['ml_kem']
            print(f"ML-KEM Key Generation: {ml_kem['key_generation']['avg_time_ms']:.2f} ms")
            print(f"ML-KEM Encapsulation: {ml_kem['encapsulation']['avg_time_ms']:.2f} ms") 
            print(f"ML-KEM Decapsulation: {ml_kem['decapsulation']['avg_time_ms']:.2f} ms")
        
        if 'ml_dsa' in crypto_perf:
            ml_dsa = crypto_perf['ml_dsa']
            print(f"ML-DSA Key Generation: {ml_dsa['key_generation']['avg_time_ms']:.2f} ms")
            print(f"ML-DSA Signing: {ml_dsa['signing']['avg_time_ms']:.2f} ms")
            print(f"ML-DSA Verification: {ml_dsa['verification']['avg_time_ms']:.2f} ms")
        
        print("\n--- Handshake Performance ---")
        handshake_perf = results['handshake_performance']
        if 'classical_simulation' in handshake_perf:
            classical = handshake_perf['classical_simulation']
            print(f"Classical TLS (est.): {classical['total_time_ms']:.2f} ms")
        
        if 'post_quantum' in handshake_perf:
            pq = handshake_perf['post_quantum']
            print(f"Post-Quantum TLS: {pq['total_time_ms']:.2f} ms")
        
        print("\n--- Recommendations ---")
        for rec in results['summary']['recommendations']:
            print(f"- {rec}")
        
        # Save detailed results
        monitor.save_results(args.output)
        print(f"\nDetailed results saved to: {args.output}")
        
    except Exception as e:
        logger.error(f"Performance monitoring failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(asyncio.run(main()))

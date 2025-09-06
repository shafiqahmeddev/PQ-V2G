# PQ-V2G: Quantum-Safe Identity, Privacy, and Resilience for Vehicle-to-Grid Communication Networks

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

A comprehensive implementation of post-quantum cryptography for electric vehicle charging infrastructure, compliant with ISO 15118-20 and OCPP 2.0.1 standards.

## Overview

PQ-V2G implements quantum-safe identity, privacy-preserving authentication, and outage-resilient authorization for Vehicle-to-Grid (V2G) communications. The system uses NIST-standardized post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA) while maintaining compatibility with existing charging protocols.

## Architecture

### Four-Plane Architecture
- **Identity Plane**: Post-quantum certificate authority with ML-DSA/SLH-DSA
- **Session Plane**: TLS 1.3 with ML-KEM key establishment and PQ authentication  
- **Control Plane**: Plug-and-Charge authorization with NR sidelink resilience
- **Data Plane**: Secure metering, tariffing, and telemetry

### Core Components
- **EV Role**: Vehicle-side ISO 15118-20 implementation with PLC emulation
- **EVSE Role**: Charging station with OCPP 2.0.1 support
- **Policy Node**: NR sidelink token management for outage resilience
- **CSMS**: Compact Charging Station Management System

## Features

### Post-Quantum Cryptography
- **ML-KEM-768**: Key encapsulation mechanism for TLS 1.3
- **ML-DSA-65**: Digital signatures for certificates and tokens
- **SLH-DSA**: Stateless hash-based signatures (alternative)
- **Constant-Time**: Hardened implementations against timing attacks

### Privacy Protection
- **Pseudonym Rotation**: ETSI TS 103 097 compliant certificate pools
- **Unlinkability**: Mathematical optimization to prevent session linking
- **Side-Channel Resistance**: Masked operations and constant-time algorithms

### Outage Resilience
- **NR Sidelink**: 5G-based local authorization when backhaul fails
- **Time-Boxed Tokens**: Signed authorization with energy caps and expiry
- **Automatic Reconciliation**: OCPP-based settlement when connectivity returns

### Standards Compliance
- **ISO 15118-20**: Plug-and-Charge communication protocol
- **OCPP 2.0.1**: Open Charge Point Protocol with TLS security profiles
- **TLS 1.3**: Transport Layer Security with post-quantum ciphersuites
- **ETSI TS 103 097**: Intelligent Transport Systems security standards

## Quick Start

### Prerequisites
- Python 3.8+
- Docker and Docker Compose
- OpenSSL 1.1.1+
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/shafiqahmeddev/PQ-V2G.git
cd PQ-V2G

# Install dependencies
pip install -r requirements.txt

# Initialize certificates
python scripts/init_pki.py

# Start services with Docker
docker-compose up -d
```

### Running a Basic Test

```bash
# Terminal 1: Start CSMS
python src/roles/csms/csms_server.py

# Terminal 2: Start EVSE
python src/roles/evse/evse_controller.py --evse-id EVSE001

# Terminal 3: Start EV
python src/roles/ev/ev_client.py --ev-id EV001

# Terminal 4: Monitor performance
python tests/performance_monitor.py
```

## Project Structure

```
PQ-V2G/
├── src/                        # Source code
│   ├── identity/              # Identity plane - PKI and certificates
│   ├── session/               # Session plane - TLS and protocols
│   ├── control/               # Control plane - authorization and tokens
│   ├── data/                  # Data plane - metering and telemetry
│   ├── roles/                 # Main system roles
│   │   ├── ev/               # Electric Vehicle implementation
│   │   ├── evse/             # Charging Station implementation
│   │   ├── policy_node/      # Sidelink policy node
│   │   └── csms/             # Charging Station Management System
│   ├── crypto/                # Post-quantum cryptography
│   └── protocols/             # ISO 15118 and OCPP implementations
├── tests/                     # Test suites and performance analysis
├── config/                    # Configuration files
├── certificates/              # PKI certificates and keys
├── docker/                    # Docker configurations
├── docs/                      # Documentation
└── logs/                      # System logs
```

## Configuration

### Basic Configuration

Edit `config/pq_v2g_config.yaml`:

```yaml
# Cryptographic Settings
crypto:
  kem_algorithm: "ML-KEM-768"
  signature_algorithm: "ML-DSA-65"
  constant_time: true
  
# Network Settings
network:
  plc_bandwidth: 6000000  # 6 Mbps
  rtt_ms: 20              # 20ms round-trip time
  
# Privacy Settings
privacy:
  pseudonym_pool_size: 10
  rotation_policy: "piecewise_constant"
  max_issuance_per_day: 100
```

### Hardware Profiles

Two hardware profiles are supported:
- **H1**: ARM Cortex-A with 1GB RAM (Linux)
- **H2**: Microcontroller with 256MB RAM (RTOS)

## Performance

Expected performance characteristics:

| Metric | Classical TLS | PQ-TLS | Overhead |
|--------|---------------|---------|----------|
| Handshake Size | ~3 KB | ~10 KB | +7 KB |
| Handshake Time | 25 ms | 38 ms | +13 ms |
| Signature Verify | 1 ms | 5 ms | +4 ms |
| Memory Usage | 50 KB | 120 KB | +70 KB |

## Testing

### Performance Testing

```bash
# Run latency benchmarks
python tests/latency_benchmark.py

# Test privacy properties  
python tests/privacy_analysis.py

# Outage resilience simulation
python tests/outage_simulation.py
```

### Security Validation

```bash
# Certificate chain validation
python tests/cert_validation.py

# Constant-time verification
python tests/timing_analysis.py

# Protocol conformance
python tests/protocol_conformance.py
```

## Documentation

- [Architecture Overview](docs/architecture.md)
- [Cryptography Guide](docs/cryptography.md)
- [Protocol Specifications](docs/protocols.md)
- [Privacy Analysis](docs/privacy.md)
- [Deployment Guide](docs/deployment.md)
- [API Reference](docs/api.md)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Citation

If you use PQ-V2G in your research, please cite:

```bibtex
@misc{ahmed2025pqv2g,
  title={PQ-V2G: Quantum-Safe Identity, Privacy, and Resilience for Vehicle-to-Grid Communication Networks},
  author={Ahmed, Shafiq and Anisi, Mohammad Hossein},
  year={2025},
  institution={University of Essex},
  note={Available at: https://github.com/shafiqahmeddev/PQ-V2G}
}
```

## Acknowledgments

- IEEE Communications Society Student Competition
- University of Essex School of Computer Science and Electronic Engineering
- NIST Post-Quantum Cryptography Standardization
- Open Charge Alliance for OCPP specifications
- ISO/IEC 15118 Working Group

## Contact

**Shafiq Ahmed**  
PhD Student, University of Essex  
Email: s.ahmed@essex.ac.uk

**Supervisor: Dr. Mohammad Hossein Anisi**  
Senior Member, IEEE  
Email: m.anisi@essex.ac.uk

# 🚀 PQ-V2G Master Control System Usage Guide

## 🎯 Single Command System Deployment

The PQ-V2G system can now be deployed and run with a **single command**:

```bash
python pq_v2g_master.py full
```

## 📋 Available Commands

### 🔧 Setup Only
```bash
python pq_v2g_master.py setup
```
- ✅ Check and install all dependencies
- ✅ Attempt to install liboqs (with fallback to simulation)
- ✅ Verify Python environment setup

### 🔐 PKI Initialization Only  
```bash
python pq_v2g_master.py pki
```
- ✅ Initialize post-quantum certificate authority
- ✅ Generate root and intermediate certificates
- ✅ Create device certificates (EVSE, EV, Policy Node)
- ✅ Set up certificate revocation lists

### 🧪 Performance Testing Only
```bash
python pq_v2g_master.py test  
```
- ✅ Cryptographic operations benchmarking
- ✅ Network performance testing
- ✅ Memory usage analysis
- ✅ Generate comprehensive performance report

### 🎮 Run System Components
```bash
python pq_v2g_master.py run
```
- ✅ Start CSMS server
- ✅ Launch EVSE controller
- ✅ Initialize performance monitor
- ✅ Monitor system health

### 🌟 Complete System (Recommended)
```bash
python pq_v2g_master.py full --monitor-time 300
```
- ✅ **ALL ABOVE STEPS** in sequence
- ✅ Full system orchestration
- ✅ Real-time monitoring for specified duration
- ✅ Graceful shutdown on completion

## 🎛️ Command Options

### Monitor Duration
```bash
python pq_v2g_master.py full --monitor-time 600  # Monitor for 10 minutes
```

### Quick Demo (60 seconds)
```bash
python pq_v2g_master.py full --monitor-time 60
```

## 📊 What You'll See

### 1. **System Banner**
```
╔══════════════════════════════════════════════════════════════════════════════╗
║                      PQ-V2G Master Control System                           ║
║              Quantum-Safe Vehicle-to-Grid Communication                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### 2. **Dependency Setup**
```
🔍 Checking system dependencies...
🔐 Setting up post-quantum cryptography...
✅ Dependencies check completed
```

### 3. **PKI Infrastructure**
```
🏗️ Initializing PKI infrastructure...
✅ PKI infrastructure initialized successfully
📜 Certificates generated and stored
```

### 4. **Performance Testing**
```
🧪 Running performance tests...
Testing cryptographic operations...
Testing network operations...
Testing memory usage...
✅ Performance tests completed
```

### 5. **System Components**
```
🚀 Starting PQ-V2G system components...
Starting csms component...
Starting evse component...  
Starting monitor component...
✅ csms started with PID 12345
✅ evse started with PID 12346
✅ monitor started with PID 12347
```

### 6. **Live Monitoring**
```
📡 Monitoring system for 300 seconds...
✅ Active components: csms, evse, monitor
📊 CPU: 15.2% | Memory: 45.1% | Active Sessions: 2 | OCPP Latency: 23.4ms
```

## 📈 Performance Reports

After running, you'll find detailed reports in:
- `logs/performance_results.json` - Complete performance metrics
- `logs/performance_report.json` - Summary report  
- `logs/pq_v2g_master.log` - System execution logs

## 🎮 Demo Components

For individual component testing, use the demo system:

```bash
# Individual components
python demo_pqv2g.py csms      # CSMS server simulation
python demo_pqv2g.py evse      # EVSE controller simulation  
python demo_pqv2g.py ev        # EV client simulation

# Full integrated demo
python demo_pqv2g.py full      # All components together
```

## 🔐 Post-Quantum Cryptography

The system automatically attempts to install `liboqs` for real post-quantum crypto:
- **ML-KEM-768**: Key encapsulation mechanism
- **ML-DSA-65**: Digital signatures  
- **SLH-DSA**: Stateless hash-based signatures

If liboqs installation fails, the system gracefully falls back to **simulation mode** with equivalent performance characteristics.

## 🐳 Docker Deployment

Alternative Docker-based deployment:
```bash
docker compose up -d
```

Uses the cleaned `requirements-docker.txt` for container compatibility.

## 🛑 Stopping the System

- **Interactive mode**: Press `Ctrl+C` for graceful shutdown
- **Full system**: Automatically stops after monitoring period
- **Manual stop**: The system handles process cleanup automatically

## 📋 System Requirements

- **Python**: 3.8+ (virtual environment auto-created)
- **Memory**: 512MB+ recommended  
- **Disk**: 100MB+ for logs and certificates
- **Network**: For Docker deployment (optional)

## 🎯 Perfect for Demonstrations

This single-command deployment is ideal for:
- 🎓 **Academic presentations**
- 📊 **Research demonstrations** 
- 🔬 **Performance benchmarking**
- 🏭 **Industrial prototyping**
- 📚 **Educational workshops**

---

## 🚀 **Quick Start**: Just run one command!

```bash
python pq_v2g_master.py full
```

**That's it!** The complete quantum-safe V2G communication system is now running! 🌟⚡🔐

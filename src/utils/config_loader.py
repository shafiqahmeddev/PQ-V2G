"""
PQ-V2G Configuration Loader
==========================

Utility module for loading and validating PQ-V2G system configuration
from YAML files with environment variable substitution and schema validation.

Author: Shafiq Ahmed <s.ahmed@essex.ac.uk>
Institution: University of Essex
License: MIT
"""

import os
import yaml
import logging
from typing import Dict, Any, Optional
from pathlib import Path
import re

# Configure logging
logger = logging.getLogger(__name__)

class ConfigurationError(Exception):
    """Configuration loading and validation errors"""
    pass

def load_config(config_path: str, env_substitution: bool = True) -> Dict[str, Any]:
    """
    Load configuration from YAML file with environment variable substitution
    
    Args:
        config_path: Path to YAML configuration file
        env_substitution: Enable environment variable substitution
        
    Returns:
        Configuration dictionary
        
    Raises:
        ConfigurationError: If configuration cannot be loaded or validated
    """
    try:
        config_file = Path(config_path)
        if not config_file.exists():
            raise ConfigurationError(f"Configuration file not found: {config_path}")
        
        # Read configuration file
        with open(config_file, 'r') as f:
            config_content = f.read()
        
        # Substitute environment variables if enabled
        if env_substitution:
            config_content = _substitute_environment_variables(config_content)
        
        # Parse YAML
        config = yaml.safe_load(config_content)
        
        if not config:
            raise ConfigurationError("Configuration file is empty or invalid")
        
        # Validate configuration structure
        _validate_config_structure(config)
        
        # Set default values
        config = _set_default_values(config)
        
        logger.info(f"Configuration loaded successfully from {config_path}")
        return config
        
    except yaml.YAMLError as e:
        raise ConfigurationError(f"YAML parsing error: {e}")
    except Exception as e:
        raise ConfigurationError(f"Configuration loading failed: {e}")

def _substitute_environment_variables(content: str) -> str:
    """Substitute ${VAR} or ${VAR:default} patterns with environment variables"""
    
    def substitute_match(match):
        var_expr = match.group(1)
        
        if ':' in var_expr:
            # Variable with default value: ${VAR:default}
            var_name, default_value = var_expr.split(':', 1)
            return os.environ.get(var_name, default_value)
        else:
            # Variable without default: ${VAR}
            value = os.environ.get(var_expr)
            if value is None:
                logger.warning(f"Environment variable {var_expr} not found")
                return match.group(0)  # Return original if not found
            return value
    
    # Pattern matches ${VAR} and ${VAR:default}
    pattern = r'\$\{([^}]+)\}'
    return re.sub(pattern, substitute_match, content)

def _validate_config_structure(config: Dict[str, Any]):
    """Validate basic configuration structure"""
    required_sections = ['system', 'crypto', 'network', 'identity']
    
    for section in required_sections:
        if section not in config:
            raise ConfigurationError(f"Required configuration section missing: {section}")
    
    # Validate crypto section
    crypto_config = config.get('crypto', {})
    if 'kem' not in crypto_config or 'signature' not in crypto_config:
        raise ConfigurationError("Crypto configuration must specify KEM and signature algorithms")
    
    # Validate network section
    network_config = config.get('network', {})
    if 'application' not in network_config:
        raise ConfigurationError("Network configuration must specify application ports")
    
    logger.debug("Configuration structure validation passed")

def _set_default_values(config: Dict[str, Any]) -> Dict[str, Any]:
    """Set default values for missing configuration options"""
    
    # System defaults
    if 'system' not in config:
        config['system'] = {}
    
    system_defaults = {
        'name': 'PQ-V2G',
        'version': '1.0.0',
        'debug': False
    }
    
    for key, value in system_defaults.items():
        if key not in config['system']:
            config['system'][key] = value
    
    # Crypto defaults
    crypto_defaults = {
        'security': {
            'constant_time': True,
            'masked_operations': True,
            'timing_attack_protection': True
        },
        'tls': {
            'version': '1.3',
            'session_resumption': False,
            'export_key_material': True
        }
    }
    
    for section, defaults in crypto_defaults.items():
        if section not in config['crypto']:
            config['crypto'][section] = defaults
        else:
            for key, value in defaults.items():
                if key not in config['crypto'][section]:
                    config['crypto'][section][key] = value
    
    # Network defaults
    network_defaults = {
        'transport': {
            'timeout_seconds': 30,
            'max_retries': 3
        },
        'application': {
            'websocket_port': 8080,
            'tls_port': 8443,
            'sidelink_port': 8844
        }
    }
    
    for section, defaults in network_defaults.items():
        if section not in config['network']:
            config['network'][section] = defaults
        else:
            for key, value in defaults.items():
                if key not in config['network'][section]:
                    config['network'][section][key] = value
    
    # Identity defaults
    identity_defaults = {
        'ca': {
            'root_validity_years': 10,
            'intermediate_validity_years': 5,
            'end_entity_validity_days': 30
        },
        'pseudonyms': {
            'pool_size': 10,
            'rotation_policy': 'piecewise_constant',
            'max_issuance_per_day': 100
        }
    }
    
    for section, defaults in identity_defaults.items():
        if section not in config['identity']:
            config['identity'][section] = defaults
        else:
            for key, value in defaults.items():
                if key not in config['identity'][section]:
                    config['identity'][section][key] = value
    
    # Performance defaults
    if 'performance' not in config:
        config['performance'] = {}
    
    performance_defaults = {
        'latency': {
            'start_of_charge_ms': 50,
            'perceptibility_threshold_ms': 100
        },
        'memory': {
            'max_heap_mb': 256,
            'stack_size_kb': 64
        }
    }
    
    for section, defaults in performance_defaults.items():
        if section not in config['performance']:
            config['performance'][section] = defaults
        else:
            for key, value in defaults.items():
                if key not in config['performance'][section]:
                    config['performance'][section][key] = value
    
    return config

def get_config_value(config: Dict[str, Any], path: str, default: Any = None) -> Any:
    """
    Get configuration value using dot notation path
    
    Args:
        config: Configuration dictionary
        path: Dot-separated path (e.g., 'crypto.kem.algorithm')
        default: Default value if path not found
        
    Returns:
        Configuration value or default
    """
    try:
        keys = path.split('.')
        value = config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
        
    except Exception:
        return default

def validate_crypto_config(config: Dict[str, Any]) -> bool:
    """Validate cryptographic configuration parameters"""
    try:
        crypto_config = config.get('crypto', {})
        
        # Validate KEM configuration
        kem_config = crypto_config.get('kem', {})
        if kem_config.get('algorithm') not in ['ML-KEM-768', 'ML-KEM-512', 'ML-KEM-1024']:
            logger.error(f"Invalid KEM algorithm: {kem_config.get('algorithm')}")
            return False
        
        # Validate signature configuration
        sig_config = crypto_config.get('signature', {})
        primary_sig = sig_config.get('primary')
        if primary_sig not in ['ML-DSA-65', 'ML-DSA-87', 'SLH-DSA']:
            logger.error(f"Invalid signature algorithm: {primary_sig}")
            return False
        
        # Validate security settings
        security_config = crypto_config.get('security', {})
        if not security_config.get('constant_time', True):
            logger.warning("Constant-time protection is disabled")
        
        if not security_config.get('timing_attack_protection', True):
            logger.warning("Timing attack protection is disabled")
        
        logger.debug("Crypto configuration validation passed")
        return True
        
    except Exception as e:
        logger.error(f"Crypto configuration validation failed: {e}")
        return False

def validate_network_config(config: Dict[str, Any]) -> bool:
    """Validate network configuration parameters"""
    try:
        network_config = config.get('network', {})
        
        # Validate application ports
        app_config = network_config.get('application', {})
        ports = ['websocket_port', 'tls_port', 'sidelink_port']
        
        for port_key in ports:
            port = app_config.get(port_key)
            if port and (not isinstance(port, int) or port < 1 or port > 65535):
                logger.error(f"Invalid port number for {port_key}: {port}")
                return False
        
        # Validate PLC configuration
        plc_config = network_config.get('plc', {})
        bandwidth = plc_config.get('bandwidth_mbps')
        if bandwidth and (not isinstance(bandwidth, (int, float)) or bandwidth <= 0):
            logger.error(f"Invalid PLC bandwidth: {bandwidth}")
            return False
        
        logger.debug("Network configuration validation passed")
        return True
        
    except Exception as e:
        logger.error(f"Network configuration validation failed: {e}")
        return False

def save_config(config: Dict[str, Any], output_path: str):
    """Save configuration to YAML file"""
    try:
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False, indent=2)
        
        logger.info(f"Configuration saved to {output_path}")
        
    except Exception as e:
        raise ConfigurationError(f"Failed to save configuration: {e}")

def merge_configs(base_config: Dict[str, Any], override_config: Dict[str, Any]) -> Dict[str, Any]:
    """Merge two configuration dictionaries, with override taking precedence"""
    def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    return deep_merge(base_config, override_config)

# Export main functions
__all__ = [
    'load_config',
    'get_config_value', 
    'validate_crypto_config',
    'validate_network_config',
    'save_config',
    'merge_configs',
    'ConfigurationError'
]

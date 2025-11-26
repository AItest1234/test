# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2024-11-26

### Complete Rebuild - WinSCP Extension

This is a complete rebuild of the project from a VAPT tool to a WinSCP Extension for SSH automation and Fusion deployment configuration.

### Added

- **SSH Automation Module** (`ssh_automation.py`)
  - Automated SSH key generation (4096-bit RSA)
  - SSH client/server installation on Windows
  - Secure private key permission management
  - Remote command execution via SSH
  - File upload/download capabilities
  - Cross-platform support (Windows/Linux)

- **Deployment Automation Module** (`deployment_automation.py`)
  - End-to-end deployment workflow automation
  - Application server configuration
  - Fusion server configuration
  - Configuration file generation
  - Project folder setup
  - Setup verification and validation

- **CLI Interface** (`main.py`)
  - Interactive mode for user-friendly setup
  - Non-interactive mode for automation
  - Rich console output with progress indicators
  - Comprehensive error handling
  - Debug mode for troubleshooting

- **Configuration Management** (`config.py`)
  - Pydantic-based configuration validation
  - Environment variable support
  - Configuration templates for properties files
  - Support for multiple technology stacks (JAVA/.NET)

### Features

- ✓ Automated SSH key generation and distribution
- ✓ Secure key permission management (Windows ACLs)
- ✓ Configuration file auto-generation
- ✓ Cross-platform support (Windows/Linux)
- ✓ Interactive and non-interactive modes
- ✓ Rich CLI with progress indicators
- ✓ Comprehensive error handling and logging
- ✓ Environment variable configuration
- ✓ SSH key passphrase support
- ✓ Project folder structure creation
- ✓ Configuration template management

### Automated Tasks

#### Application Server
1. Install/enable SSH client
2. Clean old SSH keys
3. Generate new RSA key pair (4096-bit, PEM format)
4. Set secure permissions on private key
5. Move private key to deployment folder
6. Create Fusionliteproject.properties
7. Create Fusionliteproject.ps1 (Windows) or .sh (Linux)

#### Fusion Server
1. Copy public key to authorized_keys
2. Create project folder structure
3. Generate project configuration files
4. Set up project properties and XML files

### Documentation

- Complete README.md with installation and usage guide
- QUICKSTART.md with practical examples
- Inline code documentation
- Comprehensive help text in CLI

### Dependencies

- paramiko>=3.4.0 - SSH protocol implementation
- pywinrm>=0.4.3 - Windows Remote Management
- typer>=0.9.0 - CLI framework
- rich>=13.7.0 - Rich terminal output
- pydantic>=2.5.0 - Data validation
- pydantic-settings>=2.1.0 - Settings management
- cryptography>=41.0.7 - Cryptographic operations

### Removed

- Previous VAPT (Vulnerability Assessment and Penetration Testing) functionality
- analyzer.py (VAPT engine)
- ui_components.py (VAPT UI components)
- test_confidence_gating.py
- test_exploitation_mode.py
- All VAPT-related documentation

### Project Structure

```
winscp-extension/
├── main.py                      # CLI entry point
├── config.py                    # Configuration management
├── ssh_automation.py            # SSH operations
├── deployment_automation.py     # Deployment workflow
├── requirements.txt             # Python dependencies
├── README.md                    # Main documentation
├── QUICKSTART.md               # Quick start guide
├── CHANGELOG.md                # This file
└── .gitignore                  # Git ignore rules
```

### Breaking Changes

- Complete rewrite - no backward compatibility with previous VAPT tool
- New command structure: `python main.py setup` instead of VAPT commands
- New configuration format using Pydantic models
- Different dependency requirements

### Security

- SSH keys generated with 4096-bit RSA encryption
- Proper Windows ACL permissions on private keys
- Password handling without logging
- Secure SSH connections with paramiko
- No hardcoded credentials

### Known Limitations

- Fusionliteproject.ps1/.sh templates need to be copied manually from Fusion server
- Renci.SshNet.dll must be provided separately for .NET applications
- Requires administrative privileges on Windows for SSH installation
- Requires network connectivity between Application and Fusion servers

### Future Enhancements

- Automatic template file copying from Fusion server
- Web-based UI for configuration
- Batch processing for multiple projects
- Configuration validation before execution
- Rollback functionality
- Support for additional authentication methods
- Integration with CI/CD pipelines

## Migration Guide

If you were using the previous VAPT tool:

1. This is a completely different tool - no migration path available
2. Previous VAPT functionality has been completely removed
3. Update your scripts and documentation to use the new WinSCP Extension commands
4. Review the new README.md and QUICKSTART.md for usage instructions

For SSH automation and Fusion deployment, use this new tool.
For vulnerability assessment and penetration testing, you'll need a different tool.

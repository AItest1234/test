# WinSCP Extension - SSH Automation for Fusion Deployment

A Python-based automation tool for setting up SSH keys and configuring deployment folders between Fusion Server and Application Server.

## Overview

This extension automates the complete SSH setup and configuration process required for Fusion application deployment, eliminating manual steps and reducing setup time.

## Features

- **Automated SSH Key Management**
  - Install/enable SSH client on Application server
  - Generate new RSA key pairs
  - Securely copy public keys to Fusion server
  - Configure proper permissions automatically

- **Configuration File Management**
  - Auto-generate Fusionliteproject.properties
  - Auto-generate Fusionliteproject.ps1/sh scripts
  - Create and configure project folders on Fusion server
  - Handle application-specific configuration files

- **Cross-Platform Support**
  - Windows Application servers (PowerShell)
  - Linux Application servers (Bash)
  - Automated remote execution via SSH/WinRM

## Requirements

```
Python 3.8+
paramiko>=3.4.0
pywinrm>=0.4.3
typer>=0.9.0
rich>=13.7.0
pydantic>=2.5.0
pydantic-settings>=2.1.0
cryptography>=41.0.7
```

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Interactive Mode

```bash
python main.py setup
```

The tool will prompt you for:
- Application Deployment Folder Path
- Application Server IP/Hostname
- Application Server SSH Username
- Application Server SSH Password (or key file)
- Fusion Server IP
- Fusion Server Port (default: 22)
- Fusion Server User (default: fusion)
- Project Name
- Application File Name
- Technology Stack (JAVA/.NET)

### Command Line Mode

```bash
python main.py setup \
  --app-folder "C:\MyApp\Deployment" \
  --app-server-host "192.168.1.100" \
  --app-server-user "administrator" \
  --app-server-pass "password" \
  --fusion-server-host "192.168.1.50" \
  --fusion-server-port 22 \
  --project-name "MyProject" \
  --app-file "Application.zip" \
  --tech-stack "JAVA"
```

## What It Does

### On Application Server

1. Enables SSH client (if not already enabled)
2. Cleans up old SSH keys in `C:\Users\<User>\.ssh`
3. Generates new RSA key pair in PEM format
4. Moves private key to application deployment folder
5. Sets secure permissions on private key
6. Copies configuration templates (Fusionliteproject.properties, Fusionliteproject.ps1)
7. Configures properties file with correct values
8. Copies Renci.SshNet.dll to deployment folder

### On Fusion Server

1. Copies public key to `C:\FusionLiteInsight\FusionLiteProjectService\authorized_keys`
2. Creates project folder in `C:\FusionLiteProjects\<ProjectName>`
3. Copies and renames template files (Application.properties → ProjectName.properties)
4. Configures project properties with Application server details

## Configuration Files

### Fusionliteproject.properties (Application Server)

```properties
FusionLiteProject=<ProjectName>
FusionLiteServerHost=<FusionServerIP>
FusionLiteServerPort=22
FusionLiteServerUser=fusion
FusionLiteServerKeyFile=<PathToPrivateKey>
FusionLiteServerKeyPass=<KeyPassphrase>
ApplicationFile=<ApplicationFileName>
ApplicationInclude=<RegexForInclusion>
ApplicationExclude=<RegexForExclusion>
InstrumentedFile=<ApplicationFileName>
InstrumentedFolder=Instrumented
```

### ProjectName.properties (Fusion Server)

```properties
Name=<ProjectName>
InstrumentorAddress=<ApplicationServerIP>
```

## Pipeline Execution

After setup is complete:

1. On Fusion Server:
   ```
   C:\FusionLiteInsight\FusionLiteProjectService\FusionLiteProjectServiceStart.cmd
   ```

2. On Application Server:
   ```powershell
   # Windows
   .\Fusionliteproject.ps1
   
   # Linux
   ./Fusionliteproject.sh
   ```

## Security Notes

- SSH keys are generated with 4096-bit RSA encryption
- Private keys are secured with proper Windows ACLs
- Passwords are handled securely and not logged
- All operations are logged for audit purposes

## Troubleshooting

### SSH Connection Issues
- Verify Windows Firewall allows SSH (port 22)
- Check OpenSSH Server is installed and running
- Verify user has administrative privileges

### Permission Issues
- Ensure running as Administrator on Windows
- Check folder permissions on both servers
- Verify SSH key permissions are correctly set

### Configuration Issues
- Verify all paths use correct separators (\ for Windows, / for Linux)
- Check project name matches folder name (case-sensitive)
- Ensure Fusion server paths exist before running

## Additional Commands

```bash
# Show version
python main.py version

# Show system information
python main.py info

# Get help
python main.py --help
python main.py setup --help
```

## Architecture

The tool consists of the following modules:

- **main.py**: CLI entry point with Typer
- **config.py**: Configuration management with Pydantic
- **ssh_automation.py**: SSH operations and key generation
- **deployment_automation.py**: End-to-end deployment workflow

## License

MIT License

## Support

For issues or questions, please contact the Fusion support team.

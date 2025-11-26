# Installation Guide - WinSCP Extension

## Prerequisites

### System Requirements

- **Python**: 3.8 or higher
- **Operating System**: 
  - Linux (Ubuntu, CentOS, Debian, etc.)
  - macOS
  - Windows 10/11/Server
- **Network**: SSH connectivity to Application and Fusion servers
- **Permissions**: Administrative/sudo access on target servers

### Access Requirements

- SSH credentials for Application server
- SSH credentials for Fusion server
- Administrative privileges on Windows servers (for OpenSSH installation)

## Installation Methods

### Method 1: Automated Setup (Recommended)

#### On Linux/macOS

```bash
# Clone or download the repository
git clone <repository-url>
cd winscp-extension

# Run setup script
chmod +x setup.sh
./setup.sh
```

#### On Windows

```cmd
REM Clone or download the repository
git clone <repository-url>
cd winscp-extension

REM Run setup script
setup.bat
```

### Method 2: Manual Installation

#### Step 1: Install Python

**Linux (Ubuntu/Debian)**
```bash
sudo apt update
sudo apt install python3 python3-pip -y
```

**Linux (CentOS/RHEL)**
```bash
sudo yum install python3 python3-pip -y
```

**macOS**
```bash
brew install python3
```

**Windows**
- Download from [python.org](https://www.python.org/downloads/)
- Run installer and check "Add Python to PATH"

#### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

Or install individually:
```bash
pip install paramiko>=3.4.0
pip install pywinrm>=0.4.3
pip install typer>=0.9.0
pip install rich>=13.7.0
pip install pydantic>=2.5.0
pip install pydantic-settings>=2.1.0
pip install cryptography>=41.0.7
```

#### Step 3: Verify Installation

```bash
python main.py --help
python main.py version
python main.py info
```

### Method 3: Virtual Environment (Recommended for Development)

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Verify installation
python main.py version
```

### Method 4: Docker (Coming Soon)

```bash
# Build image
docker build -t winscp-extension .

# Run container
docker run -it winscp-extension setup
```

## Configuration

### Option 1: Environment Variables

Create a `.env` file:

```bash
cp .env.example .env
# Edit .env with your values
nano .env  # or vim, vi, etc.
```

Example `.env`:
```properties
WINSCP_EXT_APP_SERVER_HOST=192.168.1.100
WINSCP_EXT_APP_SERVER_USER=administrator
WINSCP_EXT_APP_SERVER_PASS=your_password
WINSCP_EXT_FUSION_SERVER_HOST=192.168.1.50
WINSCP_EXT_FUSION_SERVER_PASS=your_password
WINSCP_EXT_PROJECT_NAME=MyProject
```

### Option 2: Command Line Arguments

```bash
python main.py setup \
  --app-folder "C:\MyApp\Deploy" \
  --app-server-host "192.168.1.100" \
  --app-server-user "admin" \
  --app-server-pass "password" \
  --fusion-server-host "192.168.1.50" \
  --fusion-server-pass "password" \
  --project-name "MyProject"
```

### Option 3: Interactive Mode

```bash
python main.py setup
# Follow the prompts
```

## Verification

### Test SSH Connectivity

Before running the tool, verify SSH access:

```bash
# Test Application server
ssh user@app-server-ip

# Test Fusion server
ssh user@fusion-server-ip
```

### Test OpenSSH on Windows

```powershell
# Check if OpenSSH Client is installed
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Client*'

# Check if OpenSSH Server is installed
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
```

### Verify Tool Installation

```bash
# Check version
python main.py version

# Check system info
python main.py info

# Verify imports
python -c "from main import app; print('OK')"
```

## Troubleshooting Installation

### Issue: Python Not Found

**Solution:**
```bash
# Linux
sudo apt install python3

# macOS
brew install python3

# Windows
# Download and install from python.org
```

### Issue: pip Not Found

**Solution:**
```bash
# Linux
sudo apt install python3-pip

# macOS
python3 -m ensurepip

# Windows
python -m ensurepip --upgrade
```

### Issue: Permission Denied (Linux)

**Solution:**
```bash
# Option 1: Use --user flag
pip install --user -r requirements.txt

# Option 2: Use virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Issue: SSL Certificate Error

**Solution:**
```bash
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
```

### Issue: Module Not Found

**Solution:**
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall

# Or install specific module
pip install paramiko typer rich pydantic
```

### Issue: Command Not Found (Windows)

**Solution:**
- Ensure Python is in PATH
- Run from Command Prompt or PowerShell (not PowerShell ISE)
- Use full path: `C:\Python39\python.exe main.py`

## Post-Installation Steps

### 1. Configure Access

Ensure you have:
- [ ] Application server SSH credentials
- [ ] Fusion server SSH credentials
- [ ] Deployment folder path
- [ ] Project name

### 2. Test Connectivity

```bash
# Test Application server
ssh user@app-server-ip "echo OK"

# Test Fusion server
ssh user@fusion-server-ip "echo OK"
```

### 3. Run First Setup

```bash
# Interactive mode (recommended for first time)
python main.py setup
```

### 4. Verify Results

Check the following on Application server:
- [ ] SSH keys generated
- [ ] Fusionliteproject.properties created
- [ ] Fusionliteproject.ps1/sh created

Check the following on Fusion server:
- [ ] authorized_keys updated
- [ ] Project folder created
- [ ] Project properties created
- [ ] Project XML created

## Upgrade Instructions

### From Source

```bash
# Pull latest changes
git pull origin main

# Reinstall dependencies
pip install -r requirements.txt --upgrade

# Verify version
python main.py version
```

### Manual Upgrade

```bash
# Backup current installation
cp -r winscp-extension winscp-extension.backup

# Download new version
# Extract and replace files

# Reinstall dependencies
pip install -r requirements.txt --upgrade
```

## Uninstallation

### Remove Tool

```bash
# If using virtual environment
deactivate
rm -rf venv

# Remove directory
cd ..
rm -rf winscp-extension
```

### Remove Dependencies (Optional)

```bash
pip uninstall paramiko pywinrm typer rich pydantic pydantic-settings cryptography
```

### Clean Up Configuration

```bash
# Remove .env file
rm .env

# Remove generated keys (if needed)
# Be careful - this removes SSH keys!
rm ~/.ssh/id_rsa*
```

## Getting Help

### Documentation

- [README.md](README.md) - Main documentation
- [QUICKSTART.md](QUICKSTART.md) - Quick start guide
- [FEATURES.md](FEATURES.md) - Feature overview
- [CHANGELOG.md](CHANGELOG.md) - Version history

### Command Help

```bash
# General help
python main.py --help

# Command-specific help
python main.py setup --help

# Show version
python main.py version

# Show system info
python main.py info
```

### Debug Mode

```bash
# Run with debug output
python main.py setup --debug
```

### Support

For issues or questions:
1. Check documentation files
2. Review error messages carefully
3. Try debug mode
4. Check prerequisites and connectivity
5. Contact support team

## Next Steps

After successful installation:

1. **Read Documentation**
   - Review [QUICKSTART.md](QUICKSTART.md) for examples
   - Check [FEATURES.md](FEATURES.md) for capabilities

2. **Configure Environment**
   - Set up `.env` file or use command-line args
   - Test SSH connectivity

3. **Run First Setup**
   - Use interactive mode for guidance
   - Verify results on both servers

4. **Test Deployment**
   - Start Fusion Project Service
   - Run deployment script
   - Verify application instrumentation

5. **Automate**
   - Create shell scripts for common tasks
   - Integrate with CI/CD pipeline
   - Document your specific configuration

## Additional Resources

- **Python**: https://www.python.org/
- **Paramiko**: https://www.paramiko.org/
- **Typer**: https://typer.tiangolo.com/
- **Rich**: https://rich.readthedocs.io/
- **Pydantic**: https://docs.pydantic.dev/

---

**Installation complete!** You're ready to use WinSCP Extension.

For quick start, run: `python main.py setup`

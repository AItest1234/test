# Quick Start Guide

## Installation

1. Install Python 3.8 or higher
2. Clone the repository
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Basic Usage

### Interactive Setup (Recommended for First-Time Users)

```bash
python main.py setup
```

Follow the interactive prompts to provide:
- Application deployment folder path
- Application server credentials
- Fusion server credentials
- Project configuration

### Non-Interactive Setup (For Automation)

```bash
python main.py setup \
  --app-folder "C:\MyApp\Deployment" \
  --app-server-host "192.168.1.100" \
  --app-server-user "administrator" \
  --app-server-pass "SecurePass123" \
  --fusion-server-host "192.168.1.50" \
  --fusion-server-pass "FusionPass123" \
  --project-name "MyProject" \
  --no-interactive
```

## Complete Example: Windows to Windows

### Scenario
- **Application Server**: Windows Server 2019 (192.168.1.100)
- **Fusion Server**: Windows Server 2022 (192.168.1.50)
- **Project Name**: MyJavaApp
- **Deployment Folder**: C:\Apps\MyJavaApp\Deploy

### Command

```bash
python main.py setup \
  --app-folder "C:\Apps\MyJavaApp\Deploy" \
  --app-server-host "192.168.1.100" \
  --app-server-user "Administrator" \
  --app-server-pass "AppServerPass" \
  --fusion-server-host "192.168.1.50" \
  --fusion-server-pass "FusionPass" \
  --project-name "MyJavaApp" \
  --app-file "MyJavaApp.zip" \
  --app-include ".*(service|core|api)-[0-9.]+\.jar$" \
  --tech-stack "JAVA"
```

### What Happens

1. ✓ Connects to Application Server
2. ✓ Enables OpenSSH Client
3. ✓ Cleans old SSH keys
4. ✓ Generates new 4096-bit RSA key pair
5. ✓ Sets secure permissions on private key
6. ✓ Moves private key to deployment folder
7. ✓ Creates Fusionliteproject.properties
8. ✓ Creates Fusionliteproject.ps1
9. ✓ Connects to Fusion Server
10. ✓ Copies public key to authorized_keys
11. ✓ Creates project folder: C:\FusionLiteProjects\MyJavaApp
12. ✓ Creates MyJavaApp.properties
13. ✓ Creates MyJavaApp.xml

### After Setup

1. Start Fusion Project Service:
   ```cmd
   C:\FusionLiteInsight\FusionLiteProjectService\FusionLiteProjectServiceStart.cmd
   ```

2. Run deployment on Application Server:
   ```powershell
   cd C:\Apps\MyJavaApp\Deploy
   .\Fusionliteproject.ps1
   ```

## Complete Example: Linux to Windows

### Scenario
- **Application Server**: Ubuntu 22.04 (192.168.1.200)
- **Fusion Server**: Windows Server 2022 (192.168.1.50)
- **Project Name**: MyLinuxApp
- **Deployment Folder**: /opt/apps/myapp/deploy

### Command

```bash
python main.py setup \
  --app-folder "/opt/apps/myapp/deploy" \
  --app-server-host "192.168.1.200" \
  --app-server-user "appuser" \
  --app-server-pass "LinuxPass" \
  --fusion-server-host "192.168.1.50" \
  --fusion-server-pass "FusionPass" \
  --project-name "MyLinuxApp" \
  --app-file "myapp.tar.gz" \
  --tech-stack "JAVA"
```

### After Setup

1. Start Fusion Project Service (on Windows):
   ```cmd
   C:\FusionLiteInsight\FusionLiteProjectService\FusionLiteProjectServiceStart.cmd
   ```

2. Run deployment on Application Server (on Linux):
   ```bash
   cd /opt/apps/myapp/deploy
   ./Fusionliteproject.sh
   ```

## Environment Variables

You can also configure using environment variables:

```bash
export WINSCP_EXT_APP_SERVER_HOST="192.168.1.100"
export WINSCP_EXT_APP_SERVER_USER="Administrator"
export WINSCP_EXT_APP_SERVER_PASS="SecurePass"
export WINSCP_EXT_FUSION_SERVER_HOST="192.168.1.50"
export WINSCP_EXT_FUSION_SERVER_PASS="FusionPass"
export WINSCP_EXT_PROJECT_NAME="MyProject"

python main.py setup --app-folder "C:\MyApp\Deploy"
```

## Common Issues

### "Connection refused"
- Ensure SSH server is running on both servers
- Check firewall rules allow port 22
- Verify network connectivity

### "Permission denied"
- Ensure user has administrative privileges
- Check user credentials are correct
- On Windows, run as Administrator

### "Directory not found"
- Verify paths are correct
- On Windows, use backslashes: `C:\Path\To\Folder`
- On Linux, use forward slashes: `/path/to/folder`

### "SSH key generation failed"
- Ensure ssh-keygen is installed
- Check .ssh directory permissions
- Verify user has write access

## Tips

1. **Use SSH Keys for Initial Connection**: If you have an existing SSH key, use `--app-server-key` instead of password
2. **Test Connectivity First**: Use `ssh user@host` to verify connectivity before running the tool
3. **Backup Existing Keys**: The tool will delete old keys - backup if needed
4. **Check Logs**: Use `--debug` flag for detailed logging
5. **Case-Sensitive Project Names**: Project name must match deployment folder name exactly

## Next Steps

After successful setup:
1. Review generated configuration files
2. Copy actual Fusionliteproject.ps1/sh from templates if needed
3. Copy Renci.SshNet.dll to deployment folder (for .NET apps)
4. Test the deployment pipeline
5. Document your specific configuration

For more details, see [README.md](README.md)

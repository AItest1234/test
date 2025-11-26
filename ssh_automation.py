"""SSH automation module for key generation and remote operations."""

import os
import stat
import logging
from pathlib import Path
from typing import Optional, Tuple
import paramiko
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()
log = logging.getLogger(__name__)


class SSHAutomation:
    """Handles SSH operations including key generation and remote command execution."""
    
    def __init__(self, host: str, username: str, password: Optional[str] = None, 
                 key_file: Optional[str] = None, port: int = 22):
        self.host = host
        self.username = username
        self.password = password
        self.key_file = key_file
        self.port = port
        self.client = None
        
    def connect(self) -> bool:
        """Establish SSH connection."""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if self.key_file:
                self.client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    key_filename=self.key_file
                )
            else:
                self.client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password
                )
            
            console.print(f"[green]✓[/green] Connected to {self.host}")
            return True
            
        except Exception as e:
            console.print(f"[red]✗[/red] Connection failed: {str(e)}")
            log.error(f"SSH connection failed: {e}")
            return False
    
    def disconnect(self):
        """Close SSH connection."""
        if self.client:
            self.client.close()
            console.print(f"[yellow]Disconnected from {self.host}[/yellow]")
    
    def execute_command(self, command: str, sudo: bool = False) -> Tuple[int, str, str]:
        """Execute a command on the remote server."""
        if not self.client:
            return -1, "", "Not connected"
        
        try:
            if sudo:
                command = f"echo {self.password} | sudo -S {command}"
            
            stdin, stdout, stderr = self.client.exec_command(command)
            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            
            return exit_code, output, error
            
        except Exception as e:
            log.error(f"Command execution failed: {e}")
            return -1, "", str(e)
    
    def execute_powershell(self, script: str) -> Tuple[int, str, str]:
        """Execute a PowerShell script on Windows server."""
        command = f'powershell -Command "{script}"'
        return self.execute_command(command)
    
    def file_exists(self, path: str) -> bool:
        """Check if a file exists on the remote server."""
        sftp = self.client.open_sftp()
        try:
            sftp.stat(path)
            sftp.close()
            return True
        except FileNotFoundError:
            sftp.close()
            return False
    
    def mkdir(self, path: str, mode: int = 0o755) -> bool:
        """Create a directory on the remote server."""
        try:
            sftp = self.client.open_sftp()
            sftp.mkdir(path, mode)
            sftp.close()
            console.print(f"[green]✓[/green] Created directory: {path}")
            return True
        except Exception as e:
            log.error(f"Failed to create directory {path}: {e}")
            return False
    
    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """Upload a file to the remote server."""
        try:
            sftp = self.client.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            console.print(f"[green]✓[/green] Uploaded: {local_path} → {remote_path}")
            return True
        except Exception as e:
            console.print(f"[red]✗[/red] Upload failed: {str(e)}")
            log.error(f"File upload failed: {e}")
            return False
    
    def download_file(self, remote_path: str, local_path: str) -> bool:
        """Download a file from the remote server."""
        try:
            sftp = self.client.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            console.print(f"[green]✓[/green] Downloaded: {remote_path} → {local_path}")
            return True
        except Exception as e:
            console.print(f"[red]✗[/red] Download failed: {str(e)}")
            log.error(f"File download failed: {e}")
            return False
    
    def write_remote_file(self, remote_path: str, content: str) -> bool:
        """Write content to a file on the remote server."""
        try:
            sftp = self.client.open_sftp()
            with sftp.file(remote_path, 'w') as f:
                f.write(content)
            sftp.close()
            console.print(f"[green]✓[/green] Created file: {remote_path}")
            return True
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to write file: {str(e)}")
            log.error(f"File write failed: {e}")
            return False
    
    def read_remote_file(self, remote_path: str) -> Optional[str]:
        """Read content from a file on the remote server."""
        try:
            sftp = self.client.open_sftp()
            with sftp.file(remote_path, 'r') as f:
                content = f.read().decode('utf-8')
            sftp.close()
            return content
        except Exception as e:
            log.error(f"File read failed: {e}")
            return None
    
    def set_file_permissions(self, remote_path: str, mode: int) -> bool:
        """Set file permissions on the remote server."""
        try:
            sftp = self.client.open_sftp()
            sftp.chmod(remote_path, mode)
            sftp.close()
            console.print(f"[green]✓[/green] Set permissions {oct(mode)} on {remote_path}")
            return True
        except Exception as e:
            log.error(f"Failed to set permissions: {e}")
            return False


class WindowsSSHSetup:
    """Handles Windows-specific SSH setup operations."""
    
    def __init__(self, ssh_client: SSHAutomation):
        self.ssh = ssh_client
    
    def enable_ssh_client(self) -> bool:
        """Enable OpenSSH client on Windows."""
        console.print("\n[bold cyan]Enabling OpenSSH Client...[/bold cyan]")
        
        # Check if already installed
        check_cmd = "Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Client*'"
        exit_code, output, _ = self.ssh.execute_powershell(check_cmd)
        
        if "Installed" in output:
            console.print("[green]✓[/green] OpenSSH Client already installed")
            return True
        
        # Install OpenSSH Client
        install_cmd = "Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0"
        exit_code, output, error = self.ssh.execute_powershell(install_cmd)
        
        if exit_code == 0:
            console.print("[green]✓[/green] OpenSSH Client installed successfully")
            return True
        else:
            console.print(f"[red]✗[/red] Failed to install OpenSSH Client: {error}")
            return False
    
    def enable_ssh_server(self) -> bool:
        """Enable OpenSSH server on Windows."""
        console.print("\n[bold cyan]Enabling OpenSSH Server...[/bold cyan]")
        
        commands = [
            "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0",
            "Start-Service sshd",
            "Set-Service -Name sshd -StartupType 'Automatic'",
            "New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22"
        ]
        
        for cmd in commands:
            exit_code, output, error = self.ssh.execute_powershell(cmd)
            if exit_code != 0 and "already exists" not in error:
                log.warning(f"Command may have failed: {error}")
        
        console.print("[green]✓[/green] OpenSSH Server configured")
        return True
    
    def clean_old_keys(self, user_home: str) -> bool:
        """Remove old SSH keys."""
        console.print("\n[bold cyan]Cleaning old SSH keys...[/bold cyan]")
        
        ssh_dir = f"{user_home}\\.ssh"
        
        # Check if .ssh directory exists
        check_cmd = f"Test-Path '{ssh_dir}'"
        exit_code, output, _ = self.ssh.execute_powershell(check_cmd)
        
        if "True" in output:
            # Remove old keys
            remove_cmd = f"Remove-Item '{ssh_dir}\\id_rsa*' -Force -ErrorAction SilentlyContinue"
            self.ssh.execute_powershell(remove_cmd)
            console.print(f"[green]✓[/green] Cleaned old keys from {ssh_dir}")
        else:
            # Create .ssh directory
            mkdir_cmd = f"New-Item -Path '{ssh_dir}' -ItemType Directory -Force"
            self.ssh.execute_powershell(mkdir_cmd)
            console.print(f"[green]✓[/green] Created {ssh_dir}")
        
        return True
    
    def generate_ssh_keys(self, user_home: str, passphrase: Optional[str] = None) -> bool:
        """Generate new SSH key pair."""
        console.print("\n[bold cyan]Generating SSH key pair...[/bold cyan]")
        
        ssh_dir = f"{user_home}\\.ssh"
        key_path = f"{ssh_dir}\\id_rsa"
        
        # Generate key using ssh-keygen
        if passphrase:
            keygen_cmd = f"echo y | ssh-keygen -t rsa -b 4096 -m PEM -f '{key_path}' -N '{passphrase}'"
        else:
            keygen_cmd = f"echo y | ssh-keygen -t rsa -b 4096 -m PEM -f '{key_path}' -N ''"
        
        exit_code, output, error = self.ssh.execute_powershell(keygen_cmd)
        
        if exit_code == 0 or self.ssh.file_exists(key_path):
            console.print(f"[green]✓[/green] Generated SSH key pair at {key_path}")
            return True
        else:
            console.print(f"[red]✗[/red] Failed to generate SSH keys: {error}")
            return False
    
    def set_private_key_permissions(self, key_path: str, username: str) -> bool:
        """Set secure permissions on private key."""
        console.print("\n[bold cyan]Setting private key permissions...[/bold cyan]")
        
        # PowerShell script to set ACL
        acl_script = f"""
        $path = '{key_path}'
        $acl = Get-Acl $path
        $acl.SetAccessRuleProtection($true, $false)
        $AdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule('{username}','FullControl','Allow')
        $acl.SetAccessRule($AdminRule)
        Set-Acl $path $acl
        """
        
        exit_code, output, error = self.ssh.execute_powershell(acl_script)
        
        if exit_code == 0:
            console.print(f"[green]✓[/green] Set secure permissions on {key_path}")
            return True
        else:
            console.print(f"[red]✗[/red] Failed to set permissions: {error}")
            return False
    
    def move_private_key(self, source: str, destination: str) -> bool:
        """Move private key to deployment folder."""
        console.print(f"\n[bold cyan]Moving private key to deployment folder...[/bold cyan]")
        
        move_cmd = f"Move-Item -Path '{source}' -Destination '{destination}' -Force"
        exit_code, output, error = self.ssh.execute_powershell(move_cmd)
        
        if exit_code == 0:
            console.print(f"[green]✓[/green] Moved private key to {destination}")
            return True
        else:
            console.print(f"[red]✗[/red] Failed to move private key: {error}")
            return False


def generate_local_ssh_keys(output_dir: str, passphrase: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
    """Generate SSH key pair locally (fallback method)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    
    try:
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        
        # Serialize private key
        encryption = serialization.BestAvailableEncryption(passphrase.encode()) if passphrase else serialization.NoEncryption()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption
        )
        
        # Serialize public key
        public_key = private_key.public_key()
        public_ssh = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )
        
        # Write keys to files
        os.makedirs(output_dir, exist_ok=True)
        
        private_key_path = os.path.join(output_dir, "id_rsa")
        public_key_path = os.path.join(output_dir, "id_rsa.pub")
        
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)
        os.chmod(private_key_path, stat.S_IRUSR | stat.S_IWUSR)
        
        with open(public_key_path, 'wb') as f:
            f.write(public_ssh)
        
        console.print(f"[green]✓[/green] Generated SSH keys locally in {output_dir}")
        return private_key_path, public_key_path
        
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to generate SSH keys: {str(e)}")
        log.error(f"Local key generation failed: {e}")
        return None, None

"""Deployment automation module for configuring Application and Fusion servers."""

import os
import logging
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table

from ssh_automation import SSHAutomation, WindowsSSHSetup
from config import Config, FUSIONLITE_PROPERTIES_TEMPLATE, PROJECT_PROPERTIES_TEMPLATE

console = Console()
log = logging.getLogger(__name__)


class DeploymentAutomation:
    """Handles end-to-end deployment automation."""
    
    def __init__(self, config: Config):
        self.config = config
        self.app_ssh: Optional[SSHAutomation] = None
        self.fusion_ssh: Optional[SSHAutomation] = None
        
    def run_full_setup(self) -> bool:
        """Run the complete setup process."""
        console.print(Panel.fit(
            "[bold cyan]WinSCP Extension - SSH Automation Setup[/bold cyan]\n"
            "Automating SSH key generation and deployment configuration",
            border_style="cyan"
        ))
        
        try:
            # Step 1: Setup Application Server
            if not self.setup_application_server():
                console.print("[red]✗[/red] Application server setup failed")
                return False
            
            # Step 2: Setup Fusion Server
            if not self.setup_fusion_server():
                console.print("[red]✗[/red] Fusion server setup failed")
                return False
            
            # Step 3: Verify Setup
            if not self.verify_setup():
                console.print("[yellow]⚠[/yellow] Setup verification completed with warnings")
            
            self.print_summary()
            return True
            
        except Exception as e:
            console.print(f"[red]✗[/red] Setup failed: {str(e)}")
            log.error(f"Setup failed: {e}", exc_info=True)
            return False
        finally:
            if self.app_ssh:
                self.app_ssh.disconnect()
            if self.fusion_ssh:
                self.fusion_ssh.disconnect()
    
    def setup_application_server(self) -> bool:
        """Setup SSH keys and configuration on Application server."""
        console.print("\n[bold green]═══ Application Server Setup ═══[/bold green]\n")
        
        # Connect to Application server
        self.app_ssh = SSHAutomation(
            host=self.config.app_server_host,
            username=self.config.app_server_user,
            password=self.config.app_server_pass,
            key_file=self.config.app_server_key_file,
            port=self.config.app_server_port
        )
        
        if not self.app_ssh.connect():
            return False
        
        # Detect OS
        exit_code, output, _ = self.app_ssh.execute_command("echo %OS%")
        is_windows = "Windows" in output
        
        if not is_windows:
            console.print("[yellow]⚠[/yellow] Linux application server detected - using alternative approach")
            return self.setup_linux_application_server()
        
        return self.setup_windows_application_server()
    
    def setup_windows_application_server(self) -> bool:
        """Setup Windows Application server."""
        win_setup = WindowsSSHSetup(self.app_ssh)
        
        # Get user home directory
        exit_code, user_home, _ = self.app_ssh.execute_powershell("$env:USERPROFILE")
        user_home = user_home.strip()
        
        # 1. Enable SSH client
        if not win_setup.enable_ssh_client():
            console.print("[yellow]⚠[/yellow] Could not enable SSH client, continuing anyway...")
        
        # 2. Clean old keys
        if not win_setup.clean_old_keys(user_home):
            return False
        
        # 3. Generate new SSH keys
        if not win_setup.generate_ssh_keys(user_home, self.config.ssh_key_passphrase):
            return False
        
        # 4. Set permissions on private key
        ssh_dir = f"{user_home}\\.ssh"
        private_key_path = f"{ssh_dir}\\id_rsa"
        public_key_path = f"{ssh_dir}\\id_rsa.pub"
        
        if not win_setup.set_private_key_permissions(private_key_path, self.config.app_server_user):
            console.print("[yellow]⚠[/yellow] Could not set permissions, continuing anyway...")
        
        # 5. Move private key to deployment folder
        deployment_key_path = f"{self.config.app_deployment_folder}\\id_rsa"
        if not win_setup.move_private_key(private_key_path, deployment_key_path):
            return False
        
        # 6. Copy public key for Fusion server
        public_key_content = self.app_ssh.read_remote_file(public_key_path)
        if not public_key_content:
            console.print("[red]✗[/red] Could not read public key")
            return False
        
        # Store public key for later use
        self.public_key_content = public_key_content
        
        # 7. Create configuration files
        if not self.create_application_config_files(deployment_key_path):
            return False
        
        # 8. Copy Renci.SshNet.dll (if available)
        self.copy_renci_dll()
        
        console.print("\n[bold green]✓ Application server setup complete[/bold green]")
        return True
    
    def setup_linux_application_server(self) -> bool:
        """Setup Linux Application server."""
        console.print("\n[bold cyan]Setting up Linux Application Server...[/bold cyan]")
        
        # Get user home directory
        exit_code, user_home, _ = self.app_ssh.execute_command("echo $HOME")
        user_home = user_home.strip()
        ssh_dir = f"{user_home}/.ssh"
        
        # 1. Create .ssh directory
        self.app_ssh.execute_command(f"mkdir -p {ssh_dir}")
        self.app_ssh.execute_command(f"chmod 700 {ssh_dir}")
        
        # 2. Clean old keys
        self.app_ssh.execute_command(f"rm -f {ssh_dir}/id_rsa*")
        console.print(f"[green]✓[/green] Cleaned old keys from {ssh_dir}")
        
        # 3. Generate SSH keys
        passphrase = self.config.ssh_key_passphrase or ""
        keygen_cmd = f'ssh-keygen -t rsa -b 4096 -m PEM -f {ssh_dir}/id_rsa -N "{passphrase}" -q'
        exit_code, output, error = self.app_ssh.execute_command(keygen_cmd)
        
        if exit_code != 0:
            console.print(f"[red]✗[/red] Failed to generate SSH keys: {error}")
            return False
        
        console.print(f"[green]✓[/green] Generated SSH key pair")
        
        # 4. Set permissions
        self.app_ssh.execute_command(f"chmod 600 {ssh_dir}/id_rsa")
        self.app_ssh.execute_command(f"chmod 644 {ssh_dir}/id_rsa.pub")
        
        # 5. Move private key to deployment folder
        deployment_key_path = f"{self.config.app_deployment_folder}/id_rsa"
        move_cmd = f"mv {ssh_dir}/id_rsa {deployment_key_path}"
        self.app_ssh.execute_command(move_cmd)
        console.print(f"[green]✓[/green] Moved private key to {deployment_key_path}")
        
        # 6. Read public key
        public_key_path = f"{ssh_dir}/id_rsa.pub"
        public_key_content = self.app_ssh.read_remote_file(public_key_path)
        if not public_key_content:
            console.print("[red]✗[/red] Could not read public key")
            return False
        
        self.public_key_content = public_key_content
        
        # 7. Create configuration files (shell script version)
        if not self.create_application_config_files_linux(deployment_key_path):
            return False
        
        console.print("\n[bold green]✓ Linux application server setup complete[/bold green]")
        return True
    
    def create_application_config_files(self, key_path: str) -> bool:
        """Create Fusionliteproject.properties and .ps1 files on Windows."""
        console.print("\n[bold cyan]Creating configuration files...[/bold cyan]")
        
        # Generate properties content
        properties_content = FUSIONLITE_PROPERTIES_TEMPLATE.format(
            project_name=self.config.project_name,
            fusion_host=self.config.fusion_server_host,
            fusion_port=self.config.fusion_server_port,
            fusion_user=self.config.fusion_server_user,
            key_file_path=key_path,
            key_passphrase=self.config.ssh_key_passphrase or "",
            app_file=self.config.application_file,
            app_include=self.config.application_include or ".*",
            app_exclude=self.config.application_exclude or "",
            instrumented_folder=self.config.instrumented_folder
        )
        
        # Write properties file
        properties_path = f"{self.config.app_deployment_folder}\\Fusionliteproject.properties"
        if not self.app_ssh.write_remote_file(properties_path, properties_content):
            return False
        
        # Try to copy PowerShell script from templates
        template_path = f"{self.config.fusion_insight_path}\\Templates\\REMOTE\\PS\\Fusionliteproject.ps1"
        dest_path = f"{self.config.app_deployment_folder}\\Fusionliteproject.ps1"
        
        # Since we can't easily copy from Fusion server to App server directly,
        # we'll create a placeholder script
        ps_script = """# FusionLite Project Deployment Script
# This script should be replaced with the actual template from Fusion server
# Location: C:\\FusionLiteInsight\\FusionLiteProjectService\\Templates\\REMOTE\\PS\\Fusionliteproject.ps1

Write-Host "FusionLite Project Deployment"
Write-Host "Project: {0}" -f (Get-Content .\\Fusionliteproject.properties | Select-String "FusionLiteProject").Line.Split("=")[1]
Write-Host ""
Write-Host "Please replace this script with the actual Fusionliteproject.ps1 from Fusion server templates."
""".format(self.config.project_name)
        
        self.app_ssh.write_remote_file(dest_path, ps_script)
        
        console.print("[yellow]⚠[/yellow] Note: Fusionliteproject.ps1 should be replaced with template from Fusion server")
        
        return True
    
    def create_application_config_files_linux(self, key_path: str) -> bool:
        """Create Fusionliteproject.properties and .sh files on Linux."""
        console.print("\n[bold cyan]Creating configuration files...[/bold cyan]")
        
        # Generate properties content
        properties_content = FUSIONLITE_PROPERTIES_TEMPLATE.format(
            project_name=self.config.project_name,
            fusion_host=self.config.fusion_server_host,
            fusion_port=self.config.fusion_server_port,
            fusion_user=self.config.fusion_server_user,
            key_file_path=key_path,
            key_passphrase=self.config.ssh_key_passphrase or "",
            app_file=self.config.application_file,
            app_include=self.config.application_include or ".*",
            app_exclude=self.config.application_exclude or "",
            instrumented_folder=self.config.instrumented_folder
        )
        
        # Write properties file
        properties_path = f"{self.config.app_deployment_folder}/Fusionliteproject.properties"
        if not self.app_ssh.write_remote_file(properties_path, properties_content):
            return False
        
        # Create shell script placeholder
        sh_script = """#!/bin/bash
# FusionLite Project Deployment Script
# This script should be replaced with the actual template from Fusion server
# Location: /opt/FusionLiteInsight/FusionLiteProjectService/Templates/REMOTE/SH/Fusionliteproject.sh

echo "FusionLite Project Deployment"
echo "Project: $(grep FusionLiteProject Fusionliteproject.properties | cut -d'=' -f2)"
echo ""
echo "Please replace this script with the actual Fusionliteproject.sh from Fusion server templates."
"""
        
        dest_path = f"{self.config.app_deployment_folder}/Fusionliteproject.sh"
        self.app_ssh.write_remote_file(dest_path, sh_script)
        self.app_ssh.execute_command(f"chmod +x {dest_path}")
        
        console.print("[yellow]⚠[/yellow] Note: Fusionliteproject.sh should be replaced with template from Fusion server")
        
        return True
    
    def copy_renci_dll(self) -> bool:
        """Copy Renci.SshNet.dll to deployment folder."""
        # This is a placeholder - in real implementation, this DLL would need to be provided
        console.print("[yellow]⚠[/yellow] Note: Renci.SshNet.dll should be copied manually to deployment folder")
        return True
    
    def setup_fusion_server(self) -> bool:
        """Setup configuration on Fusion server."""
        console.print("\n[bold green]═══ Fusion Server Setup ═══[/bold green]\n")
        
        # Connect to Fusion server
        self.fusion_ssh = SSHAutomation(
            host=self.config.fusion_server_host,
            username=self.config.fusion_server_user,
            password=self.config.fusion_server_pass,
            port=self.config.fusion_server_port
        )
        
        if not self.fusion_ssh.connect():
            return False
        
        # 1. Copy public key to authorized_keys
        if not self.setup_authorized_keys():
            return False
        
        # 2. Create project folder
        if not self.create_project_folder():
            return False
        
        # 3. Setup project configuration files
        if not self.setup_project_config():
            return False
        
        console.print("\n[bold green]✓ Fusion server setup complete[/bold green]")
        return True
    
    def setup_authorized_keys(self) -> bool:
        """Copy public key to Fusion server authorized_keys."""
        console.print("\n[bold cyan]Setting up authorized_keys...[/bold cyan]")
        
        authorized_keys_path = f"{self.config.fusion_insight_path}\\authorized_keys"
        
        # Write public key
        if not self.fusion_ssh.write_remote_file(authorized_keys_path, self.public_key_content):
            return False
        
        console.print(f"[green]✓[/green] Public key added to {authorized_keys_path}")
        return True
    
    def create_project_folder(self) -> bool:
        """Create project folder on Fusion server."""
        console.print("\n[bold cyan]Creating project folder...[/bold cyan]")
        
        project_folder = f"{self.config.fusion_projects_path}\\{self.config.project_name}"
        
        # Check if folder exists, create if not
        check_cmd = f"Test-Path '{project_folder}'"
        exit_code, output, _ = self.fusion_ssh.execute_powershell(check_cmd)
        
        if "False" in output:
            mkdir_cmd = f"New-Item -Path '{project_folder}' -ItemType Directory -Force"
            exit_code, output, error = self.fusion_ssh.execute_powershell(mkdir_cmd)
            
            if exit_code != 0:
                console.print(f"[red]✗[/red] Failed to create project folder: {error}")
                return False
        
        console.print(f"[green]✓[/green] Project folder ready: {project_folder}")
        return True
    
    def setup_project_config(self) -> bool:
        """Setup project configuration files on Fusion server."""
        console.print("\n[bold cyan]Creating project configuration...[/bold cyan]")
        
        project_folder = f"{self.config.fusion_projects_path}\\{self.config.project_name}"
        
        # Generate properties content
        properties_content = PROJECT_PROPERTIES_TEMPLATE.format(
            project_name=self.config.project_name,
            app_server_host=self.config.app_server_host
        )
        
        # Write properties file
        properties_file = f"{project_folder}\\{self.config.project_name}.properties"
        if not self.fusion_ssh.write_remote_file(properties_file, properties_content):
            return False
        
        # Create placeholder XML file
        xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<project name="{self.config.project_name}">
    <!-- Project configuration XML -->
    <!-- This should be customized based on your application requirements -->
    <instrumentor>
        <address>{self.config.app_server_host}</address>
    </instrumentor>
</project>
"""
        
        xml_file = f"{project_folder}\\{self.config.project_name}.xml"
        if not self.fusion_ssh.write_remote_file(xml_file, xml_content):
            return False
        
        console.print(f"[green]✓[/green] Created {self.config.project_name}.properties")
        console.print(f"[green]✓[/green] Created {self.config.project_name}.xml")
        console.print("[yellow]⚠[/yellow] Note: Customize XML file based on application requirements")
        
        return True
    
    def verify_setup(self) -> bool:
        """Verify the setup was successful."""
        console.print("\n[bold cyan]═══ Verifying Setup ═══[/bold cyan]\n")
        
        all_ok = True
        
        # Check Application server files
        app_files = [
            f"{self.config.app_deployment_folder}\\id_rsa",
            f"{self.config.app_deployment_folder}\\Fusionliteproject.properties",
            f"{self.config.app_deployment_folder}\\Fusionliteproject.ps1"
        ]
        
        console.print("[bold]Application Server:[/bold]")
        for file_path in app_files:
            exists = self.app_ssh.file_exists(file_path.replace("\\", "/"))
            if exists:
                console.print(f"  [green]✓[/green] {file_path}")
            else:
                console.print(f"  [red]✗[/red] {file_path}")
                all_ok = False
        
        # Check Fusion server files
        fusion_files = [
            f"{self.config.fusion_insight_path}\\authorized_keys",
            f"{self.config.fusion_projects_path}\\{self.config.project_name}\\{self.config.project_name}.properties",
            f"{self.config.fusion_projects_path}\\{self.config.project_name}\\{self.config.project_name}.xml"
        ]
        
        console.print("\n[bold]Fusion Server:[/bold]")
        for file_path in fusion_files:
            exists = self.fusion_ssh.file_exists(file_path.replace("\\", "/"))
            if exists:
                console.print(f"  [green]✓[/green] {file_path}")
            else:
                console.print(f"  [yellow]⚠[/yellow] {file_path}")
        
        return all_ok
    
    def print_summary(self):
        """Print setup summary."""
        console.print("\n" + "="*70)
        console.print(Panel.fit(
            "[bold green]Setup Complete![/bold green]\n\n"
            f"[cyan]Project:[/cyan] {self.config.project_name}\n"
            f"[cyan]Application Server:[/cyan] {self.config.app_server_host}\n"
            f"[cyan]Fusion Server:[/cyan] {self.config.fusion_server_host}\n"
            f"[cyan]Deployment Folder:[/cyan] {self.config.app_deployment_folder}",
            border_style="green",
            title="✓ Success"
        ))
        
        console.print("\n[bold cyan]Next Steps:[/bold cyan]\n")
        
        table = Table(show_header=False, box=None)
        table.add_column("Step", style="cyan")
        table.add_column("Action", style="white")
        
        table.add_row(
            "1.",
            f"Start Fusion Project Service:\n"
            f"   {self.config.fusion_insight_path}\\FusionLiteProjectServiceStart.cmd"
        )
        table.add_row(
            "2.",
            f"Run deployment script on Application Server:\n"
            f"   {self.config.app_deployment_folder}\\Fusionliteproject.ps1"
        )
        table.add_row(
            "3.",
            "Copy actual Fusionliteproject.ps1 from Fusion templates if needed"
        )
        table.add_row(
            "4.",
            "Copy Renci.SshNet.dll to deployment folder"
        )
        
        console.print(table)
        console.print("\n" + "="*70 + "\n")

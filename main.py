"""WinSCP Extension - Main CLI Entry Point."""

import logging
import sys
from typing import Optional
from pathlib import Path

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import print as rprint

from config import Config
from deployment_automation import DeploymentAutomation

app = typer.Typer(
    name="winscp-ext",
    help="WinSCP Extension for SSH Automation and Fusion Deployment",
    add_completion=False
)

console = Console()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)
log = logging.getLogger(__name__)


def print_banner():
    """Print application banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║           WinSCP Extension - SSH Automation Tool             ║
    ║                                                               ║
    ║         Automated SSH Setup for Fusion Deployment            ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


@app.command()
def setup(
    # Application Server Settings
    app_folder: Optional[str] = typer.Option(
        None, "--app-folder", help="Application deployment folder path"
    ),
    app_server_host: Optional[str] = typer.Option(
        None, "--app-server-host", help="Application server IP/hostname"
    ),
    app_server_port: int = typer.Option(
        22, "--app-server-port", help="Application server SSH port"
    ),
    app_server_user: Optional[str] = typer.Option(
        None, "--app-server-user", help="Application server username"
    ),
    app_server_pass: Optional[str] = typer.Option(
        None, "--app-server-pass", help="Application server password"
    ),
    app_server_key: Optional[str] = typer.Option(
        None, "--app-server-key", help="Application server SSH key file"
    ),
    
    # Fusion Server Settings
    fusion_server_host: Optional[str] = typer.Option(
        None, "--fusion-server-host", help="Fusion server IP/hostname"
    ),
    fusion_server_port: int = typer.Option(
        22, "--fusion-server-port", help="Fusion server SSH port"
    ),
    fusion_server_user: str = typer.Option(
        "fusion", "--fusion-server-user", help="Fusion server username"
    ),
    fusion_server_pass: Optional[str] = typer.Option(
        None, "--fusion-server-pass", help="Fusion server password"
    ),
    
    # Project Settings
    project_name: Optional[str] = typer.Option(
        None, "--project-name", help="Project name (case-sensitive)"
    ),
    app_file: str = typer.Option(
        "Application.zip", "--app-file", help="Application file name"
    ),
    app_include: str = typer.Option(
        "", "--app-include", help="Regex for DLLs/JARs to include"
    ),
    app_exclude: str = typer.Option(
        "", "--app-exclude", help="Regex for DLLs/JARs to exclude"
    ),
    tech_stack: str = typer.Option(
        "JAVA", "--tech-stack", help="Technology stack (JAVA or DOTNET)"
    ),
    
    # SSH Key Settings
    ssh_passphrase: Optional[str] = typer.Option(
        None, "--ssh-passphrase", help="SSH key passphrase (optional)"
    ),
    
    # Other Settings
    debug: bool = typer.Option(
        False, "--debug", help="Enable debug mode"
    ),
    interactive: bool = typer.Option(
        True, "--interactive/--no-interactive", help="Interactive mode"
    )
):
    """
    Setup SSH automation for Fusion deployment.
    
    This command will:
    1. Generate SSH keys on Application server
    2. Configure authorized_keys on Fusion server
    3. Create configuration files on both servers
    4. Set up project folders
    """
    
    print_banner()
    
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Interactive mode - prompt for missing values
    if interactive:
        console.print("\n[bold cyan]Interactive Setup Mode[/bold cyan]\n")
        console.print("Please provide the following information:\n")
        
        if not app_folder:
            app_folder = Prompt.ask(
                "[cyan]Application Deployment Folder Path[/cyan]",
                default="C:\\MyApp\\Deployment"
            )
        
        if not app_server_host:
            app_server_host = Prompt.ask(
                "[cyan]Application Server IP/Hostname[/cyan]"
            )
        
        if not app_server_user:
            app_server_user = Prompt.ask(
                "[cyan]Application Server Username[/cyan]",
                default="administrator"
            )
        
        if not app_server_pass and not app_server_key:
            app_server_pass = Prompt.ask(
                "[cyan]Application Server Password[/cyan]",
                password=True
            )
        
        if not fusion_server_host:
            fusion_server_host = Prompt.ask(
                "[cyan]Fusion Server IP/Hostname[/cyan]"
            )
        
        if not fusion_server_pass:
            fusion_server_pass = Prompt.ask(
                "[cyan]Fusion Server Password[/cyan]",
                password=True
            )
        
        if not project_name:
            project_name = Prompt.ask(
                "[cyan]Project Name[/cyan] (case-sensitive)"
            )
        
        console.print()
    
    # Validate required parameters
    if not all([app_folder, app_server_host, app_server_user, fusion_server_host, project_name]):
        console.print("[red]Error:[/red] Missing required parameters")
        console.print("Run with --help for more information or use interactive mode")
        raise typer.Exit(1)
    
    if not app_server_pass and not app_server_key:
        console.print("[red]Error:[/red] Either password or SSH key file must be provided for Application server")
        raise typer.Exit(1)
    
    # Create configuration
    config = Config(
        app_deployment_folder=app_folder,
        app_server_host=app_server_host,
        app_server_port=app_server_port,
        app_server_user=app_server_user,
        app_server_pass=app_server_pass,
        app_server_key_file=app_server_key,
        fusion_server_host=fusion_server_host,
        fusion_server_port=fusion_server_port,
        fusion_server_user=fusion_server_user,
        fusion_server_pass=fusion_server_pass,
        project_name=project_name,
        application_file=app_file,
        application_include=app_include,
        application_exclude=app_exclude,
        tech_stack=tech_stack,
        ssh_key_passphrase=ssh_passphrase,
        debug_mode=debug
    )
    
    # Display configuration summary
    console.print("\n[bold]Configuration Summary:[/bold]\n")
    console.print(f"  [cyan]Application Server:[/cyan] {config.app_server_host}:{config.app_server_port}")
    console.print(f"  [cyan]Deployment Folder:[/cyan] {config.app_deployment_folder}")
    console.print(f"  [cyan]Fusion Server:[/cyan] {config.fusion_server_host}:{config.fusion_server_port}")
    console.print(f"  [cyan]Project Name:[/cyan] {config.project_name}")
    console.print(f"  [cyan]Technology Stack:[/cyan] {config.tech_stack}")
    console.print()
    
    # Confirm before proceeding
    if interactive:
        if not Confirm.ask("[yellow]Proceed with setup?[/yellow]", default=True):
            console.print("[yellow]Setup cancelled[/yellow]")
            raise typer.Exit(0)
    
    # Run deployment automation
    try:
        automation = DeploymentAutomation(config)
        success = automation.run_full_setup()
        
        if success:
            console.print("\n[bold green]✓ Setup completed successfully![/bold green]\n")
            raise typer.Exit(0)
        else:
            console.print("\n[bold red]✗ Setup failed![/bold red]\n")
            raise typer.Exit(1)
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Setup interrupted by user[/yellow]")
        raise typer.Exit(130)
    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {str(e)}")
        if debug:
            log.exception("Setup failed with exception")
        raise typer.Exit(1)


@app.command()
def version():
    """Show version information."""
    console.print("[bold cyan]WinSCP Extension v1.0.0[/bold cyan]")
    console.print("SSH Automation Tool for Fusion Deployment")


@app.command()
def info():
    """Show system and configuration information."""
    console.print(Panel.fit(
        "[bold cyan]WinSCP Extension - System Information[/bold cyan]\n\n"
        "[yellow]Purpose:[/yellow] Automate SSH key generation and deployment configuration\n"
        "[yellow]Supports:[/yellow] Windows and Linux application servers\n"
        "[yellow]Features:[/yellow]\n"
        "  • Automated SSH key generation\n"
        "  • Secure key permission management\n"
        "  • Configuration file generation\n"
        "  • Project folder setup\n"
        "  • Cross-platform support",
        border_style="cyan"
    ))


def main():
    """Main entry point."""
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Fatal error:[/red] {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()

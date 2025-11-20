"""
UI Components for VAPT CLI Tool

This module provides reusable Rich-based UI components for better user experience
and visual clarity during vulnerability assessment and penetration testing.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.layout import Layout
from rich.live import Live
from rich.tree import Tree
from rich.syntax import Syntax
from rich import box
from typing import List, Dict, Any, Optional
import time

console = Console()

# Color scheme for consistency
COLORS = {
    "critical": "bold red",
    "high": "bold orange3",
    "medium": "bold yellow",
    "low": "bold cyan",
    "info": "bold blue",
    "success": "bold green",
    "warning": "bold yellow",
    "error": "bold red",
    "neutral": "white"
}

SEVERITY_COLORS = {
    "Critical": "red",
    "High": "orange3",
    "Medium": "yellow",
    "Low": "cyan",
    "Info": "blue"
}


def print_banner():
    """Display the VAPT tool banner"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██╗   ██╗ █████╗ ██████╗ ████████╗     █████╗ ██╗        ║
║   ██║   ██║██╔══██╗██╔══██╗╚══██╔══╝    ██╔══██╗██║        ║
║   ██║   ██║███████║██████╔╝   ██║       ███████║██║        ║
║   ╚██╗ ██╔╝██╔══██║██╔═══╝    ██║       ██╔══██║██║        ║
║    ╚████╔╝ ██║  ██║██║        ██║       ██║  ██║██║        ║
║     ╚═══╝  ╚═╝  ╚═╝╚═╝        ╚═╝       ╚═╝  ╚═╝╚═╝        ║
║                                                              ║
║        Vulnerability Assessment & Penetration Testing        ║
║                    AI-Powered Active Scanner                 ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""
    console.print(banner, style="bold cyan")


def print_section_header(title: str, style: str = "bold cyan"):
    """Print a section header with consistent styling"""
    console.rule(f"[{style}]✦ {title} ✦[/{style}]")


def create_target_info_panel(method: str, url: str, categories: List[str], params: Optional[List[str]] = None):
    """Create a panel showing target information"""
    content = f"""[bold]HTTP Method:[/bold] [cyan]{method}[/cyan]
[bold]Target URL:[/bold] [cyan]{url}[/cyan]
[bold]Test Categories:[/bold] [yellow]{', '.join(categories)}[/yellow]"""
    
    if params:
        content += f"\n[bold]Focus Parameters:[/bold] [magenta]{', '.join(params)}[/magenta]"
    else:
        content += f"\n[bold]Focus Parameters:[/bold] [dim]All available parameters[/dim]"
    
    panel = Panel(
        content,
        title="[bold green]🎯 Target Information[/bold green]",
        border_style="green",
        box=box.ROUNDED
    )
    console.print(panel)


def create_warning_panel():
    """Create the warning panel for active scanning"""
    warning_text = """[bold red]⚠️  ACTIVE SCANNING MODE ENABLED  ⚠️[/bold red]

This tool will send [underline]potentially malicious payloads[/underline] to the target system.

[yellow]Important Requirements:[/yellow]
  • Ensure you have [bold]explicit, written permission[/bold] to test this system
  • Understand this may trigger security alerts or WAF responses
  • May cause unintended side effects or service disruption
  • All testing activities will be logged

[bold cyan]Legal Notice:[/bold cyan]
Unauthorized testing of systems you do not own or have permission to test
is illegal and may result in criminal prosecution.
"""
    
    panel = Panel(
        warning_text,
        title="[bold yellow]⚡ ACTION REQUIRED ⚡[/bold yellow]",
        border_style="red",
        box=box.DOUBLE
    )
    console.print(panel)


def create_progress_tracker(total_categories: int):
    """Create a progress tracker for category testing"""
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    )
    return progress


def create_test_result_table(category: str, results: List[Dict[str, Any]]):
    """Create a formatted table for test results"""
    table = Table(
        title=f"[bold cyan]Test Results: {category}[/bold cyan]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta"
    )
    
    table.add_column("#", style="dim", width=4)
    table.add_column("Payload", style="cyan", width=40, overflow="fold")
    table.add_column("Type", style="yellow", width=20)
    table.add_column("Confidence", justify="center", width=12)
    table.add_column("Status", justify="center", width=12)
    
    for idx, result in enumerate(results, 1):
        payload = str(result.get('payload', 'N/A'))[:40]
        test_type = str(result.get('type', result.get('test_type', 'unknown')))[:20]
        confidence = result.get('confidence', 0)
        
        # Color code confidence
        if confidence >= 80:
            conf_str = f"[bold green]{confidence}%[/bold green]"
            status = "[bold green]✓ HIGH[/bold green]"
        elif confidence >= 60:
            conf_str = f"[yellow]{confidence}%[/yellow]"
            status = "[yellow]◆ MED[/yellow]"
        else:
            conf_str = f"[dim]{confidence}%[/dim]"
            status = "[dim]○ LOW[/dim]"
        
        table.add_row(str(idx), payload, test_type, conf_str, status)
    
    console.print(table)


def create_iteration_panel(iteration: int, max_iterations: int, category: str):
    """Create a panel for iteration progress"""
    progress_bar = "█" * iteration + "░" * (max_iterations - iteration)
    
    content = f"""[bold cyan]Category:[/bold cyan] {category}
[bold yellow]Iteration:[/bold yellow] {iteration}/{max_iterations}
[bold magenta]Progress:[/bold magenta] [{progress_bar}] {int(iteration/max_iterations*100)}%
"""
    
    panel = Panel(
        content,
        title="[bold blue]🔄 Adaptive Testing Progress[/bold blue]",
        border_style="blue",
        box=box.ROUNDED
    )
    console.print(panel)


def print_payload_test_info(payload_num: int, total: int, payload: str, test_type: str, modifications: Optional[Dict] = None):
    """Print formatted payload testing information"""
    console.print(f"\n[bold white]  ┌─ Payload {payload_num}/{total}[/bold white]")
    console.print(f"  │ [cyan]Test:[/cyan] {payload[:80]}{'...' if len(payload) > 80 else ''}")
    console.print(f"  │ [yellow]Type:[/yellow] {test_type}")
    
    if modifications:
        console.print(f"  │ [magenta]Modifications Applied:[/magenta]")
        for key, value in modifications.items():
            if value:
                console.print(f"  │   • {key}: {value}")
    
    console.print(f"  └─ [dim]Testing...[/dim]")


def print_exploitation_banner():
    """Print banner when exploitation mode is activated"""
    banner = Panel(
        "[bold red]⚡ EXPLOITATION MODE ACTIVATED ⚡[/bold red]\n\n"
        "[yellow]Confidence threshold exceeded (>70)[/yellow]\n"
        "[cyan]Switching to aggressive data extraction...[/cyan]",
        border_style="red",
        box=box.DOUBLE
    )
    console.print(banner)


def create_extracted_data_table(extracted_data: List[Dict[str, Any]]):
    """Create a table showing extracted data"""
    table = Table(
        title="[bold green]📊 Successfully Extracted Data[/bold green]",
        box=box.DOUBLE,
        show_header=True,
        header_style="bold green"
    )
    
    table.add_column("#", style="dim", width=4)
    table.add_column("Data Type", style="yellow", width=20)
    table.add_column("Extracted Value", style="green", width=50, overflow="fold")
    table.add_column("Confidence", justify="center", width=12)
    
    for idx, data in enumerate(extracted_data, 1):
        data_type = data.get('data_type', 'unknown')
        value = str(data.get('data', 'N/A'))[:50]
        confidence = data.get('confidence', 0)
        
        conf_str = f"[bold green]{confidence}%[/bold green]" if confidence >= 70 else f"[yellow]{confidence}%[/yellow]"
        
        table.add_row(str(idx), data_type, value, conf_str)
    
    console.print(table)


def create_vulnerability_summary(findings: List[Dict[str, Any]]):
    """Create a summary table of all findings"""
    if not findings:
        console.print(Panel(
            "[yellow]No vulnerabilities detected during testing.[/yellow]",
            title="[bold green]Summary[/bold green]",
            border_style="green"
        ))
        return
    
    table = Table(
        title="[bold red]⚠️  Vulnerability Summary  ⚠️[/bold red]",
        box=box.DOUBLE,
        show_header=True,
        header_style="bold magenta"
    )
    
    table.add_column("#", style="dim", width=4)
    table.add_column("Category", style="cyan", width=30)
    table.add_column("Severity", justify="center", width=12)
    table.add_column("Confirmations", justify="center", width=14)
    table.add_column("Exploitation", justify="center", width=14)
    table.add_column("Data Extracted", justify="center", width=16)
    
    for idx, finding in enumerate(findings, 1):
        category = finding.get('category', 'Unknown')
        severity = finding.get('severity', 'Unknown')
        confirmations = len(finding.get('confirmation_payloads', []))
        exploited = finding.get('exploitation_successful', False)
        data_count = len(finding.get('extracted_data', []))
        
        # Color code severity
        severity_color = SEVERITY_COLORS.get(severity, "white")
        severity_str = f"[{severity_color}]{severity}[/{severity_color}]"
        
        # Exploitation status
        exploit_str = "[bold green]✓ YES[/bold green]" if exploited else "[dim]○ No[/dim]"
        
        # Data extracted
        data_str = f"[bold green]{data_count} items[/bold green]" if data_count > 0 else "[dim]-[/dim]"
        
        table.add_row(
            str(idx),
            category,
            severity_str,
            str(confirmations),
            exploit_str,
            data_str
        )
    
    console.print("\n")
    console.print(table)
    console.print("\n")


def create_statistics_panel(stats: Dict[str, Any]):
    """Create a panel showing testing statistics"""
    content = f"""[bold cyan]Categories Tested:[/bold cyan] {stats.get('categories_tested', 0)}
[bold yellow]Vulnerabilities Found:[/bold yellow] {stats.get('vulnerabilities_found', 0)}
[bold green]Successful Exploitations:[/bold green] {stats.get('successful_exploits', 0)}
[bold magenta]Data Points Extracted:[/bold magenta] {stats.get('data_extracted', 0)}
[bold blue]Total Payloads Tested:[/bold blue] {stats.get('total_payloads', 0)}
[bold white]Duration:[/bold white] {stats.get('duration', 'N/A')}
"""
    
    panel = Panel(
        content,
        title="[bold green]📈 Testing Statistics[/bold green]",
        border_style="green",
        box=box.ROUNDED
    )
    console.print(panel)


def print_data_extraction_success(data_type: str, data_preview: str):
    """Print formatted data extraction success message"""
    panel = Panel(
        f"[bold yellow]Data Type:[/bold yellow] {data_type}\n"
        f"[bold cyan]Preview:[/bold cyan] {data_preview[:150]}{'...' if len(data_preview) > 150 else ''}",
        title="[bold green]✓ DATA EXTRACTION SUCCESSFUL[/bold green]",
        border_style="green",
        box=box.DOUBLE
    )
    console.print(panel)


def print_analysis_summary(verdict: str, confidence: int, key_findings: List[str]):
    """Print analysis summary in a formatted way"""
    # Color code verdict
    if verdict in ["VULNERABLE", "POTENTIALLY_VULNERABLE"]:
        verdict_style = "bold red"
        icon = "⚠️"
    else:
        verdict_style = "bold green"
        icon = "✓"
    
    # Color code confidence
    if confidence >= 80:
        conf_style = "bold green"
    elif confidence >= 60:
        conf_style = "yellow"
    else:
        conf_style = "dim"
    
    content = f"[{verdict_style}]{icon} Verdict:[/{verdict_style}] [{verdict_style}]{verdict}[/{verdict_style}]\n"
    content += f"[bold]Confidence:[/bold] [{conf_style}]{confidence}%[/{conf_style}]\n"
    
    if key_findings:
        content += "\n[bold cyan]Key Findings:[/bold cyan]\n"
        for finding in key_findings[:3]:
            content += f"  • {finding[:100]}\n"
    
    console.print(Panel(content, border_style="blue", box=box.ROUNDED))


def create_request_modifications_tree(modifications: Dict[str, Any]):
    """Create a tree view of request modifications"""
    tree = Tree("[bold magenta]🔧 Request Modifications[/bold magenta]")
    
    if modifications.get('headers_to_remove'):
        headers_branch = tree.add("[yellow]Headers Removed[/yellow]")
        for header in modifications['headers_to_remove']:
            headers_branch.add(f"[dim]- {header}[/dim]")
    
    if modifications.get('headers_to_add'):
        headers_branch = tree.add("[green]Headers Added[/green]")
        for key, value in modifications['headers_to_add'].items():
            headers_branch.add(f"[dim]{key}: {value}[/dim]")
    
    if modifications.get('cookies_to_remove'):
        cookies_branch = tree.add("[yellow]Cookies Removed[/yellow]")
        for cookie in modifications['cookies_to_remove']:
            cookies_branch.add(f"[dim]- {cookie}[/dim]")
    
    if modifications.get('method'):
        tree.add(f"[cyan]Method Changed:[/cyan] [bold]{modifications['method']}[/bold]")
    
    if modifications.get('query_params_to_add'):
        params_branch = tree.add("[green]Query Parameters Added[/green]")
        for key, value in modifications['query_params_to_add'].items():
            params_branch.add(f"[dim]{key}={value}[/dim]")
    
    console.print(tree)


def print_stage_transition(stage: int, stage_name: str, category: str):
    """Print a formatted stage transition"""
    stage_text = f"""
[bold cyan]Stage {stage}/3:[/bold cyan] {stage_name}
[bold yellow]Category:[/bold yellow] {category}
[bold magenta]Status:[/bold magenta] In Progress...
"""
    
    console.print(Panel(
        stage_text,
        border_style="cyan",
        box=box.ROUNDED
    ))


def print_final_report_header():
    """Print header for final report generation"""
    console.print("\n")
    console.rule("[bold green]✦ Generating Final VAPT Report ✦[/bold green]")
    console.print("\n")


def print_completion_message(report_path: str):
    """Print completion message with report location"""
    completion_text = f"""
[bold green]✓ Vulnerability Assessment Complete[/bold green]

[cyan]Report Generated:[/cyan] [bold]{report_path}[/bold]
[yellow]Status:[/yellow] All testing completed successfully

[dim]Thank you for using VAPT AI Agent![/dim]
"""
    
    panel = Panel(
        completion_text,
        title="[bold green]🎉 Assessment Complete[/bold green]",
        border_style="green",
        box=box.DOUBLE
    )
    console.print(panel)


def print_error(error_message: str, context: str = ""):
    """Print formatted error message"""
    content = f"[bold red]Error:[/bold red] {error_message}"
    if context:
        content += f"\n[dim]Context: {context}[/dim]"
    
    panel = Panel(
        content,
        title="[bold red]❌ Error[/bold red]",
        border_style="red",
        box=box.ROUNDED
    )
    console.print(panel)


def print_info(message: str, title: str = "Info"):
    """Print formatted info message"""
    panel = Panel(
        f"[cyan]{message}[/cyan]",
        title=f"[bold blue]ℹ️  {title}[/bold blue]",
        border_style="blue",
        box=box.ROUNDED
    )
    console.print(panel)

# vapt_cli/main.py
import typer
import inquirer
import sys
from rich.console import Console
from rich.prompt import Confirm
from rich.panel import Panel

from .config import setup_logging, OWASP_CATEGORIES
from .analyzer import perform_full_workflow, parse_raw_http_request, find_request_parameters
from .reporter import generate_report
from .ui_components import (
    print_banner, 
    create_warning_panel, 
    create_target_info_panel,
    print_info
)

app = typer.Typer()
console = Console()

@app.command()
def analyze(
    debug: bool = typer.Option(False, "--debug", "-d", help="Enable debug logging."),
    proxy: str = typer.Option(None, "--proxy", help="HTTP/HTTPS proxy to send traffic through (e.g., http://127.0.0.1:8080).")
):
    """
    Analyzes an HTTP request using a multi-stage AI agent.
    """
    setup_logging(debug)
    
    # Display improved banner
    print_banner()
    
    if proxy:
        print_info(f"All traffic will be routed through: {proxy}", "Proxy Configuration")

    console.print("\n[bold]Step 0: Provide Raw HTTP Request[/bold]")
    console.print("Paste the request below and press Ctrl+D (or Ctrl+Z+Enter on Windows) to continue.")
    raw_request_input = sys.stdin.read()
    if not raw_request_input.strip():
        console.print("[yellow]No request provided. Exiting.[/yellow]"); raise typer.Exit()

    try:
        parsed_req = parse_raw_http_request(raw_request_input)
        available_params = find_request_parameters(parsed_req)
    except ValueError as e:
        console.print(f"[bold red]Error parsing request: {e}[/bold red]"); raise typer.Exit()

    selected_params = None
    if available_params:
        param_questions = [inquirer.Checkbox('params', message="Select parameters to focus on", choices=available_params, default=[])]
        param_answers = inquirer.prompt(param_questions)
        if param_answers: selected_params = param_answers['params']

    owasp_questions = [inquirer.Checkbox('categories', message="Which OWASP categories do you want to test for?", choices=OWASP_CATEGORIES, default=[])]
    owasp_answers = inquirer.prompt(owasp_questions)
    if not owasp_answers or not owasp_answers['categories']:
        console.print("[yellow]No categories selected. Exiting.[/yellow]"); raise typer.Exit()
    selected_categories = owasp_answers['categories']
    
    # Display target information in a nice panel
    console.print("\n")
    create_target_info_panel(
        method=parsed_req.method,
        url=parsed_req.url,
        categories=selected_categories,
        params=selected_params
    )
    
    # Display warning panel
    console.print("\n")
    create_warning_panel()
    
    if not Confirm.ask("\n[bold cyan]Do you acknowledge the risks and have permission to proceed?[/bold cyan]", default=False):
        console.print("[red]Analysis aborted by user.[/red]"); raise typer.Exit()

    console.print("\n")
    findings = perform_full_workflow(raw_request_input, selected_categories, selected_params, proxy) # Pass proxy here
        
if __name__ == "__main__":
    app()
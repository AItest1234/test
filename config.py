# vapt_cli/config.py
from pydantic_settings import BaseSettings
from rich.console import Console
import logging
from rich.logging import RichHandler

def setup_logging(debug_mode: bool = False):
    """Configures logging for the application."""
    log_level = "DEBUG" if debug_mode else "INFO"
    
    # Configure the root logger
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_path=debug_mode)]
    )
    
    # Silence overly verbose loggers from libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)


class Settings(BaseSettings):
    CEREBRAS_API_KEY: str
    CEREBRAS_API_BASE: str = "https://api.cerebras.ai/v1"
    CEREBRAS_MODEL: str = "zai-glm-4.6"

    class Config:
        env_file = ".env"

try:
    settings = Settings()
except Exception as e:
    console = Console()
    console.print(f"[bold red]Error: Configuration not loaded. {e}[/bold red]")
    console.print("[yellow]Please ensure a .env file exists and contains the CEREBRAS_API_KEY.[/yellow]")
    exit(1)

# A list of OWASP API Security Top 10 categories for user selection
OWASP_CATEGORIES = [
    "A01:2021 - Broken Access Control",
    "A02:2021 - Cryptographic Failures",
    "A03:2021 - Injection",
    "A04:2021 - Insecure Design",
    "A05:2021 - Security Misconfiguration",
    "A06:2021 - Vulnerable and Outdated Components",
    "A07:2021 - Identification and Authentication Failures",
    "A08:2021 - Software and Data Integrity Failures",
    "A09:2021 - Security Logging and Monitoring Failures",
    "A10:2021 - Server-Side Request Forgery (SSRF)"
]
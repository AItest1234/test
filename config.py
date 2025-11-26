"""Configuration management for WinSCP Extension."""

from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings


class Config(BaseSettings):
    """Application configuration."""
    
    # Application Server Settings
    app_server_host: str = Field(default="", description="Application server hostname/IP")
    app_server_port: int = Field(default=22, description="Application server SSH port")
    app_server_user: str = Field(default="", description="Application server username")
    app_server_pass: Optional[str] = Field(default=None, description="Application server password")
    app_server_key_file: Optional[str] = Field(default=None, description="Application server SSH key file")
    
    # Fusion Server Settings
    fusion_server_host: str = Field(default="", description="Fusion server hostname/IP")
    fusion_server_port: int = Field(default=22, description="Fusion server SSH port")
    fusion_server_user: str = Field(default="fusion", description="Fusion server username")
    fusion_server_pass: Optional[str] = Field(default=None, description="Fusion server password")
    
    # Deployment Settings
    app_deployment_folder: str = Field(default="", description="Application deployment folder path")
    project_name: str = Field(default="", description="Project name (case-sensitive)")
    application_file: str = Field(default="Application.zip", description="Application file name")
    application_include: str = Field(default="", description="Regex for DLLs/JARs to include")
    application_exclude: str = Field(default="", description="Regex for DLLs/JARs to exclude")
    instrumented_folder: str = Field(default="Instrumented", description="Instrumented folder name")
    
    # Technology Stack
    tech_stack: str = Field(default="JAVA", description="Technology stack (JAVA or DOTNET)")
    
    # SSH Key Settings
    ssh_key_passphrase: Optional[str] = Field(default=None, description="SSH key passphrase")
    ssh_key_bits: int = Field(default=4096, description="SSH key size in bits")
    
    # Paths
    fusion_insight_path: str = Field(
        default="C:\\FusionLiteInsight\\FusionLiteProjectService",
        description="FusionLite Insight service path"
    )
    fusion_projects_path: str = Field(
        default="C:\\FusionLiteProjects",
        description="Fusion projects base path"
    )
    
    # Logging
    log_level: str = Field(default="INFO", description="Logging level")
    debug_mode: bool = Field(default=False, description="Enable debug mode")
    
    class Config:
        env_prefix = "WINSCP_EXT_"
        case_sensitive = False


# Default configuration templates
FUSIONLITE_PROPERTIES_TEMPLATE = """# FusionLite Project Configuration
FusionLiteProject={project_name}
FusionLiteServerHost={fusion_host}
FusionLiteServerPort={fusion_port}
FusionLiteServerUser={fusion_user}
FusionLiteServerKeyFile={key_file_path}
FusionLiteServerKeyPass={key_passphrase}

ApplicationFile={app_file}
ApplicationInclude={app_include}
ApplicationExclude={app_exclude}
InstrumentedFile={app_file}
InstrumentedFolder={instrumented_folder}
"""

FUSIONLITE_POWERSHELL_TEMPLATE = """# FusionLite Project PowerShell Script
# This script will be customized based on templates from Fusion server
"""

PROJECT_PROPERTIES_TEMPLATE = """# Project Configuration
Name={project_name}
InstrumentorAddress={app_server_host}
"""

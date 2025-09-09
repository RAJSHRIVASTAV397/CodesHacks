"""Utility functions for reporting and output generation."""

import os
import json
from datetime import datetime
from typing import Any, Dict, List, Optional
import logging

def create_output_dirs(base_dir: str, timestamp: str) -> Dict[str, str]:
    """Create output directory structure.
    
    Args:
        base_dir: Base directory for output
        timestamp: Timestamp for session
        
    Returns:
        Dictionary of created directory paths
        
    Raises:
        OSError: If directory creation fails
    """
    dirs = {
        'session': os.path.join(base_dir, f'scan_{timestamp}'),
        'results': os.path.join(base_dir, f'scan_{timestamp}', 'results'),
        'evidence': os.path.join(base_dir, f'scan_{timestamp}', 'evidence'),
        'logs': os.path.join(base_dir, f'scan_{timestamp}', 'logs'),
        'reports': os.path.join(base_dir, f'scan_{timestamp}', 'reports')
    }
    
    # Create all directories
    for dir_path in dirs.values():
        os.makedirs(dir_path, exist_ok=True)
    
    return dirs

def generate_text_report(findings: List[str], metadata: Dict[str, Any], output_file: str) -> None:
    """Generate text format report.
    
    Args:
        findings: List of scan findings
        metadata: Scan metadata
        output_file: Path to output file
        
    Raises:
        OSError: If file creation fails
    """
    with open(output_file, 'w') as f:
        f.write("CodesHacks Scan Report\n")
        f.write("=" * 50 + "\n\n")
        
        # Write metadata
        f.write("Scan Information\n")
        f.write("-" * 20 + "\n")
        for key, value in metadata.items():
            f.write(f"{key}: {value}\n")
        f.write("\n")
        
        # Write findings
        f.write("Findings\n")
        f.write("-" * 20 + "\n")
        for finding in findings:
            f.write(f"{finding}\n")

def generate_json_report(findings: List[str], metadata: Dict[str, Any], output_file: str) -> None:
    """Generate JSON format report.
    
    Args:
        findings: List of scan findings
        metadata: Scan metadata
        output_file: Path to output file
        
    Raises:
        OSError: If file creation fails
    """
    report = {
        'metadata': metadata,
        'findings': findings,
        'generated': datetime.now().isoformat()
    }
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)

def generate_html_report(findings: List[str], metadata: Dict[str, Any], output_file: str) -> None:
    """Generate HTML format report.
    
    Args:
        findings: List of scan findings
        metadata: Scan metadata
        output_file: Path to output file
        
    Raises:
        OSError: If file creation fails
    """
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>CodesHacks Scan Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .header { background: #f5f5f5; padding: 20px; margin-bottom: 20px; }
            .section { margin-bottom: 20px; }
            .finding { border-left: 4px solid #ccc; padding-left: 10px; margin: 10px 0; }
            .critical { border-color: #dc3545; }
            .high { border-color: #fd7e14; }
            .medium { border-color: #ffc107; }
            .low { border-color: #28a745; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>CodesHacks Scan Report</h1>
            <p>Generated: {generated}</p>
        </div>
        
        <div class="section">
            <h2>Scan Information</h2>
            {metadata}
        </div>
        
        <div class="section">
            <h2>Findings</h2>
            {findings}
        </div>
    </body>
    </html>
    """
    
    # Format metadata
    metadata_html = "<table>"
    for key, value in metadata.items():
        metadata_html += f"<tr><td><strong>{key}:</strong></td><td>{value}</td></tr>"
    metadata_html += "</table>"
    
    # Format findings
    findings_html = "<div class='findings'>"
    for finding in findings:
        severity = "low"
        if "CRITICAL" in finding:
            severity = "critical"
        elif "HIGH" in finding:
            severity = "high"
        elif "MEDIUM" in finding:
            severity = "medium"
        findings_html += f"<div class='finding {severity}'>{finding}</div>"
    findings_html += "</div>"
    
    # Generate final HTML
    html = html.format(
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        metadata=metadata_html,
        findings=findings_html
    )
    
    with open(output_file, 'w') as f:
        f.write(html)

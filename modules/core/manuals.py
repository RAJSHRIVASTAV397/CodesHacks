"""Manual pages and documentation for CodesHacks tools and scans."""

from typing import Dict, List, Optional
import textwrap
from modules.utils.logging import colored_text

# Main categories of tools
CATEGORIES = {
    'recon': 'Reconnaissance Tools',
    'vuln': 'Vulnerability Scanning',
    'web': 'Web Application Testing',
    'network': 'Network Tools',
    'external': 'External Tools Integration',
    'mobile': 'Mobile Application Testing',
    'api': 'API Security Testing',
    'crypto': 'Cryptographic Analysis',
    'malware': 'Malware Analysis',
    'forensics': 'Digital Forensics'
}

# Define available tools and their documentation
TOOLS = {
    'recon': {
        'subdomain': {
            'name': 'Subdomain Enumeration',
            'description': 'Enumerate subdomains using various techniques',
            'options': [
                '-w, --wordlist FILE    Custom wordlist for bruteforce',
                '-r, --recursive        Enable recursive enumeration',
                '-t, --threads NUM      Number of concurrent threads'
            ],
            'example': '''
                # Basic subdomain enumeration
                codeshacks.py recon subdomain -d example.com

                # With custom wordlist and threads
                codeshacks.py recon subdomain -d example.com -w wordlist.txt -t 20
            '''
        }
    },
    'web': {
        'xss': {
            'name': 'Cross-Site Scripting Scanner',
            'description': 'Detect XSS vulnerabilities in web applications',
            'options': [
                '-u, --url URL         Target URL to scan',
                '-p, --payload FILE    Custom XSS payload file',
                '--crawl              Enable crawling'
            ],
            'example': '''
                # Basic XSS scan
                codeshacks.py web xss -u http://example.com

                # With custom payloads
                codeshacks.py web xss -u http://example.com -p payloads.txt
            '''
        }
    }
}

def display_man_page(topic: Optional[str] = None, tool: Optional[str] = None) -> None:
    """Display manual page for a specific topic or tool.
    
    Args:
        topic: Optional category/topic name
        tool: Optional specific tool name
    """
    if not topic and not tool:
        print_main_manual()
        return

    if topic and not tool:
        if topic in CATEGORIES:
            print_category_manual(topic)
        else:
            print(colored_text(f"Error: Manual page for '{topic}' not found.", 'red'))
            print("Use 'codeshacks.py man' to see available topics.")
        return

    if topic and tool:
        if topic in TOOLS and tool in TOOLS[topic]:
            print_tool_manual(topic, tool)
        else:
            print(colored_text(f"Error: Manual page for '{topic} {tool}' not found.", 'red'))
            print("Use 'codeshacks.py man TOPIC' to see available tools.")

def print_main_manual() -> None:
    """Print the main manual page."""
    manual = f"""
    {colored_text('NAME', 'cyan')}
        codeshacks - Advanced Security Testing Framework

    {colored_text('SYNOPSIS', 'cyan')}
        codeshacks.py [OPTIONS] COMMAND [ARGS]
        codeshacks.py man [TOPIC] [TOOL]

    {colored_text('DESCRIPTION', 'cyan')}
        CodesHacks is a comprehensive security testing framework that provides
        various tools for security assessment, penetration testing, and analysis.

    {colored_text('MANUAL SECTIONS', 'cyan')}"""
    
    print(textwrap.dedent(manual))
    
    for cat_id, cat_name in CATEGORIES.items():
        print(f"    {colored_text(cat_id.upper(), 'yellow'):<12} {cat_name}")
    
    usage = f"""
    {colored_text('USAGE', 'cyan')}
        View main manual:
            codeshacks.py man

        View category manual:
            codeshacks.py man CATEGORY
            Example: codeshacks.py man recon

        View specific tool manual:
            codeshacks.py man CATEGORY TOOL
            Example: codeshacks.py man web xss

    {colored_text('OPTIONS', 'cyan')}
        -h, --help            Show brief help message
        -v, --verbose         Enable verbose output
        --debug              Enable debug logging
        -o, --output FILE    Output file for results
        --format FORMAT      Output format (text, json, html)

    {colored_text('FILES', 'cyan')}
        ~/.codeshacks/config      User configuration file
        ~/.codeshacks/logs        Log files directory
        ~/.codeshacks/reports     Generated reports directory

    {colored_text('EXAMPLES', 'cyan')}
        # View manual for reconnaissance tools
        codeshacks.py man recon

        # View manual for XSS scanner
        codeshacks.py man web xss

        # View manual for all API testing tools
        codeshacks.py man api
    """
    
    print(textwrap.dedent(usage))

def print_category_manual(category: str) -> None:
    """Print manual page for a specific category.
    
    Args:
        category: Category name
    """
    if category not in CATEGORIES:
        print(colored_text(f"Error: Category '{category}' not found.", 'red'))
        return
    
    print(f"\n{colored_text(CATEGORIES[category], 'cyan')}")
    print("=" * len(CATEGORIES[category]))
    
    if category in TOOLS:
        print("\nAvailable Tools:")
        for tool_id, tool_info in TOOLS[category].items():
            print(f"\n{colored_text(tool_id, 'yellow')}: {tool_info['name']}")
            print(f"    {tool_info['description']}")
    
    print("\nUse 'codeshacks.py man {category} TOOL' for specific tool documentation")

def print_tool_manual(category: str, tool: str) -> None:
    """Print manual page for a specific tool.
    
    Args:
        category: Tool category
        tool: Tool name
    """
    if category not in TOOLS or tool not in TOOLS[category]:
        print(colored_text(f"Error: Tool '{tool}' not found in category '{category}'.", 'red'))
        return
    
    tool_info = TOOLS[category][tool]
    
    manual = f"""
    {colored_text('NAME', 'cyan')}
        {tool} - {tool_info['name']}

    {colored_text('DESCRIPTION', 'cyan')}
        {tool_info['description']}

    {colored_text('SYNOPSIS', 'cyan')}
        codeshacks.py -t {tool} [options]

    {colored_text('OPTIONS', 'cyan')}"""
    
    print(textwrap.dedent(manual))
    
    for option in tool_info['options']:
        print(f"        {option}")
    
    examples = f"""
    {colored_text('EXAMPLES', 'cyan')}
    {textwrap.dedent(tool_info['example']).strip()}
    """
    
    print(textwrap.dedent(examples))

def get_man_completions(args: List[str]) -> List[str]:
    """Get command completion suggestions.
    
    Args:
        args: List of current command arguments
        
    Returns:
        List of possible completions
    """
    if len(args) == 0:
        return list(CATEGORIES.keys())
    
    if len(args) == 1 and args[0] in CATEGORIES:
        if args[0] in TOOLS:
            return list(TOOLS[args[0]].keys())
        return []
    
    return []

"""Command handler for manual pages."""

from typing import List, Optional
from modules.core.manuals import display_man_page, get_man_completions

def handle_man_command(args: List[str]) -> None:
    """Handle the man command and its arguments.
    
    Args:
        args: List of command arguments
    """
    topic = args[0] if len(args) > 0 else None
    tool = args[1] if len(args) > 1 else None
    
    display_man_page(topic, tool)

def complete_man_command(current_args: List[str]) -> List[str]:
    """Provide command completion suggestions for man command.
    
    Args:
        current_args: Current command arguments
        
    Returns:
        List of possible completions
    """
    return get_man_completions(current_args)

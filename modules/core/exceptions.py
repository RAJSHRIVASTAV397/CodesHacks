"""Core exceptions for CodesHacks."""

class CodesHacksError(Exception):
    """Base exception class for CodesHacks errors."""
    pass

class ConfigError(CodesHacksError):
    """Configuration related errors."""
    pass

class ScanError(CodesHacksError):
    """Scanning related errors."""
    pass

class ToolError(CodesHacksError):
    """External tool related errors."""
    pass

class ValidationError(CodesHacksError):
    """Input validation errors."""
    pass

class ConnectionError(CodesHacksError):
    """Network connection errors."""
    pass

class ApiError(CodesHacksError):
    """API related errors."""
    pass

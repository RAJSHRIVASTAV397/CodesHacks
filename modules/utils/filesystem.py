"""Utility functions for working with file system."""

import os
import shutil
import hashlib
from typing import List, Dict, Optional, Union
from pathlib import Path
import json
import yaml

def ensure_dir(path: Union[str, Path]) -> Path:
    """Ensure a directory exists, creating it if necessary.
    
    Args:
        path: Directory path
        
    Returns:
        Path object for directory
        
    Raises:
        OSError: If directory creation fails
    """
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path

def calculate_file_hash(file_path: Union[str, Path], 
                       hash_type: str = 'sha256',
                       chunk_size: int = 8192) -> str:
    """Calculate hash of a file.
    
    Args:
        file_path: Path to file
        hash_type: Hash algorithm to use
        chunk_size: Size of chunks to read
        
    Returns:
        Hex digest of file hash
        
    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If hash type is invalid
    """
    hash_funcs = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512
    }
    
    if hash_type not in hash_funcs:
        raise ValueError(f"Invalid hash type: {hash_type}")
    
    hasher = hash_funcs[hash_type]()
    
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(chunk_size), b''):
            hasher.update(chunk)
    
    return hasher.hexdigest()

def load_json_file(file_path: Union[str, Path]) -> Dict:
    """Load and parse a JSON file.
    
    Args:
        file_path: Path to JSON file
        
    Returns:
        Parsed JSON data
        
    Raises:
        FileNotFoundError: If file doesn't exist
        json.JSONDecodeError: If JSON is invalid
    """
    with open(file_path, 'r') as f:
        return json.load(f)

def save_json_file(data: Dict, 
                  file_path: Union[str, Path], 
                  pretty: bool = True) -> None:
    """Save data to a JSON file.
    
    Args:
        data: Data to save
        file_path: Output file path
        pretty: Use pretty printing
        
    Raises:
        OSError: If file creation fails
    """
    with open(file_path, 'w') as f:
        if pretty:
            json.dump(data, f, indent=2)
        else:
            json.dump(data, f)

def load_yaml_file(file_path: Union[str, Path]) -> Dict:
    """Load and parse a YAML file.
    
    Args:
        file_path: Path to YAML file
        
    Returns:
        Parsed YAML data
        
    Raises:
        FileNotFoundError: If file doesn't exist
        yaml.YAMLError: If YAML is invalid
    """
    with open(file_path, 'r') as f:
        return yaml.safe_load(f)

def save_yaml_file(data: Dict, file_path: Union[str, Path]) -> None:
    """Save data to a YAML file.
    
    Args:
        data: Data to save
        file_path: Output file path
        
    Raises:
        OSError: If file creation fails
    """
    with open(file_path, 'w') as f:
        yaml.safe_dump(data, f)

def backup_file(file_path: Union[str, Path], 
                backup_dir: Optional[Union[str, Path]] = None) -> Path:
    """Create a backup copy of a file.
    
    Args:
        file_path: Path to file to backup
        backup_dir: Optional backup directory
        
    Returns:
        Path to backup file
        
    Raises:
        FileNotFoundError: If source file doesn't exist
        OSError: If backup creation fails
    """
    file_path = Path(file_path)
    
    if not file_path.exists():
        raise FileNotFoundError(f"Source file not found: {file_path}")
    
    if backup_dir:
        backup_dir = Path(backup_dir)
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup_path = backup_dir / f"{file_path.name}.bak"
    else:
        backup_path = file_path.with_suffix(file_path.suffix + '.bak')
    
    shutil.copy2(file_path, backup_path)
    return backup_path

def find_files(directory: Union[str, Path], 
               pattern: str = '*',
               recursive: bool = True) -> List[Path]:
    """Find files matching a pattern.
    
    Args:
        directory: Directory to search
        pattern: Glob pattern to match
        recursive: Search subdirectories
        
    Returns:
        List of matching file paths
    """
    directory = Path(directory)
    if recursive:
        return list(directory.rglob(pattern))
    else:
        return list(directory.glob(pattern))

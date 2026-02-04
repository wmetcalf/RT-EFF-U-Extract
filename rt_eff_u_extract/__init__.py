"""
RTF Eff-U Extract - Extract URLs from RTF embedded objects
"""

__version__ = "0.1.0"
__author__ = "coz"
__description__ = "Extract URLs from RTF embedded objects with deobfuscation and exploit detection"

# Import main analysis functions for library usage
from .rt_eff_u_extract import (
    analyze_rtf_objects,
    extract_urls_from_data,
    is_rtf_file,
    deobfuscate_hex,
    deobfuscate_rtf_text,
    scan_document_body,
)

# Import OLE parsers
from .ole_parsers import parse_ole_object

__all__ = [
    "__version__",
    "__author__",
    "__description__",
    # Main API functions
    "analyze_rtf_objects",
    "extract_urls_from_data",
    "is_rtf_file",
    # Deobfuscation utilities
    "deobfuscate_hex",
    "deobfuscate_rtf_text",
    "scan_document_body",
    # Structure parsers
    "parse_ole_object",
]

"""
RTF Eff-U Extract - Extract URLs from RTF embedded objects
"""

__version__ = "0.1.0"
__author__ = "coz"
__description__ = "Extract URLs from RTF embedded objects with deobfuscation and exploit detection"

from .ole_parsers import *

__all__ = [
    "__version__",
    "__author__",
    "__description__",
]

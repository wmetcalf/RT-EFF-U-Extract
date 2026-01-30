#!/usr/bin/env python3
r"""
RTF URL Extractor - Extract URLs from RTF embedded objects
Supports wide URLs, normal URLs, deobfuscation, and CLSID mapping

This tool analyzes RTF files for embedded objects and extracts URLs using
the oletools/rtfobj library. It handles sophisticated obfuscation techniques
documented by threat intelligence researchers.

Obfuscation Techniques Handled:
================================
1. Whitespace injection (spaces, tabs, \r, \n)
2. RTF comments and ignorable destinations (\*\destination)
3. \' escape sequences that disorder the hex state machine
4. Split control words across groups
5. Oversized control words (>0xFF truncation behavior)
6. Multiple \objdata entries (parser uses last one)
7. Control words embedded in hex data (\par, \pard, etc.)
8. Null byte padding in URLs

Parsing Approaches:
==================
1. Structure-based parsing (primary): Parse known OLE object structures directly
   - Package objects, OLE2Link monikers, Equation Editor MTEF format
2. Pattern-based extraction (fallback): Use regex with backoff parsing

References:
- Google Cloud Threat Intelligence: RTF Malware Evasion
  https://cloud.google.com/blog/topics/threat-intelligence/how-rtf-malware-evades-detection
- CVE-2010-3333, CVE-2012-0158, CVE-2015-1641, CVE-2017-11882
"""

import sys
import argparse
import json
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from oletools import rtfobj
import binascii
import multiprocessing
import time

# Import structure-based OLE parsers
try:
    from .ole_parsers import parse_ole_object
    HAS_STRUCTURE_PARSERS = True
except ImportError:
    try:
        from ole_parsers import parse_ole_object
        HAS_STRUCTURE_PARSERS = True
    except ImportError:
        HAS_STRUCTURE_PARSERS = False
        print("Warning: ole_parsers.py not found. Using pattern-based extraction only.", file=sys.stderr)

# Try to use faster regex engines for performance
try:
    import re2 as re
    # Ensure it falls back to the 'regex' module if available, otherwise 're'
    re.set_fallback_notification(re.FALLBACK_QUIETLY)
    try:
        import regex
        re.set_fallback_module(regex)
    except ImportError:
        pass
except ImportError:
    try:
        import regex as re
    except ImportError:
        import re


def is_valid_url(url: str) -> bool:
    """
    Validate that a URL is likely legitimate and not garbage data.

    Filters out:
    - URLs that are too long (> 2048 chars - browser limit)
    - URLs with >80% non-printable/high-entropy characters
    - URLs that look like base64 blobs without proper structure
    - UNC paths that are just random garbage
    """
    if not url or not isinstance(url, str):
        return False

    # Remove common null bytes and whitespace
    url = url.strip().replace('\x00', '')

    if not url:
        return False

    # Length check - most browsers limit URLs to 2048 chars
    # For UNC paths and long base64, allow up to 4096
    if len(url) > 4096:
        return False

    # Must have a protocol or UNC path marker
    has_protocol = any(url.lower().startswith(p) for p in [
        'http://', 'https://', 'ftp://', 'ftps://', 'file://', 'smb://',
        'mms://', 'rtsp://', 'ms-', 'javascript:', 'vbscript:', 'about:',
        '//', '\\\\', '%APPDATA%', '%TEMP%', '%USERPROFILE%', '%PUBLIC%'
    ])

    if not has_protocol:
        return False

    # For very long URLs (>500 chars), check if they're just garbage
    # by looking at character distribution
    if len(url) > 500:
        # Count printable ASCII vs total
        printable_count = sum(1 for c in url if 32 <= ord(c) <= 126)
        printable_ratio = printable_count / len(url)

        # If less than 80% printable, likely garbage
        if printable_ratio < 0.8:
            return False

        # Check for excessive path depth (likely base64 blob masquerading as path)
        if url.count('/') > 50 or url.count('\\') > 50:
            return False

        # Check entropy - if it's too uniform, it's likely garbage
        # Simple check: count unique chars vs length
        unique_chars = len(set(url.lower()))
        # Base64 has 64 chars, normal URLs have more variation
        if len(url) > 500 and unique_chars < 20:  # Too uniform
            return False

    # URL must have some structure beyond just slashes
    # Filter out things like "///AAAAAAAAAAAAAA..."
    url_no_protocol = url.split('://', 1)[-1] if '://' in url else url.lstrip('/\\')
    if len(url_no_protocol) > 100:
        # Check if it's just a repeating pattern or high-entropy garbage
        # Look for domain or path structure
        has_structure = any(c in url_no_protocol for c in ['.', ':', '?', '&', '='])
        if not has_structure:
            # No query params, no dots, no structure - likely garbage
            # Unless it's a simple path
            if len(url_no_protocol) > 200:
                return False

    return True


def deduplicate_urls(urls: List[Dict]) -> List[Dict]:
    """
    Deduplicate URLs while preserving metadata.

    Keeps first occurrence of each unique URL.
    """
    seen = set()
    result = []

    for url_info in urls:
        url = url_info.get('url', '')
        if not url:
            continue

        # Normalize for comparison
        url_normalized = url.strip().replace('\x00', '').lower()

        if url_normalized not in seen:
            seen.add(url_normalized)
            result.append(url_info)

    return result


# Known ActiveX CLSIDs (expanded list for comprehensive mapping)
CLSID_MAP = {
    # Microsoft Equation Editor (Exploit Target)
    "0002CE02-0000-0000-C000-000000000046": "Microsoft Equation Editor 3.0 (CVE-2017-11882, CVE-2018-0802)",
    "0002CE03-0000-0000-C000-000000000046": "MathType Equation Editor",

    # Microsoft Excel Objects
    "00020820-0000-0000-C000-000000000046": "Microsoft Excel Chart",
    "00020821-0000-0000-C000-000000000046": "Microsoft Excel Worksheet",
    "00020830-0000-0000-C000-000000000046": "Microsoft Excel Macro Sheet",
    "00020832-0000-0000-C000-000000000046": "Microsoft Excel Binary Worksheet",
    "00020810-0000-0000-C000-000000000046": "Microsoft Excel Worksheet (legacy)",
    "00020811-0000-0000-C000-000000000046": "Microsoft Excel Chart (legacy)",

    # Microsoft Word Objects
    "00020900-0000-0000-C000-000000000046": "Microsoft Word Document",
    "00020901-0000-0000-C000-000000000046": "Microsoft Word Picture",
    "00020906-0000-0000-C000-000000000046": "Microsoft Word 6.0-7.0 Document",
    "00020907-0000-0000-C000-000000000046": "Microsoft Word 6.0-7.0 Picture",

    # Microsoft PowerPoint Objects
    "64818D10-4F9B-11CF-86EA-00AA00B929E8": "Microsoft PowerPoint Presentation",
    "64818D11-4F9B-11CF-86EA-00AA00B929E8": "Microsoft PowerPoint Slide",

    # Microsoft Graph and Visio
    "00020803-0000-0000-C000-000000000046": "Microsoft Graph Chart",
    "00021A14-0000-0000-C000-000000000046": "Microsoft Visio Drawing",

    # Package/Embedding Objects
    "F20DA720-C02F-11CE-927B-0800095AE340": "Package/Packager Object",
    "00000300-0000-0000-C000-000000000046": "StdOleLink (OLE Link)",
    "00000303-0000-0000-C000-000000000046": "File Moniker",
    "00000304-0000-0000-C000-000000000046": "Item Moniker",
    "00000305-0000-0000-C000-000000000046": "Anti Moniker",
    "00000306-0000-0000-C000-000000000046": "Pointer Moniker",

    # Multimedia Objects
    "00022601-0000-0000-C000-000000000046": "Microsoft Media Player",
    "05589FA1-C356-11CE-BF01-00AA0055595A": "ActiveMovie Control",
    "22D6F312-B0F6-11D0-94AB-0080C74C7E95": "Windows Media Player",

    # Adobe Objects
    "CA8A9780-280D-11CF-A24D-444553540000": "Adobe Shockwave Flash",
    "D27CDB6E-AE6D-11CF-96B8-444553540000": "Adobe Flash Player",

    # Forms and Controls
    "5512D110-5CC6-11CF-8D67-00AA00BDCE1D": "Microsoft Forms 2.0 HTML SUBMIT Button",
    "5512D112-5CC6-11CF-8D67-00AA00BDCE1D": "Microsoft Forms 2.0 HTML RESET Button",
    "5512D113-5CC6-11CF-8D67-00AA00BDCE1D": "Microsoft Forms 2.0 HTML TEXT",
    "5512D114-5CC6-11CF-8D67-00AA00BDCE1D": "Microsoft Forms 2.0 HTML Hidden",
    "5512D115-5CC6-11CF-8D67-00AA00BDCE1D": "Microsoft Forms 2.0 HTML Password",
    "8BD21D10-EC42-11CE-9E0D-00AA006002F3": "Microsoft Forms 2.0 CommandButton",
    "8BD21D20-EC42-11CE-9E0D-00AA006002F3": "Microsoft Forms 2.0 Label",
    "8BD21D30-EC42-11CE-9E0D-00AA006002F3": "Microsoft Forms 2.0 TextBox",
    "8BD21D40-EC42-11CE-9E0D-00AA006002F3": "Microsoft Forms 2.0 ListBox",
    "8BD21D50-EC42-11CE-9E0D-00AA006002F3": "Microsoft Forms 2.0 ComboBox",
    "8BD21D60-EC42-11CE-9E0D-00AA006002F3": "Microsoft Forms 2.0 CheckBox",
    "8BD21D70-EC42-11CE-9E0D-00AA006002F3": "Microsoft Forms 2.0 OptionButton",

    # Scriptlet and Script Control
    "0E59F1D2-1FBE-11D0-8FF2-00A0D10038BC": "Microsoft Scriptlet Component",
    "0E59F1D3-1FBE-11D0-8FF2-00A0D10038BC": "Microsoft Scriptlet",

    # Internet Explorer Objects
    "25336920-03F9-11CF-8FD0-00AA00686F13": "HTML Document",
    "EAB22AC1-30C1-11CF-A7EB-0000C05BAE0B": "Internet Explorer WebBrowser Control",
    "8856F961-340A-11D0-A96B-00C04FD705A2": "Internet Explorer Shell Embed Control",

    # Windows Shell and Explorer Objects
    "13709620-C279-11CE-A49E-444553540000": "Shell DocObject Viewer",
    "F3AA0DC0-9358-11D0-A4B5-00A0C91110ED": "Web View Folder Icon",
    "1FBA04EE-3024-11D2-8F1F-0000F87ABD16": "Explorer Band",
    "ECD4FC4D-521C-11D0-B792-00A0C90312E1": "Shell Browser Window",
    "9BA05972-F6A8-11CF-A442-00A0C90A8F39": "Shell Folder View",
    "EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B": "Shell.Explorer.1 (Internet Explorer Shell Link)",
    "88A05C00-F000-11CE-8350-444553540000": "HTML Windows Media Player",
    "EFD01300-160F-11D2-BB2E-00805FF7EFCA": "Folder Band",
    "D93CE8B0-4C03-11D3-A97A-00C04F8ECB66": "Windows Shell Folder",

    # Common OLE Objects
    "00000301-0000-0000-C000-000000000046": "StdOleLink",
    "00000302-0000-0000-C000-000000000046": "StdOleDocument",
    "00000308-0000-0000-C000-000000000046": "Composite Moniker",
    "00000309-0000-0000-C000-000000000046": "Class Moniker",
    "0000030A-0000-0000-C000-000000000046": "OBJREF Moniker",
    "0000030B-0000-0000-C000-000000000046": "Session Moniker",

    # Legacy and Special
    "11111111-1111-1111-1111-111111111111": "OLE1.0 Embedded Object",
    "00000000-0000-0000-0000-000000000000": "NULL/Unknown CLSID",

    # Paint and Image Objects
    "0003000A-0000-0000-C000-000000000046": "Paintbrush Picture",
    "0003000B-0000-0000-C000-000000000046": "Bitmap Image",
}


def is_rtf_file(file_path: str) -> bool:
    """
    Check if file starts with {\rt to validate it's an RTF file
    """
    try:
        with open(file_path, 'rb') as f:
            header = f.read(10)
            # Check for {\rt or {\rtf
            return header.startswith(b'{\\rt')
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return False


def deobfuscate_hex(hex_data: bytes) -> bytes:
    r"""
    Remove common obfuscations from hex-encoded data based on RTF parser behavior.

    Handles techniques from: https://cloud.google.com/blog/topics/threat-intelligence/how-rtf-malware-evades-detection
    - Whitespace (spaces, tabs, newlines, carriage returns)
    - RTF comments (\* ... )
    - \' escape sequences that disorder hex state
    - Escaped special characters (\\, \{, \}, \+, \-, \%)
    - Unicode control words (\ucN, \uN)
    - Control words split across hex data
    - Oversized control words (up to 0xFF / 255 chars)
    - Oversized numeric parameters (\bin with overflow)
    - Multiple \objdata entries (use last)
    - Control words ignored in objdata context (\par, etc.)
    """
    if not hex_data:
        return hex_data

    # Convert to string if bytes
    if isinstance(hex_data, bytes):
        try:
            hex_str = hex_data.decode('latin-1')
        except:
            return hex_data
    else:
        hex_str = hex_data

    # Remove RTF escaped special characters (ignored in objdata context)
    # These are literal characters that need escaping: \\ \{ \} \+ \- \%
    hex_str = re.sub(r'\\[\\{}+\-%]', '', hex_str)

    # Remove \\' escape sequences (\'HH format) - these disorder the hex state machine
    # Example: 01\'1122 -> the \'11 resets state and causes the 0 of 01 to be dropped
    hex_str = re.sub(r"\\'[0-9a-fA-F]{2}", '', hex_str)

    # Remove Unicode control words: \ucN and \uN (both ignored, chars after \uN not skipped)
    hex_str = re.sub(r'\\uc\d+\s*', '', hex_str)
    hex_str = re.sub(r'\\u-?\d+\s*', '', hex_str)

    # Remove RTF comments/ignorable groups: {\* ... }
    # This must run BEFORE specific ignorable destination removal to catch the full group
    hex_str = re.sub(r'\{\\[*][^{}]+\}', '', hex_str)

    # Remove RTF ignorable destinations: \\*\\destination
    # Example: {\*\generator Word}
    hex_str = re.sub(r'\\[*]\\[a-z0-9]+\s*', '', hex_str)

    # Remove common control words that are ignored in objdata context
    # \par, \pard, etc. - these don't accept data
    hex_str = re.sub(r'\\(?:par|pard|tab|line|page)[^a-z0-9]', '', hex_str)

    # Remove whitespace (including \r and \n which RTF parser ignores)
    hex_str = re.sub(r'[\s\r\n]+', '', hex_str)

    # Handle split control words - remove legitimate RTF control sequences
    # Match: \controlword123 or \controlword-123 (with optional numeric parameter)
    # Note: Spec says max 32 chars, but MS Word allows up to 0xFF (255) - oversized control word attack
    hex_str = re.sub(r'\\[a-z]{1,255}[-]?\d*\s*', '', hex_str, flags=re.IGNORECASE)

    # Remove braces and remaining backslashes that aren't part of hex
    hex_str = hex_str.replace('{', '').replace('}', '').replace('\\', '')

    # Remove any remaining non-hex characters
    hex_str = re.sub(r'[^0-9a-fA-F]', '', hex_str)

    return hex_str.encode('latin-1')


def extract_urls_from_data(data: bytes) -> List[Dict[str, str]]:
    """
    Extract URLs from binary data. Supports:
    - Normal ASCII URLs (http://, https://, ftp://, etc.)
    - Wide/UTF-16 URLs
    """
    urls = []

    # Pattern for URLs - including historically abused protocol handlers
    # http/https/ftp: Standard web protocols
    # file: Local file access
    # mhtml/mht: MHTML protocol (CVE-2011-0096, CVE-2021-40444)
    # ms-msdt: MS Diagnostics Tool (Follina CVE-2022-30190)
    # search-ms: Windows Search protocol
    # shell: Shell protocol handler
    # smb: SMB protocol
    url_pattern = rb'(?:https?|ftps?|file|mhtml?|ms-msdt|search-ms|shell|smb)://[^\s\x00\'"<>]+'

    # UNC paths with various obfuscations:
    # Standard: \\server\share
    # Triple slash: ///server/share
    # Mixed slashes: //\server\share or \\/server/share
    unc_pattern = rb'(?:[\\/]{2,3})[a-zA-Z0-9\-._]+[\\/][^\s\x00\'"<>]+'

    # Extract normal ASCII URLs
    for match in re.finditer(url_pattern, data, re.IGNORECASE):
        start_pos = match.start()
        url_bytes = None
        extraction_method = 'regex'

        # Strategy 1: Check for length prefix immediately before URL
        # Try different length prefix formats (common in binary formats)
        if start_pos >= 4:
            # Try 4-byte little-endian length prefix (DWORD)
            len_prefix_4 = int.from_bytes(data[start_pos-4:start_pos], 'little')
            if 10 <= len_prefix_4 <= 2048:  # Reasonable URL length
                url_end = start_pos + len_prefix_4
                if url_end <= len(data):
                    url_bytes = data[start_pos:url_end]
                    extraction_method = 'len4-prefix'

        if url_bytes is None and start_pos >= 2:
            # Try 2-byte little-endian length prefix (WORD)
            len_prefix_2 = int.from_bytes(data[start_pos-2:start_pos], 'little')
            if 10 <= len_prefix_2 <= 2048:
                url_end = start_pos + len_prefix_2
                if url_end <= len(data):
                    url_bytes = data[start_pos:url_end]
                    extraction_method = 'len2-prefix'

        if url_bytes is None and start_pos >= 1:
            # Try 1-byte length prefix (Pascal string style)
            len_prefix_1 = data[start_pos-1]
            if 10 <= len_prefix_1 <= 255:
                url_end = start_pos + len_prefix_1
                if url_end <= len(data):
                    url_bytes = data[start_pos:url_end]
                    extraction_method = 'len1-prefix'

        # Strategy 2: Find null terminator
        if url_bytes is None:
            null_pos = data.find(b'\x00', start_pos)
            if null_pos > start_pos:
                url_bytes = data[start_pos:null_pos]
                extraction_method = 'null-term'
            else:
                # Strategy 3: Use regex match as fallback
                url_bytes = match.group(0)
                extraction_method = 'regex-fallback'

        url = url_bytes.decode('latin-1', errors='ignore')

        # Clean only valid URL characters, remove trailing junk
        url = re.sub(r'[^\x20-\x7E]+$', '', url)  # Remove non-printable at end
        url = url.rstrip(')"\'<>[]{}')  # Remove trailing punctuation

        if url and len(url) >= 10:  # Minimum valid URL
            urls.append({
                'url': url,
                'type': f'ascii-{extraction_method}',
                'offset': hex(start_pos)
            })

    # Extract UNC paths (credential theft vector)
    for match in re.finditer(unc_pattern, data, re.IGNORECASE):
        start_pos = match.start()

        # Find null terminator
        null_pos = data.find(b'\x00', start_pos)
        if null_pos > start_pos:
            unc_bytes = data[start_pos:null_pos]
        else:
            unc_bytes = match.group(0)

        unc = unc_bytes.decode('latin-1', errors='ignore')
        unc = re.sub(r'[^\x20-\x7E]+$', '', unc)
        unc = unc.rstrip(')"\'<>[]{}')

        if unc and len(unc) >= 10:
            urls.append({
                'url': unc,
                'type': 'unc',
                'offset': hex(start_pos)
            })

    # Extract wide/UTF-16 URLs (little-endian)
    # Look for various protocol patterns in UTF-16LE
    wide_url_starts = []

    # Patterns for common protocols in wide format
    # http/https: h\x00t\x00t\x00p\x00
    # file: f\x00i\x00l\x00e\x00
    # mhtml: m\x00h\x00t\x00m\x00l\x00
    # ms-msdt: m\x00s\x00-\x00m\x00s\x00d\x00t\x00
    wide_patterns = [
        rb'h\x00t\x00t\x00p\x00(?:s\x00)?:\x00/\x00/\x00',  # http(s)://
        rb'f\x00i\x00l\x00e\x00:\x00/\x00/\x00',  # file://
        rb'f\x00t\x00p\x00(?:s\x00)?:\x00/\x00/\x00',  # ftp(s)://
        rb'm\x00h\x00t\x00m?\x00l\x00:\x00',  # mhtml: or mht:
        rb'm\x00s\x00-\x00m\x00s\x00d\x00t\x00:\x00',  # ms-msdt:
        rb's\x00e\x00a\x00r\x00c\x00h\x00-\x00m\x00s\x00:\x00',  # search-ms:
    ]

    for wide_pattern in wide_patterns:
        for match in re.finditer(wide_pattern, data, re.IGNORECASE):
            start_pos = match.start()
            wide_url_bytes = None
            extraction_method = 'regex'

            # Strategy 1: Find double-null terminator (most reliable for wide strings)
            end_pos = start_pos
            while end_pos < len(data) - 1:
                if data[end_pos:end_pos+2] == b'\x00\x00':
                    break
                end_pos += 2
            wide_url_bytes = data[start_pos:end_pos]
            extraction_method = 'double-null'

            # Strategy 2: Validate with length prefix if available
            # (Length prefix might include struct overhead, so use for validation only)
            if start_pos >= 4:
                len_prefix_4 = int.from_bytes(data[start_pos-4:start_pos], 'little')
                actual_len = len(wide_url_bytes)

                # If prefix exactly matches our extracted length, good!
                if len_prefix_4 == actual_len:
                    extraction_method = 'double-null+len4-exact'
                # If prefix is close (within reasonable overhead), still good
                elif actual_len <= len_prefix_4 <= actual_len + 100:
                    extraction_method = 'double-null+len4-valid'
                # If length prefix suggests a different length, try it
                elif 20 <= len_prefix_4 <= 512 and len_prefix_4 % 2 == 0:
                    # Only use it if it ends with valid chars (not binary junk)
                    alt_end = start_pos + len_prefix_4
                    if alt_end <= len(data):
                        alt_bytes = data[start_pos:alt_end]
                        # Check if last chars are reasonable (before the assumed null terminator)
                        try:
                            alt_url = alt_bytes.decode('utf-16le', errors='strict')
                            # If it decodes cleanly and has no control chars, use it
                            if all(c.isprintable() or c in '\r\n\t' for c in alt_url):
                                wide_url_bytes = alt_bytes
                                extraction_method = 'len4-bytes-validated'
                        except:
                            pass  # Keep double-null version

            # Extract and decode
            try:
                url = wide_url_bytes.decode('utf-16le', errors='ignore')

                if url and len(url) >= 10:  # Minimum valid URL length
                    urls.append({
                        'url': url,
                        'type': f'wide-{extraction_method}',
                        'offset': hex(start_pos)
                    })
            except:
                pass

    # Also check for URL-like patterns after removing nulls
    # Sometimes URLs are mangled with null bytes (but not proper UTF-16)
    null_separated = data.replace(b'\x00', b'')
    for match in re.finditer(url_pattern, null_separated, re.IGNORECASE):
        url = match.group(0).decode('latin-1', errors='ignore')

        # Truncate at first non-URL character (keep only valid URL chars)
        # Valid URL chars: alphanumeric, dash, dot, slash, colon, etc.
        valid_url = []
        for char in url:
            if char.isalnum() or char in '-._~:/?#[]@!$&()*+,;=%':
                valid_url.append(char)
            else:
                # Stop at first invalid character
                break

        url = ''.join(valid_url)

        # Only add if not already found and is valid
        if url and len(url) >= 10 and not any(u['url'] == url for u in urls):
            urls.append({
                'url': url,
                'type': 'ascii-cleaned',
                'offset': 'N/A'
            })

    # Deduplicate and clean up
    # If we have multiple extraction methods for the same URL, keep the best one
    final_urls = []
    seen_urls = set()

    # Sort by extraction method quality (best to worst)
    # Length-prefixed + validated is most reliable
    def get_type_priority(url_type):
        if 'len4-exact' in url_type:
            return 0  # Best: exact length match
        elif 'len4-prefix' in url_type or 'len4-bytes-validated' in url_type:
            return 1  # Very good: 4-byte length prefix validated
        elif 'double-null+len4' in url_type:
            return 2  # Good: double-null with length validation
        elif 'double-null' in url_type:
            return 3  # Good: double-null for wide strings
        elif 'len2' in url_type or 'len1' in url_type:
            return 4  # OK: smaller length prefixes
        elif 'null-term' in url_type:
            return 5  # OK: null-terminated
        elif url_type == 'wide':
            return 6  # Legacy wide
        elif url_type == 'ascii':
            return 7  # Legacy ascii
        elif url_type == 'unc':
            return 8  # UNC path
        else:
            return 99  # Fallback/cleaned

    urls.sort(key=lambda x: get_type_priority(x['type']))

    for url_info in urls:
        url = url_info['url']

        # Skip if we've seen an exact match
        if url in seen_urls:
            continue

        # Skip if this is a prefix/subset of something we've already added
        is_duplicate = False
        for existing in final_urls:
            existing_url = existing['url']

            # Check if one is a prefix of the other
            if url.startswith(existing_url) or existing_url.startswith(url):
                # Keep the cleaner one (based on type priority)
                if get_type_priority(url_info['type']) >= get_type_priority(existing['type']):
                    is_duplicate = True
                    break

        if not is_duplicate:
            final_urls.append(url_info)
            seen_urls.add(url)

    return final_urls


def _analyze_rtf_objects_impl(file_path: str, emulate: bool = False, timeout: int = 10) -> List[Dict]:
    """
    Internal implementation - use analyze_rtf_objects() instead which enforces hard timeout

    Use rtfobj to extract embedded objects and analyze them for URLs

    Args:
        file_path: Path to RTF file
        emulate: If True, emulate Equation Editor shellcode
        timeout: Emulation timeout in seconds (per-file, not per-object)
    """
    results = []

    try:
        # Start per-file timeout timer
        file_start_time = time.time()

        # Read RTF file as bytes
        with open(file_path, 'rb') as f:
            rtf_data = f.read()

        # Parse RTF file
        rtf_parser = rtfobj.RtfObjParser(rtf_data)
        rtf_parser.parse()

        # Iterate through found objects
        for idx, obj in enumerate(rtf_parser.objects):
            # Check if we've exceeded the per-file timeout
            elapsed = time.time() - file_start_time
            if elapsed >= timeout:
                print(f"[!] Per-file timeout ({timeout}s) exceeded after {elapsed:.1f}s. Skipping remaining objects.", file=sys.stderr)
                break

            # Calculate remaining time for this object
            remaining_timeout = max(1, int(timeout - elapsed))  # At least 1 second
            # Get class name and convert bytes to string if needed
            class_name = obj.class_name if hasattr(obj, 'class_name') else 'Unknown'
            if isinstance(class_name, bytes):
                class_name = class_name.decode('latin-1', errors='ignore')

            obj_info = {
                'index': idx,
                'start': obj.start if hasattr(obj, 'start') else 0,
                'end': obj.end if hasattr(obj, 'end') else 0,
                'class_name': class_name,
                'format_id': obj.format_id if hasattr(obj, 'format_id') else None,
                'is_ole': obj.is_ole if hasattr(obj, 'is_ole') else False,
                'is_package': obj.is_package if hasattr(obj, 'is_package') else False,
                'clsid': None,
                'clsid_desc': None,
                'raw_data_size': 0,
                'urls': []
            }

            # Get CLSID if available
            if hasattr(obj, 'clsid') and obj.clsid:
                clsid_str = obj.clsid.upper() if isinstance(obj.clsid, str) else obj.clsid
                obj_info['clsid'] = str(clsid_str)
                obj_info['clsid_desc'] = CLSID_MAP.get(str(clsid_str), obj.clsid_desc if hasattr(obj, 'clsid_desc') and obj.clsid_desc else 'Unknown ActiveX Control')

            # Get raw object data - check multiple possible attributes
            raw_data = None
            data_source = None
            if hasattr(obj, 'oledata') and obj.oledata:
                raw_data = obj.oledata
                data_source = 'oledata'
            elif hasattr(obj, 'rawdata') and obj.rawdata:
                raw_data = obj.rawdata
                data_source = 'rawdata'
            elif hasattr(obj, 'olepkgdata') and obj.olepkgdata:
                raw_data = obj.olepkgdata
                data_source = 'olepkgdata'
            elif hasattr(obj, 'hexdata') and obj.hexdata:
                # hexdata is the hex string representation
                raw_data = obj.hexdata.encode('latin-1')
                data_source = 'hexdata'

            if raw_data:
                obj_info['raw_data_size'] = len(raw_data)

                # oledata and rawdata are already binary - don't deobfuscate/unhexlify
                # Only hexdata needs deobfuscation and unhexlifying
                if data_source in ['oledata', 'rawdata', 'olepkgdata']:
                    # rtfobj gives us clean binary data
                    decoded_data = raw_data
                elif data_source == 'hexdata':
                    # hexdata is a hex string - deobfuscate and unhexlify
                    deobfuscated = deobfuscate_hex(raw_data)
                    try:
                        decoded_data = binascii.unhexlify(deobfuscated)
                    except:
                        decoded_data = raw_data
                else:
                    # Unknown source - try to detect
                    decoded_data = raw_data

                # ==============================================================
                # APPROACH 1: Structure-based parsing (preferred)
                # ==============================================================
                # Try parsing based on known OLE object structures
                structure_urls = []
                shellcode_data = None

                # Attempt to identify object type by content if CLSID is missing or unknown
                target_clsid = obj_info['clsid']


                if HAS_STRUCTURE_PARSERS:
                    # Equation Editor CLSID byte signatures (little-endian)
                    eq_clsid_patterns = [
                        (b'\x02\xCE\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46', '0002CE02-0000-0000-C000-000000000046'),
                        (b'\x03\xCE\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46', '0002CE03-0000-0000-C000-000000000046'),
                        (b'\x00\x2C\xE0\x20\x00\x00\x00\x00\x0C\x00\x00\x00\x00\x00\x00\x04', '20E02C00-0000-0000-0C00-000000000004'),
                    ]

                    # Search for CLSID bytes in decoded data (search entire data, not just first 200 bytes)
                    # If we find a known signature, we trust it over the container's reported CLSID
                    for clsid_bytes, clsid_str in eq_clsid_patterns:
                        if clsid_bytes in decoded_data:
                            target_clsid = clsid_str
                            obj_info['clsid'] = clsid_str
                            obj_info['clsid_desc'] = 'Microsoft Equation Editor 3.0 (CVE-2017-11882, CVE-2018-0802) [detected from oledata]'
                            break

                    # If still unknown or missing, check efficiently for header signatures
                    is_known_clsid = target_clsid and target_clsid in CLSID_MAP
                    if not is_known_clsid:
                         # Look for MTEF v3 header (03 01 01), OLE signature, or 'Equation.3'
                         if (b'\x03\x01\x01' in decoded_data[:200] or 
                             b'\xd0\xcf\x11\xe0' in decoded_data[:200] or
                             b'Equation.3' in decoded_data[:200] or
                             target_clsid == '20E02C00-0000-0000-0C00-000000000004'):
                                 
                            # Looks like Equation Editor or OLE compound file
                            target_clsid = '0002CE02-0000-0000-C000-000000000046'

                # Try structure parsing if we have a valid target CLSID or known class name
                class_name_str = obj_info['class_name'].decode('ascii', errors='ignore').lower() if isinstance(obj_info['class_name'], bytes) else (obj_info['class_name'] or '').lower()
                should_parse = HAS_STRUCTURE_PARSERS and (
                    target_clsid or
                    class_name_str in ['package', 'ole2link']
                )

                if should_parse:
                    try:
                        clsid_to_use = target_clsid or obj_info['clsid'] or ''
                        parsed_obj = parse_ole_object(clsid_to_use, decoded_data,
                                                      emulate_shellcode=emulate, timeout=remaining_timeout)
                        if parsed_obj:
                            if 'urls' in parsed_obj and parsed_obj['urls']:
                                for url in parsed_obj['urls']:
                                    structure_urls.append({
                                        'url': url,
                                        'type': f"{parsed_obj['type']}-structure",
                                        'offset': '(structure-parsed)'
                                    })

                            # Store additional structured data
                            if parsed_obj['type'] == 'Package':
                                obj_info['package_label'] = parsed_obj.get('label')
                                obj_info['package_org_path'] = parsed_obj.get('org_path')
                                obj_info['package_data_path'] = parsed_obj.get('data_path')
                            elif parsed_obj['type'] == 'OLE2Link':
                                obj_info['ole2link_url'] = parsed_obj.get('url')
                            elif parsed_obj['type'] == 'EquationEditor':
                                obj_info['equation_editor'] = True
                                obj_info['shellcode_found'] = parsed_obj.get('font_record_found', False)
                                shellcode_data = parsed_obj.get('shellcode')
                                if shellcode_data:
                                    obj_info['shellcode_size'] = len(shellcode_data)
                                    if 'emulation' in parsed_obj:
                                        emu_res = parsed_obj['emulation']
                                        if emu_res.get('urls'):
                                            for url_info in emu_res['urls']:
                                                structure_urls.append({
                                                    'url': url_info.get('url'),
                                                    'type': f"emulated-{url_info.get('source', 'unknown')}",
                                                    'offset': 'N/A'
                                                })
                                            
                                            # Save Speakeasy report if present
                                            if emu_res.get('report'):
                                                report_path = f"speakeasy_obj_{idx}_structure.json"
                                                with open(report_path, 'w') as f:
                                                    json.dump(emu_res['report'], f, indent=4)
                                                print(f"[*] Saved full Speakeasy report to {report_path}", file=sys.stderr)
                    except Exception as e:
                        pass

                # Fallback: If emulation requested and based on generic object properties
                # try scanning the raw object for shellcode (for malformed objects)
                # Optimization: Only scan if structure parsing failed to find URLs
                pattern_extracted_early = False  # Track if we did pattern extraction already
                if emulate and not structure_urls and HAS_STRUCTURE_PARSERS:
                    # Quick pattern extraction BEFORE expensive emulation
                    # This ensures we get URLs even if emulation times out
                    quick_pattern_urls = extract_urls_from_data(decoded_data)
                    if quick_pattern_urls:
                        print(f"[*] Quick pattern scan found {len(quick_pattern_urls)} URL(s) before emulation", file=sys.stderr)
                        structure_urls.extend(quick_pattern_urls)
                        pattern_extracted_early = True

                    try:
                        from .shellcode_emulator import emulate_shellcode, scan_shellcode

                        # Phase 1: Fast Pass (offset 0 + known patterns)
                        emu_res = emulate_shellcode(decoded_data, timeout=remaining_timeout)

                        # Phase 2: Adaptive Scan (Sliding Window)
                        # If fast pass failed AND we don't already have URLs from structure/patterns, try deep scanning
                        # ONLY for Equation Editor objects (known to have embedded shellcode)
                        # Skip expensive scanning if we already found URLs via structure parsing or early pattern extraction
                        if not (emu_res['success'] and emu_res.get('urls')) and not structure_urls:
                             # Check if this is an Equation Editor object
                             is_equation_editor = False

                             # Check 1: CLSID match
                             if target_clsid and target_clsid.upper() in [
                                 '0002CE02-0000-0000-C000-000000000046',
                                 '0002CE03-0000-0000-C000-000000000046',
                                 '20E02C00-0000-0000-0C00-000000000004'
                             ]:
                                 is_equation_editor = True

                             # Check 2: CLSID bytes in data
                             if not is_equation_editor:
                                 eq_clsid_patterns = [
                                     b'\x02\xCE\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46',
                                     b'\x03\xCE\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46',
                                     b'\x00\x2C\xE0\x20\x00\x00\x00\x00\x0C\x00\x00\x00\x00\x00\x00\x04',
                                 ]
                                 for clsid_bytes in eq_clsid_patterns:
                                     if clsid_bytes in decoded_data:
                                         is_equation_editor = True
                                         break

                             # Check 3: "Equation" string marker (case-insensitive)
                             if not is_equation_editor:
                                 if b'equation.3' in decoded_data[:4096].lower() or b'equation.2' in decoded_data[:4096].lower():
                                     is_equation_editor = True

                             # Only scan Equation Editor objects that are small enough
                             if is_equation_editor and len(decoded_data) < 1024 * 1024:
                                 print(f"[*] Standard emulation yielded no URLs. Attempting sliding-window scan on Object #{idx}...", file=sys.stderr)
                                 # Recalculate remaining timeout for scanning phase
                                 elapsed = time.time() - file_start_time
                                 scan_timeout = max(1, int(timeout - elapsed))
                                 # Use priority offsets with short per-offset timeout (scan_shellcode limits to 3s for priority, 2s for others)
                                 # Adaptive stride: large files (>50KB) use stride=4 to avoid timeout
                                 adaptive_stride = 4 if len(decoded_data) > 50 * 1024 else 1
                                 scan_res = scan_shellcode(decoded_data, stride=adaptive_stride, timeout=scan_timeout)
                                 if scan_res['success']:
                                     emu_res = scan_res

                        if emu_res['success'] and (emu_res.get('urls') or emu_res.get('api_calls')):
                            if emu_res.get('urls'):
                                for url_info in emu_res['urls']:
                                    structure_urls.append({
                                        'url': url_info.get('url'),
                                        'type': f"raw-emulation-{url_info.get('source', 'unknown')}",
                                        'offset': f"scanned:{hex(emu_res.get('scan_offset', 0))}" if 'scan_offset' in emu_res else '0'
                                    })
                            # Also grab APIs/IOCs
                            if emu_res.get('api_calls') or emu_res.get('file_operations'):
                                obj_info['shellcode_found'] = True # effectively found it
                                obj_info['raw_emulation_success'] = True
                                
                                # Save Speakeasy report if present
                                if emu_res.get('report'):
                                    report_path = f"speakeasy_obj_{idx}_raw.json"
                                    with open(report_path, 'w') as f:
                                        json.dump(emu_res['report'], f, indent=4)
                                    print(f"[*] Saved full Speakeasy report to {report_path}", file=sys.stderr)
                    except Exception as e:
                        # print(f"Emulation error: {e}")
                        pass

                # ==============================================================
                # APPROACH 2: Pattern-based extraction (fallback)
                # ==============================================================
                # Extract URLs from both raw and decoded data using regex patterns
                # Skip if we already did pattern extraction early (before emulation)
                pattern_urls = []
                if not pattern_extracted_early:
                    pattern_urls = extract_urls_from_data(raw_data)
                    if decoded_data != raw_data:
                        pattern_urls.extend(extract_urls_from_data(decoded_data))

                # If we extracted shellcode, try to find URLs in it too
                if shellcode_data:
                    shellcode_urls = extract_urls_from_data(shellcode_data)
                    for url_info in shellcode_urls:
                        url_info['type'] = f"shellcode-{url_info['type']}"
                    pattern_urls.extend(shellcode_urls)

                # Combine structure-based and pattern-based results
                all_urls = structure_urls + pattern_urls

                # Deduplicate URLs (prefer structure-based over pattern-based)
                seen = set()
                unique_urls = []
                for url_info in all_urls:
                    if url_info['url'] not in seen:
                        seen.add(url_info['url'])
                        unique_urls.append(url_info)

                obj_info['urls'] = unique_urls

            results.append(obj_info)

    except Exception as e:
        print(f"Error parsing RTF objects: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()

    # Validate and deduplicate URLs before returning
    for obj_info in results:
        if obj_info.get('urls'):
            # Filter out invalid URLs
            valid_urls = [u for u in obj_info['urls'] if is_valid_url(u.get('url', ''))]
            # Deduplicate
            obj_info['urls'] = deduplicate_urls(valid_urls)

    return results


def _worker_analyze(file_path, emulate, timeout, result_queue):
    """Worker function for multiprocessing timeout enforcement"""
    try:
        results = _analyze_rtf_objects_impl(file_path, emulate, timeout)
        result_queue.put(('success', results))
    except Exception as e:
        result_queue.put(('error', str(e)))


def analyze_rtf_objects(file_path: str, emulate: bool = False, timeout: int = 10) -> List[Dict]:
    """
    Analyze RTF file with HARD timeout enforcement using multiprocessing.

    This wrapper ensures the process is killed if it exceeds the timeout,
    regardless of what's happening inside (emulation, parsing, etc.)

    Args:
        file_path: Path to RTF file
        emulate: If True, emulate Equation Editor shellcode
        timeout: Hard timeout in seconds - process will be KILLED if exceeded

    Returns:
        List of analyzed objects with URLs
    """
    # Create queue for inter-process communication
    result_queue = multiprocessing.Queue()

    # Create worker process
    process = multiprocessing.Process(
        target=_worker_analyze,
        args=(file_path, emulate, timeout, result_queue)
    )

    # Start process and wait with timeout
    process.start()
    process.join(timeout=timeout + 2)  # Give 2 extra seconds for graceful shutdown

    # Check if process is still alive (timeout exceeded)
    if process.is_alive():
        # Force kill the process
        process.terminate()
        process.join(timeout=1)
        if process.is_alive():
            process.kill()  # Nuclear option
            process.join()

        print(f"[!] Hard timeout ({timeout}s) exceeded - process killed", file=sys.stderr)
        return []  # Return empty results on timeout

    # Process completed - get results
    if not result_queue.empty():
        status, data = result_queue.get()
        if status == 'success':
            return data
        else:
            print(f"[!] Error in analysis: {data}", file=sys.stderr)
            return []

    # No results in queue (shouldn't happen)
    return []


def print_results(results: List[Dict], verbose: bool = False):
    """
    Pretty print the extraction results
    """
    if not results:
        print("No embedded objects found.")
        return

    print(f"\n{'='*80}")
    print(f"RTF URL Extraction Results")
    print(f"{'='*80}\n")

    total_urls = 0
    for obj_info in results:
        print(f"Object #{obj_info['index']}:")
        print(f"  Class Name: {obj_info['class_name']}")

        if obj_info['clsid']:
            print(f"  CLSID: {obj_info['clsid']}")
            print(f"  Description: {obj_info['clsid_desc']}")

        print(f"  Raw Data Size: {obj_info['raw_data_size']} bytes")

        if obj_info['urls']:
            print(f"  URLs Found: {len(obj_info['urls'])}")
            for url_info in obj_info['urls']:
                print(f"    [{url_info['type']}] {url_info['url']}")
                if verbose:
                    print(f"      Offset: {url_info['offset']}")
            total_urls += len(obj_info['urls'])
        else:
            print(f"  URLs Found: 0")

        print()

    print(f"{'='*80}")
    print(f"Total Objects: {len(results)}")
    print(f"Total URLs: {total_urls}")
    print(f"{'='*80}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Extract URLs from RTF embedded objects with deobfuscation support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s malicious.rtf
  %(prog)s -v suspicious.rtf
  %(prog)s --json output.json document.rtf
        """
    )

    parser.add_argument('file', help='RTF file to analyze')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output with offsets')
    parser.add_argument('--json', metavar='FILE',
                       help='Export results to JSON file')
    parser.add_argument('--no-interactive', action='store_true',
                       help='Skip prompts for batch processing')
    parser.add_argument('--emulate', action='store_true',
                       help='Emulate Equation Editor shellcode to extract URLs (requires speakeasy-emulator)')
    parser.add_argument('--timeout', type=int, default=10, metavar='SECONDS',
                       help='Shellcode emulation timeout in seconds (default: 10)')

    args = parser.parse_args()

    # Validate input file
    if not Path(args.file).exists():
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    # Check if it's an RTF file
    if not is_rtf_file(args.file):
        print(f"Warning: File does not appear to be a valid RTF file (missing {{\\rt header)",
              file=sys.stderr)
        if not args.no_interactive:
            response = input("Continue anyway? [y/N]: ")
            if response.lower() != 'y':
                sys.exit(1)
        else:
            # In non-interactive mode, skip non-RTF files
            print(f"Skipping non-RTF file", file=sys.stderr)
            sys.exit(0)

    # Check for speakeasy if emulation requested
    if args.emulate and not HAS_STRUCTURE_PARSERS:
        print(f"Warning: Structure parsers not available, emulation disabled", file=sys.stderr)
        args.emulate = False
    elif args.emulate:
        # Check if speakeasy is available
        try:
            from .shellcode_emulator import HAS_SPEAKEASY
            if not HAS_SPEAKEASY:
                print(f"Error: --emulate requires speakeasy-emulator", file=sys.stderr)
                print(f"Install with: pip install speakeasy-emulator", file=sys.stderr)
                sys.exit(1)
        except ImportError:
            print(f"Error: --emulate requires speakeasy-emulator", file=sys.stderr)
            print(f"Install with: pip install speakeasy-emulator", file=sys.stderr)
            sys.exit(1)

    # Analyze the file
    print(f"Analyzing RTF file: {args.file}")
    if args.emulate:
        print(f"Shellcode emulation: ENABLED (timeout: {args.timeout}s)")
    results = analyze_rtf_objects(args.file, emulate=args.emulate, timeout=args.timeout)

    # Print results
    print_results(results, verbose=args.verbose)

    # Export to JSON if requested
    if args.json:
        import json
        with open(args.json, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results exported to: {args.json}")


if __name__ == '__main__':
    main()

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
import hashlib
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

    # High entropy/garbage check
    printable_chars = [c for c in url if 32 <= ord(c) <= 126]
    if len(url) > 20 and len(printable_chars) / len(url) < 0.7:
        return False

    # Basic structure check for common protocols
    if url.lower().startswith(('http://', 'https://')):
        if '.' not in url or len(url) < 12:
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



def deobfuscate_rtf_text(data: bytes) -> bytes:
    """
    Deobfuscate RTF text to reveal hidden strings/commands.
    - Removes comments/ignorables
    - Removes newlines
    - Decodes \\'xx sequences
    Returns: BYTES
    """
    # Ensure data is bytes
    if not isinstance(data, bytes):
        return data

    text = data
    
    # 1. Remove comments/ignorables {\* ... }
    # IGNORE known document-level tags to preserve them for scanning
    # Remove groups that do NOT start with \template, \htmltag, \fldinst
    text = re.sub(rb'\{\\[*](?!\\template|\\htmltag|\\fldinst)[^{}]+\}', b'', text)

    # 1.5. Protect delimiters for key control words
    # If \template is followed by newline/tab/null, stripping them merges tokens.
    # We strip junk globally, so we must insert a SAFE delimiter (Space) if one is missing.
    # Regex: (keyword) followed by non-alpha-non-space (which implies junk chars or punctuation)
    # Actually simpler: Replace (keyword)[junk]+ with "(keyword) ".
    # List: \template, \field, \htmltag, \fldinst
    # Pattern: \\(template|field|htmltag|fldinst)(?=[\r\n\t\x00])
    text = re.sub(rb'\\(template|field|htmltag|fldinst)(?=[\r\n\t\x00])', rb'\\\1 ', text)
    
    # 2. Remove ignorables like \*\destination
    # Same exclusion apply if relevant, but typically only Step 1 catches split keywords
    # text = re.sub(rb'\\[*]\\[a-z0-9]+\s*', b'', text)

    # 3. Remove newlines/returns/tabs/nulls (RTF ignores them)
    text = re.sub(rb'[\r\n\t\x00]+', b'', text)

    # 3.5. Decode Unicode sequences (\uN and \ucN) and handle junk logic
    
    # Process \uN and \ucN manually to handle skip count state
    output = bytearray()
    i = 0
    n = len(text)
    skip_count = 1 # Default \uc1
    
    while i < n:
        if text[i] == 92: # Backslash '\'
            # Check for \ucN
            match_uc = re.match(rb'\\uc(\d+)', text[i:i+10]) 
            if match_uc:
                try:
                    skip_count = int(match_uc.group(1))
                except:
                    pass
                i += len(match_uc.group(0))
                continue
                
            # Check for \uN
            match_u = re.match(rb'\\u(-?\d+)', text[i:i+10])
            if match_u:
                val_str = match_u.group(1)
                val = int(val_str)
                if val < 0: val += 65536
                if 0 <= val <= 255:
                    output.append(val)
                else:
                    output.append(ord('?'))
                i += len(match_u.group(0))
                skipped = 0
                while skipped < skip_count and i < n:
                    if text[i] == ord(' '): 
                         i += 1 
                         continue
                    i += 1
                    skipped += 1
                continue
                
            # Check for ignorable control words (junk spaces)
            match_ign = re.match(rb'\\(par|pard|tab|line|plain)(?![a-z0-9])', text[i:i+20])
            if match_ign:
                 i += len(match_ign.group(0))
                 if i < n and text[i] == ord(' '):
                     i += 1
                 continue

            # Check for escaped specials: \{ \} \\
            if i+1 < n:
                next_b = text[i+1]
                if next_b in b'{}\\':
                    output.append(next_b)
                    i += 2
                    continue
                
        output.append(text[i])
        i += 1
        
    text = bytes(output)

    # 4. Decode \'xx hex sequences manually ...
    # re.sub with callback truncates large files with specific patterns?
    output = bytearray()
    last_pos = 0
    pattern = re.compile(rb"\\'[0-9a-fA-F]{2}")
    
    for match in pattern.finditer(text):
        output.extend(text[last_pos:match.start()])
        try:
            val = int(match.group(0)[2:], 16)
            output.append(val)
        except:
            output.extend(match.group(0))
        last_pos = match.end()
    
    output.extend(text[last_pos:])
    text = bytes(output)
    
    # 5. Simplistic cleanup of braces used for grouping within keywords
    # This is risky but helps with split keywords like \t}em{plate
    # For now, let's just trust step 1 handled the major obfuscations
    
    return text


def scan_document_body(data: bytes) -> List[Dict]:
    """
    Scan the entire document body for obfuscated external links.
    Focuses on:
    - \\template
    - \\field (HYPERLINK)
    - \\htmltag (detected as requested)
    """
    results = []
    
    # Deobfuscate the whole body
    clean_text = deobfuscate_rtf_text(data)
    # Deobfuscate the whole body
    clean_text = deobfuscate_rtf_text(data)
    
    # helper to safely decode bytes to str for results
    def safe_decode(b: bytes) -> str:
        return b.decode('latin-1', errors='ignore')

    # 1. Scan for \template targets
    # Syntax: {\*\template URL} or \template URL
    # Regex: Handle quoted and unquoted
    template_matches = re.finditer(rb'\\template\s+(?:\"([^\"]+)\"|([^\s\}]+))', clean_text, re.IGNORECASE)
    for m in template_matches:
        url_bytes = m.group(1) or m.group(2)
        url = safe_decode(url_bytes)
        # Verify it looks like a URL/Path
        if len(url) > 3 and (':' in url or url.startswith('\\\\') or '.' in url):
            results.append({
                'type': 'doc-template',
                'url': url,
                'offset': 'obfuscated' # We lost true offset during cleanup
            })

    # 2. Scan for HYPERLINK and INCLUDEPICTURE fields
    # Syntax: \field{\*\fldinst { HYPERLINK "URL" }}
    # Syntax: \field{\*\fldinst { INCLUDEPICTURE "URL" }}
    # Regex: (HYPERLINK|INCLUDEPICTURE|INCLUDETEXT)\s+(?:\"([^\"]+)\"|([^\s\}]+))
    hyperlinks = re.finditer(rb'(HYPERLINK|INCLUDEPICTURE|INCLUDETEXT)\s+(?:\"([^\"]+)\"|([^\s\}]+))', clean_text, re.IGNORECASE)
    for m in hyperlinks:
        keyword = safe_decode(m.group(1)).upper()
        url_bytes = m.group(2) or m.group(3)
        
        # Determine type based on keyword
        doc_type = 'doc-hyperlink'
        if 'INCLUDEPICTURE' in keyword:
            doc_type = 'doc-includepicture'
        elif 'INCLUDETEXT' in keyword:
            doc_type = 'doc-includetext'
            
        if url_bytes:
             results.append({
                'type': doc_type,
                'url': safe_decode(url_bytes),
                'offset': 'obfuscated'
            })

    # 3. Scan for \htmltag
    # Syntax: {\*\htmltag ... href="URL" ...}
    htmltags = re.finditer(rb'\\htmltag.*?(?:href|src)=[\'\"]?([^\s\'\"\}]+)', clean_text, re.IGNORECASE)
    for m in htmltags:
        url_bytes = m.group(1)
        if url_bytes:
             results.append({
                'type': 'doc-htmltag',
                'url': safe_decode(url_bytes),
                'offset': 'obfuscated'
            })
            
    return results


def strip_bin_runs(data: bytes) -> Tuple[bytes, int]:
    r"""
    Strip \binN runs from raw RTF data before parser sees it.

    The \bin control word declares N bytes of raw binary data embedded in the
    RTF stream. Malware uses this to inject junk padding into \objdata hex
    regions, inflating objects and evading signature detection (Mandiant blog
    Section 2e).

    rtfobj handles \bin by converting the binary bytes to hex and concatenating
    them into the hex stream. This breaks nibble alignment when \bin appears at
    an odd nibble boundary. Stripping the runs before parsing avoids this.

    Returns:
        (cleaned_data, count_of_bin_runs_stripped)
    """
    # \bin followed by required numeric parameter, optional single space delimiter
    # Must NOT match \binary or other \bin* control words
    pattern = re.compile(rb'\\bin(\d+) ?')
    result = bytearray()
    pos = 0
    count = 0
    while pos < len(data):
        m = pattern.search(data, pos)
        if not m:
            result.extend(data[pos:])
            break
        # Copy everything before the \bin match
        result.extend(data[pos:m.start()])
        n = int(m.group(1))
        # Skip the \binN control word + N binary bytes
        skip_to = m.end() + n
        pos = min(skip_to, len(data))
        count += 1
    return bytes(result), count


def _count_and_sub(pattern, repl, string, flags=0):
    """Count regex matches, then substitute. Returns (new_string, count)."""
    count = len(re.findall(pattern, string, flags=flags))
    return re.sub(pattern, repl, string, flags=flags), count


_HEX_CHARS = set(b'0123456789abcdefABCDEF')

# Import rtfobj's known destination control words for accurate {\*\dest} handling.
# Known destinations (like \comment) cause rtfobj to open a new destination context,
# diverting text away from the objdata stream. Unknown CWs after \* do NOT divert —
# hex chars after them stay in the objdata stream. We must match this behavior.
try:
    from oletools.rtfobj import DESTINATION_CONTROL_WORDS as _RTFOBJ_DEST_CWS
    _DEST_CW_STRS = frozenset(cw.decode('ascii', errors='ignore') for cw in _RTFOBJ_DEST_CWS)
except Exception:
    _DEST_CW_STRS = frozenset()


def deobfuscate_hex(hex_data: bytes, track: bool = False):
    r"""
    Remove obfuscation from hex-encoded RTF \objdata using a proper state-machine
    parser instead of regexes.

    Walks the data character by character, implementing the RTF hex parser behavior:
    - Hex chars [0-9a-fA-F] are accumulated
    - '\' starts a control word: reads name (letters), optional numeric param
      (digits with optional '-' sign), optional space delimiter — all discarded
    - '\binN' skips N following bytes (binary data)
    - '\'hh' escape sequences are discarded and reset nibble state (matches rtfobj/Word)
    - '\\' '\{' '\}' and other escaped specials are discarded
    - '{' pushes group depth; '}' pops it
    - '{\*\knownDest ...}' — known destination, all content discarded (matches rtfobj)
    - '{\*\unknownCW ...}' — CW skipped, hex chars kept (matches rtfobj)
    - Whitespace and all other non-hex chars are ignored

    Args:
        hex_data: Raw hex data from \objdata region (bytes or str)
        track: If True, return (cleaned_bytes, stats_dict)

    Returns:
        bytes of clean hex chars, or (bytes, dict) if track=True
    """
    stats = {}
    if not hex_data:
        return (hex_data, stats) if track else hex_data

    if isinstance(hex_data, bytes):
        data = hex_data
    else:
        data = hex_data.encode('latin-1')

    result = bytearray()
    i = 0
    length = len(data)

    # Stack tracking whether hex chars should be kept at each brace depth.
    # Known destinations after \* push False (discard hex); everything else
    # inherits from parent. Top-level always keeps.
    keep_stack = [True]
    # Track whether any hex chars have been emitted in the current group.
    # Used to decide \* handling: {\*\unknownCW} discards when no hex
    # preceded \* (RTF ignorable destination), but {hex\*\unknownCW}
    # keeps hex that appeared before \*.
    group_hex_count = [0]

    while i < length:
        ch = data[i]

        if ch == 0x5C:  # '\'
            # Backslash — start of control word or escaped char
            if i + 1 >= length:
                i += 1
                continue

            next_ch = data[i + 1]

            # Escaped specials: \\ \{ \} \+ \- \%
            if next_ch in (0x5C, 0x7B, 0x7D, 0x2B, 0x2D, 0x25):
                stats['escaped_specials'] = stats.get('escaped_specials', 0) + 1
                i += 2
                continue

            # \' escape: \'HH — nibble-state management (matches rtfobj/MS Word)
            # MS Word resets nibble accumulator: if odd count of hex chars
            # accumulated so far, drop the last one (orphaned high nibble)
            if next_ch == 0x27:  # "'"
                stats['escape_sequences'] = stats.get('escape_sequences', 0) + 1
                if len(result) & 1:
                    result.pop()
                i += min(4, length - i)  # skip \' + 2 hex chars (clamp to end)
                continue

            # \* ignorable destination marker
            if next_ch == 0x2A:  # '*'
                # RTF spec: \* marks the group as an ignorable destination.
                # If the following CW is a known destination, always discard.
                # If unknown AND no hex chars were emitted in this group
                # before \*, discard too (the whole group is ignorable).
                # If unknown but hex chars preceded \*, keep the group
                # (the hex is real data; only the \*\CW part is ignorable).
                j = i + 2
                while j < length and data[j] in (0x20, 0x09, 0x0D, 0x0A):
                    j += 1
                dest_name = None
                if j < length and data[j] == 0x5C:  # backslash starting CW
                    k = j + 1
                    while k < length and ((0x61 <= data[k] <= 0x7A) or (0x41 <= data[k] <= 0x5A)):
                        k += 1
                    if k > j + 1:
                        dest_name = data[j+1:k].decode('latin-1').lower()
                if len(keep_stack) > 1 and dest_name:
                    if dest_name in _DEST_CW_STRS:
                        # Known destination — always discard
                        keep_stack[-1] = False
                    elif group_hex_count[-1] == 0:
                        # Unknown dest but no hex preceded \* in this group
                        # — treat the entire group as ignorable
                        keep_stack[-1] = False
                stats['comments'] = stats.get('comments', 0) + 1
                i += 2
                continue

            # Control word: \<letters>[<-?digits>][<space>]
            if 0x61 <= next_ch <= 0x7A or 0x41 <= next_ch <= 0x5A:  # a-z or A-Z
                j = i + 1
                # Read CW name (letters)
                while j < length and ((0x61 <= data[j] <= 0x7A) or (0x41 <= data[j] <= 0x5A)):
                    j += 1
                cw_name = data[i+1:j].decode('latin-1').lower()

                # Read optional numeric parameter
                param_start = j
                if j < length and data[j] == 0x2D:  # '-'
                    j += 1
                while j < length and 0x30 <= data[j] <= 0x39:  # 0-9
                    j += 1

                # Optional space delimiter (consumed)
                if j < length and data[j] == 0x20:  # ' '
                    j += 1

                # Handle \bin: skip N raw bytes
                if cw_name == 'bin' and param_start < j:
                    param_str = data[param_start:j].rstrip(b' ').decode('latin-1')
                    try:
                        n_bytes = max(0, int(param_str))
                    except ValueError:
                        n_bytes = 0
                    stats['bin_runs'] = stats.get('bin_runs', 0) + 1
                    i = min(j + n_bytes, length)
                    continue

                # Known destination CW inside a group — discard remaining
                # content (matches rtfobj, which opens a new context for
                # destinations like \object, \objdata, \comment, etc.)
                if cw_name in _DEST_CW_STRS and len(keep_stack) > 1:
                    keep_stack[-1] = False

                stats['generic_control_words'] = stats.get('generic_control_words', 0) + 1
                i = j
                continue

            # Control symbol: backslash + single non-alpha char (e.g. \2, \;, \?)
            # rtfobj skips both bytes as a control symbol. We must match.
            stats['stray_backslashes'] = stats.get('stray_backslashes', 0) + 1
            i += 2
            continue

        elif ch == 0x7B:  # '{'
            keep_stack.append(keep_stack[-1])  # inherit parent keep state
            group_hex_count.append(0)
            stats['brace_groups'] = stats.get('brace_groups', 0) + 1
            i += 1
            continue

        elif ch == 0x7D:  # '}'
            if len(keep_stack) > 1:
                keep_stack.pop()
            if len(group_hex_count) > 1:
                group_hex_count.pop()
            stats['brace_groups'] = stats.get('brace_groups', 0) + 1
            i += 1
            continue

        elif ch in _HEX_CHARS:
            if keep_stack[-1]:
                result.append(ch)
                group_hex_count[-1] += 1
            i += 1
            continue

        else:
            # Whitespace or other non-hex — skip
            if ch in (0x20, 0x09, 0x0D, 0x0A):
                stats['whitespace'] = stats.get('whitespace', 0) + 1
            else:
                stats['non_hex_chars'] = stats.get('non_hex_chars', 0) + 1
            i += 1
            continue

    result_bytes = bytes(result)
    return (result_bytes, stats) if track else result_bytes


def deobfuscate_rtf_file(file_path: str, output_path: str) -> dict:
    r"""
    Read an RTF file, safely deobfuscate it, and write a cleaned version.

    Strategy: Use our own deobfuscate_hex() state-machine parser directly
    on each \objdata region.  This avoids rtfobj's hex-leakage bugs with
    complex obfuscation (nested groups whose CW names contain hex-like
    chars a-f) and removes the need for fragile position-matching between
    rtfobj objects and original file positions.

    Also handles:
    - Nested \objdata regions (only innermost leaf regions are cleaned)
    - Object-level keywords embedded in hex regions are relocated before
      the \objdata keyword so Word still sees them

    Returns dict with stats about what was cleaned.
    """
    with open(file_path, 'rb') as f:
        data = f.read()

    stats = {'objdata_regions': 0, 'header_fixed': False}

    # Object-level keywords to relocate from inside \objdata hex regions
    _obj_kw_re = re.compile(
        rb'\\(obj(?:link|emb|html|ocx|autlink|sub|pub|icemb'
        rb'|w|h|setsize|scalex|scaley|cropb|cropt|cropl|cropr'
        rb'|update|time|class|name))(-?\d*)',
        re.IGNORECASE,
    )

    # Find all \objdata regions in the original data.
    # Consume optional numeric parameter and trailing space, matching
    # RTF CW syntax (\name[-]digits[ ]).  Obfuscation may append digits
    # directly after \objdata (e.g. \objdata87598{...}) — these are the
    # CW parameter, not hex data.
    objdata_pat = re.compile(rb'\\objdata-?\d*\s?', re.IGNORECASE)
    orig_regions = []
    for m in objdata_pat.finditer(data):
        kw_start = m.start()
        region_start = m.end()
        depth = 0
        i = region_start
        while i < len(data):
            b = data[i:i+1]
            if b == b'\\' and i + 1 < len(data) and data[i+1:i+2] in (b'{', b'}', b'\\'):
                i += 2
                continue
            if b == b'{':
                depth += 1
            elif b == b'}':
                if depth == 0:
                    orig_regions.append((kw_start, region_start, i))
                    break
                depth -= 1
            i += 1

    stats['objdata_regions'] = len(orig_regions)

    # Detect nested regions: an inner \objdata inside an outer \objdata.
    # Only replace innermost (leaf) regions — outer regions would lose
    # the inner \object when their hex content is replaced.
    nested_parents = set()
    for i, (kw_i, hs_i, he_i) in enumerate(orig_regions):
        for j, (kw_j, hs_j, he_j) in enumerate(orig_regions):
            if i != j and hs_j >= hs_i and he_j <= he_i:
                nested_parents.add(i)

    # Build replacements using our own hex parser on each region.
    replacements = []
    for idx, (kw_start, hex_start, hex_end) in enumerate(orig_regions):
        if idx in nested_parents:
            continue

        raw_region = data[hex_start:hex_end]
        clean_hex_bytes = deobfuscate_hex(raw_region)
        clean_hex = clean_hex_bytes.decode('latin-1')

        # Skip regions where all data is in \bin runs (raw binary OLE
        # data, no hex chars).  Replacing with empty hex would destroy
        # the object.  Leave the region as-is — Word handles \bin natively.
        if not clean_hex:
            continue

        # Extract object-level keywords embedded in the hex region
        relocated_kws = []
        seen_kws = set()
        for km in _obj_kw_re.finditer(raw_region):
            kw_name = km.group(1).lower()
            if kw_name not in seen_kws:
                seen_kws.add(kw_name)
                relocated_kws.append(km.group(0))

        if len(clean_hex) % 2:
            clean_hex = clean_hex[:-1]

        # Fix corrupted OLE1 version field.  Obfuscation can scatter
        # junk hex chars at depth 0 before the real OLE data, corrupting
        # the 4-byte version field while leaving the rest intact.  If
        # format_id (bytes 4-7) and ProgID structure validate, replace
        # the version with the standard 0x00000501.
        if len(clean_hex) >= 24:
            try:
                raw_bytes = bytes.fromhex(clean_hex[:24])
                fmt_id = int.from_bytes(raw_bytes[4:8], 'little')
                pid_len = int.from_bytes(raw_bytes[8:12], 'little')
                ver = int.from_bytes(raw_bytes[0:4], 'little')
                if (fmt_id in (1, 2, 5)
                        and 1 <= pid_len <= 255
                        and ver != 0x501):
                    # Validate ProgID is printable ASCII
                    pid_end = 12 + pid_len
                    if pid_end * 2 <= len(clean_hex):
                        pid_bytes = bytes.fromhex(
                            clean_hex[24:pid_end * 2])
                        if pid_bytes and 0x20 <= pid_bytes[0] <= 0x7E:
                            clean_hex = '01050000' + clean_hex[8:]
            except (ValueError, IndexError):
                pass

        replacements.append((kw_start, hex_end, clean_hex, relocated_kws))

    # Apply replacements backwards to preserve offsets
    for kw_start, hex_end, clean_hex, relocated_kws in reversed(replacements):
        lines = [clean_hex[j:j+64] for j in range(0, len(clean_hex), 64)]
        formatted = '\r\n'.join(lines).encode('latin-1')

        # Build replacement: relocated keywords + \objdata + clean hex
        kw_prefix = b''.join(relocated_kws) if relocated_kws else b''
        replacement = kw_prefix + b'\\objdata ' + formatted
        data = data[:kw_start] + replacement + data[hex_end:]

    with open(output_path, 'wb') as f:
        f.write(data)

    return stats


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
    # FIX: Use negative lookbehind to ensure we don't match standard protocols (http:// etc.)
    # We check that the character preceding the slashes is NOT a colon ':'
    unc_pattern = rb'(?<!:)(?:[\\/]{2,3})[a-zA-Z0-9\-._]+[\\/][^\s\x00\'"<>]+'

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
        # Additional validation: Check if this is just a subset of an already found URL
        start_pos = match.start()
        
        # If the preceding char is ':', it's likely a protocol we missed in lookbehind (e.g. at start of buffer)
        # or if lookbehind wasn't supported by the regex engine (re vs regex)
        if start_pos > 0 and data[start_pos-1] == ord(':'):
            continue

        # Find null terminator
        null_pos = data.find(b'\x00', start_pos)
        if null_pos > start_pos:
            unc_bytes = data[start_pos:null_pos]
        else:
            unc_bytes = match.group(0)

        unc = unc_bytes.decode('latin-1', errors='ignore')
        unc = re.sub(r'[^\x20-\x7E]+$', '', unc)
        unc = unc.rstrip(')"\'<>[]{}')
        
        # Skip if this path is already part of a found URL
        # E.g. found "http://foo.com/bar", unc is "//foo.com/bar"
        is_subset = False
        for u in urls:
            if unc in u['url'] and u['type'].startswith('ascii-'):
                is_subset = True
                break
        
        if is_subset:
            continue

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
                # Debug: Show raw bytes structure
                DEBUG_WIDE_URLS = False  # Set to True to see byte-level details
                if DEBUG_WIDE_URLS:
                    print(f"\n[DEBUG] Wide URL extraction at offset {hex(start_pos)}:", file=sys.stderr)
                    print(f"  Length prefix (4 bytes before): {data[start_pos-4:start_pos].hex() if start_pos >= 4 else 'N/A'}", file=sys.stderr)
                    print(f"  Extracted bytes ({len(wide_url_bytes)}): {wide_url_bytes[:80].hex()}{'...' if len(wide_url_bytes) > 80 else ''}", file=sys.stderr)
                    print(f"  Bytes after URL: {data[end_pos:end_pos+10].hex()}", file=sys.stderr)
                    print(f"  Method: {extraction_method}", file=sys.stderr)

                url = wide_url_bytes.decode('utf-16le', errors='ignore')

                if DEBUG_WIDE_URLS:
                    print(f"  Decoded: {repr(url)}", file=sys.stderr)

                # Clean up trailing junk
                url = re.sub(r'[^\x20-\x7E]+$', '', url)  # Remove non-printable at end
                url = url.rstrip(')"\'<>[]{}')  # Remove trailing punctuation

                # Remove trailing space followed by short garbage tokens (common padding in malware)
                # E.g., "http://foo.com/page.html e" -> "http://foo.com/page.html"
                # But preserve legitimate paths like "http://foo.com/my page.html"
                url = re.sub(r'\s+[a-zA-Z0-9]{1,2}$', '', url)
                url = url.rstrip()  # Final whitespace cleanup

                if DEBUG_WIDE_URLS:
                    print(f"  After cleanup: {repr(url)}\n", file=sys.stderr)

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


def _format_api_trace(api_calls: List[Dict]) -> str:
    """Format API calls into a concise trace string"""
    if not api_calls:
        return ""
        
    trace_parts = []
    for call in api_calls:
        api_name = call.get('api', call.get('api_name', 'unknown'))
        args = []
        
        # Handle 'args' list (from Speakeasy report)
        if 'args' in call and isinstance(call['args'], list):
            for arg_val in call['args']:
                if isinstance(arg_val, str):
                    # Check if it looks like a hex number
                    if arg_val.startswith('0x'):
                         continue # Skip raw pointers in trace to save space
                    if len(arg_val) < 100:
                        args.append(f'"{arg_val}"')
        
        # approximate args from params dict if list args missing (from hook)
        if not args and call.get('params'):
            for p_val in call['params'].values():
                 if isinstance(p_val, str) and len(p_val) < 100:
                     args.append(f'"{p_val}"')
        
        arg_str = ", ".join(args)
        trace_parts.append(f"{api_name}({arg_str})")
        
    return "\n".join(trace_parts)


def _extract_apis_from_report(report: Dict) -> List[Dict]:
    """Extract flattened API list from Speakeasy report"""
    apis = []
    if not report:
        return apis
        
    for ep in report.get('entry_points', []):
        for api in ep.get('apis', []):
            apis.append(api)
    return apis


def _analyze_rtf_objects_impl(file_path: str, emulate: bool = False, timeout: int = 10, dump: bool = False) -> List[Dict]:
    """
    Internal implementation - use analyze_rtf_objects() instead which enforces hard timeout

    Use rtfobj to extract embedded objects and analyze them for URLs

    Args:
        file_path: Path to RTF file
        emulate: If True, emulate Equation Editor shellcode
        timeout: Emulation timeout in seconds (per-file, not per-object)
    """
    results = []
    
    # --- Document-Level Scan (New) ---
    try:
        with open(file_path, 'rb') as f:
            full_data = f.read()

        # Check for truncated RTF header: {\rt but not {\rtf
        # Valid RTF starts with {\rtf1, {\rt alone is an evasion technique
        truncated_header = full_data[:5].startswith(b'{\\rt') and not full_data[:5].startswith(b'{\\rtf')

        doc_links = scan_document_body(full_data)
        if doc_links or truncated_header:
            # Create a virtual "Document Body" object to hold these findings
            doc_result = {
                'index': -1, # Special index
                'class_name': 'Document Body',
                'clsid': None,
                'clsid_desc': 'Deobfuscated Document Content',
                'raw_data_size': len(full_data),
                'urls': doc_links or [],
                'is_ole': False,
                'is_package': False
            }
            if truncated_header:
                doc_result['truncated_header'] = True
                print(f"[!] Truncated RTF header detected: {{\\rt without {{\\rtf - possible evasion", file=sys.stderr)
            results.append(doc_result)
    except Exception as e:
        print(f"[!] Error in document scanner: {e}", file=sys.stderr)

    # --- Object-Level Scan ---
    try:
        # Start per-file timeout timer
        file_start_time = time.time()

        # Read RTF file as bytes
        with open(file_path, 'rb') as f:
            rtf_data = f.read()

        # Pre-process: strip \bin runs before rtfobj parses
        # rtfobj merges \bin bytes into hex, breaking nibble alignment
        rtf_data, bin_count = strip_bin_runs(rtf_data)
        if bin_count:
            print(f"[*] Stripped {bin_count} \\bin run(s) from RTF data", file=sys.stderr)
            # Attach bin_runs stat to the Document Body result if it exists
            for r in results:
                if r.get('index') == -1:
                    r.setdefault('obfuscation', {})['bin_runs'] = bin_count
                    break

        # Pre-scan raw objdata regions for obfuscation stats BEFORE rtfobj
        # cleans the hex. rtfobj strips obfuscation internally, so we lose
        # visibility unless we scan the raw data first.
        # Also store deobfuscated hex as fallback for when rtfobj's parsing fails.
        _raw_objdata_pattern = re.compile(rb'\\objdata\s*', re.IGNORECASE)
        raw_obfuscation_stats = []
        _deobfuscated_hex_regions = []  # fallback: [(clean_hex_bytes, ...)]
        for m in _raw_objdata_pattern.finditer(rtf_data):
            region_start = m.end()
            depth = 0
            i = region_start
            while i < len(rtf_data):
                b = rtf_data[i:i+1]
                if b == b'\\' and i + 1 < len(rtf_data) and rtf_data[i+1:i+2] in (b'{', b'}', b'\\'):
                    i += 2
                    continue
                if b == b'{':
                    depth += 1
                elif b == b'}':
                    if depth == 0:
                        clean_hex, stats = deobfuscate_hex(rtf_data[region_start:i], track=True)
                        raw_obfuscation_stats.append(stats)
                        # Convert clean hex to binary for fallback
                        try:
                            import binascii
                            raw_bytes = binascii.unhexlify(clean_hex)
                            _deobfuscated_hex_regions.append(raw_bytes)
                        except Exception:
                            _deobfuscated_hex_regions.append(None)
                        break
                    depth -= 1
                i += 1

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
            if hasattr(obj, 'hexdata') and obj.hexdata:
                # hexdata is the hex string representation - we prefer this for manual deobfuscation
                # because rtfobj's oledata can be mangled by some samples
                raw_data = obj.hexdata if isinstance(obj.hexdata, bytes) else obj.hexdata.encode('latin-1')
                data_source = 'hexdata'
            elif hasattr(obj, 'oledata') and obj.oledata:
                raw_data = obj.oledata
                data_source = 'oledata'

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
                    # Use pre-scanned raw stats (rtfobj already cleaned hexdata,
                    # so scanning it finds nothing)
                    if idx < len(raw_obfuscation_stats) and raw_obfuscation_stats[idx]:
                        obj_info['obfuscation'] = raw_obfuscation_stats[idx]
                    try:
                        decoded_data = binascii.unhexlify(deobfuscated)
                    except Exception as e:
                        decoded_data = raw_data
                else:
                    # Unknown source - try to detect
                    decoded_data = raw_data

                # ==============================================================
                # Dump object if requested (BEFORE any further processing)
                # ==============================================================
                if dump:
                    dump_fname = f"object_{idx}.bin"
                    try:
                        with open(dump_fname, 'wb') as f:
                            f.write(decoded_data)
                        print(f"[*] Dumped object #{idx} to {dump_fname}", file=sys.stderr)
                    except Exception as e:
                         print(f"[!] Failed to dump object {idx}: {e}", file=sys.stderr)
                

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
                            obj_info['clsid'] = target_clsid
                            obj_info['clsid_desc'] = 'Microsoft Equation Editor 3.0 [detected from header]'

                # Try structure parsing if we have a valid target CLSID or known class name
                class_name_str = obj_info['class_name'].decode('ascii', errors='ignore').lower() if isinstance(obj_info['class_name'], bytes) else (obj_info['class_name'] or '').lower()
                should_parse = HAS_STRUCTURE_PARSERS and (
                    target_clsid or
                    class_name_str in ['package', 'ole2link']
                )

                if should_parse or 'equation' in class_name_str:
                    try:
                        parsed_obj = None
                        # Force Equation Editor parsing if class name matches or "Equation" found in prefix
                        if not parsed_obj and ("equation" in obj_info['class_name'].lower() or b"Equation" in raw_data[:256]):
                            if HAS_STRUCTURE_PARSERS:
                                # Set a fake CLSID to help with description
                                target_clsid = '0002CE02-0000-0000-C000-000000000046'
                                obj_info['clsid'] = target_clsid
                                obj_info['clsid_desc'] = CLSID_MAP.get(target_clsid, "Microsoft Equation Editor 3.0 [detected from header/class]")
                                
                                parsed_obj = parse_ole_object(target_clsid, decoded_data, emulate_shellcode=emulate, timeout=remaining_timeout)

                        clsid_to_use = target_clsid or obj_info['clsid'] or ''
                        if not parsed_obj: # Only parse if not already parsed by the fallback above
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
                                
                                # Access the raw PackageObject from the parser result
                                pkg_obj = parsed_obj.get('parsed')
                                if pkg_obj and pkg_obj.embedded_data:
                                    data = pkg_obj.embedded_data
                                    obj_info['package_file_size'] = len(data)
                                    
                                    # Calculate hashes
                                    obj_info['md5'] = hashlib.md5(data).hexdigest()
                                    obj_info['sha256'] = hashlib.sha256(data).hexdigest()
                                    
                                    # Determine filename for dumping (SHA256-based for deduplication)
                                    dump_path = f"{obj_info['sha256']}.bin"
                                    
                                    # Dump file only if it doesn't exist
                                    try:
                                        if not Path(dump_path).exists():
                                            with open(dump_path, 'wb') as f:
                                                f.write(data)
                                            print(f"[*] Extracted Package file to {dump_path} (Size: {len(data)} bytes, SHA256: {obj_info['sha256']})", file=sys.stderr)
                                        else:
                                            print(f"[*] Skipping duplicate Package file {dump_path}", file=sys.stderr)
                                            
                                        obj_info['dumped_file'] = dump_path
                                    except Exception as e:
                                        print(f"[!] Failed to dump package file: {e}", file=sys.stderr)

                            elif parsed_obj['type'] == 'OLE2Link':
                                obj_info['ole2link_url'] = parsed_obj.get('url')
                            elif parsed_obj['type'] == 'ShellExplorer':
                                obj_info['is_exploit'] = parsed_obj.get('is_exploit', False)
                                obj_info['exploit_reason'] = parsed_obj.get('exploit_reason')
                            elif parsed_obj['type'] == 'EquationEditor':
                                obj_info['equation_editor'] = True
                                obj_info['shellcode_found'] = parsed_obj.get('font_record_found', False)
                                obj_info['is_exploit'] = parsed_obj.get('is_exploit', False)
                                obj_info['exploit_reason'] = parsed_obj.get('exploit_reason')
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
                                                
                                            # Add API trace summary
                                            # Prefer report APIs as they have resolved arguments
                                            report_apis = _extract_apis_from_report(emu_res.get('report'))
                                            if report_apis:
                                                obj_info['api_trace'] = _format_api_trace(report_apis)
                                            elif emu_res.get('api_calls'):
                                                obj_info['api_trace'] = _format_api_trace(emu_res['api_calls'])

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
                        print(f"[*] Quick pattern scan found {len(quick_pattern_urls)} URL(s) before emulation: {[u['url'] for u in quick_pattern_urls]}", file=sys.stderr)
                        structure_urls.extend(quick_pattern_urls)
                        pattern_extracted_early = True

                    try:
                        try:
                            from .shellcode_emulator import emulate_shellcode, scan_shellcode
                        except ImportError:
                            from shellcode_emulator import emulate_shellcode, scan_shellcode

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
                                    
                                    # Add API trace summary
                                    # Prefer report APIs as they have resolved arguments
                                    report_apis = _extract_apis_from_report(emu_res.get('report'))
                                    if report_apis:
                                        obj_info['api_trace'] = _format_api_trace(report_apis)
                                    elif emu_res.get('api_calls'):
                                        obj_info['api_trace'] = _format_api_trace(emu_res['api_calls'])

                                    # Exploit Detection Heuristic for CVE-2018-0802/Malformed Objects
                                    if not obj_info.get('is_exploit'):
                                         # Check if this object is Equation Editor (by CLSID or class name)
                                         is_eq = False
                                         desc = str(obj_info.get('clsid_desc', '')).lower()
                                         cls_name = str(obj_info.get('class_name', '')).lower()
                                         
                                         # Debug print
                                         # print(f"DEBUG: Checking exploit object. Desc: {desc}, Class: {cls_name}", file=sys.stderr)
                                         
                                         # Check detected CLSID
                                         if 'equation' in desc:
                                             is_eq = True
                                         # Check class name
                                         elif 'equation' in cls_name:
                                             is_eq = True
                                         # Check specific CLSID manually if description failed
                                         elif obj_info.get('clsid') in ['0002CE02-0000-0000-C000-000000000046', '20E02C00-0000-0000-0C00-000000000004']:
                                             is_eq = True
                                             
                                         if is_eq:
                                              obj_info['is_exploit'] = True
                                              obj_info['exploit_reason'] = "Malformed Equation Editor Object (Likely CVE-2018-0802)"
                                              print(f"[!] POSSIBLE EXPLOIT DETECTED: {obj_info['exploit_reason']}", file=sys.stderr)

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
            valid_urls = obj_info['urls']
            # Deduplicate
            obj_info['urls'] = deduplicate_urls(valid_urls)

    return results


def _worker_analyze(file_path, emulate, timeout, result_queue, dump):
    """Worker function for multiprocessing timeout enforcement"""
    try:
        results = _analyze_rtf_objects_impl(file_path, emulate, timeout, dump)
        result_queue.put(('success', results))
    except Exception as e:
        result_queue.put(('error', str(e)))


def analyze_rtf_objects(file_path: str, emulate: bool = False, timeout: int = 10, dump: bool = False) -> List[Dict]:
    """
    Analyze RTF file for embedded objects and URLs.

    Args:
        file_path: Path to RTF file
        emulate: If True, emulate Equation Editor shellcode
        timeout: Hard timeout in seconds
        dump: If True, dump object bodies to disk

    Returns:
        List of analyzed objects with URLs
    """
    return _analyze_rtf_objects_impl(file_path, emulate, timeout, dump)


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

        if obj_info.get('truncated_header'):
            print(f"  [!] TRUNCATED HEADER: {{\\rt without {{\\rtf - evasion technique")

        if obj_info.get('is_exploit'):
            print(f"  [!] POSSIBLE EXPLOIT DETECTED: {obj_info.get('exploit_reason', 'Probable exploit payload')}")

        if obj_info['urls']:
            print(f"  URLs Found: {len(obj_info['urls'])}")
            for url_info in obj_info['urls']:
                print(f"    [{url_info['type']}] {url_info['url']}")
                if verbose:
                    print(f"      Offset: {url_info['offset']}")
            total_urls += len(obj_info['urls'])
        else:
            print(f"  URLs Found: 0")
            
        if obj_info.get('obfuscation'):
            stats = obj_info['obfuscation']
            total = sum(stats.values())
            print(f"  Obfuscation Detected: {total} artifacts")
            for technique, count in sorted(stats.items(), key=lambda x: -x[1]):
                print(f"    {technique}: {count}")

        if obj_info.get('api_trace'):
            print(f"  API Trace:")
            # Split lines and indent
            for line in obj_info['api_trace'].splitlines():
                 print(f"    {line}")

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
    parser.add_argument('--dump', action='store_true',
                       help='Dump extracted object bodies to disk (object_N.bin)')
    parser.add_argument('--deobfuscate', metavar='FILE',
                       help='Write a deobfuscated copy of the RTF to FILE')
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
            try:
                from shellcode_emulator import HAS_SPEAKEASY
                if not HAS_SPEAKEASY:
                    print(f"Error: --emulate requires speakeasy-emulator", file=sys.stderr)
                    print(f"Install with: pip install speakeasy-emulator", file=sys.stderr)
                    sys.exit(1)
            except ImportError as e:
                print(f"Error: --emulate requires speakeasy-emulator ({e})", file=sys.stderr)
                # print(f"Install with: pip install speakeasy-emulator", file=sys.stderr)
                sys.exit(1)

    # Analyze the file
    print(f"Analyzing RTF file: {args.file}")
    if args.emulate:
        print(f"Shellcode emulation: ENABLED (timeout: {args.timeout}s)")
    results = analyze_rtf_objects(args.file, emulate=args.emulate, timeout=args.timeout, dump=args.dump)

    # Print results
    print_results(results, verbose=args.verbose)

    # Write deobfuscated RTF if requested
    if args.deobfuscate:
        deobf_stats = deobfuscate_rtf_file(args.file, args.deobfuscate)
        print(f"Deobfuscated RTF written to: {args.deobfuscate}")
        if deobf_stats['header_fixed']:
            print(f"  Fixed truncated RTF header -> {{\\rtf1")
        if deobf_stats['bin_runs']:
            print(f"  Stripped {deobf_stats['bin_runs']} \\bin run(s)")
        if deobf_stats['objdata_regions']:
            print(f"  Cleaned {deobf_stats['objdata_regions']} \\objdata region(s)")

    # Export to JSON if requested
    if args.json:
        import json
        with open(args.json, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results exported to: {args.json}")


if __name__ == '__main__':
    main()

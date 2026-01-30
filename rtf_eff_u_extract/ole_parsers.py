#!/usr/bin/env python3
"""
OLE Object Binary Structure Parsers
====================================

Parsers for commonly abused OLE objects based on documented binary structures.
Similar approach to TheMissingLNK - parse based on known offsets and structure.

References:
- Package Object: https://github.com/idiom/OLEPackagerFormat
- OLE2Link: MS-OLEDS, NCC Group CVE-2017-8759 analysis
- Equation Editor: Unit42, SANS CVE-2017-11882 analysis
"""

import struct
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

# Try to import speakeasy for shellcode emulation
try:
    from .shellcode_emulator import emulate_shellcode
    HAS_EMULATOR = True
except ImportError:
    try:
        from shellcode_emulator import emulate_shellcode
        HAS_EMULATOR = True
    except ImportError:
        HAS_EMULATOR = False


@dataclass
class PackageObject:
    """Parsed OLE Package object with extracted paths/URLs"""
    header: int
    label: str
    org_path: str
    u_type: int
    data_path: str
    data_len: int
    org_path_w: Optional[str] = None
    label_w: Optional[str] = None
    def_path_w: Optional[str] = None
    embedded_data: Optional[bytes] = None

    def get_urls(self) -> List[str]:
        """Extract all potential URLs/paths from Package object"""
        urls = []
        for field in [self.org_path, self.data_path, self.org_path_w, self.def_path_w]:
            if field and ('://' in field or field.startswith('\\\\')):
                urls.append(field)
        return urls


@dataclass
class OLE2LinkObject:
    """Parsed OLE2Link/StdOleLink moniker object"""
    clsid: bytes
    moniker_length: int
    url: str

    def get_urls(self) -> List[str]:
        """Extract URL from moniker"""
        return [self.url] if self.url else []


@dataclass
class EquationEditorObject:
    """Parsed Equation Editor MTEF object with shellcode"""
    version: int
    platform: int
    product: int
    font_record_found: bool
    shellcode: Optional[bytes] = None
    shellcode_offset: Optional[int] = None
    emulation_results: Optional[Dict] = None

    def get_shellcode(self) -> Optional[bytes]:
        """Return extracted shellcode if present"""
        return self.shellcode

    def get_urls(self) -> List[str]:
        """Extract URLs from emulation results if available"""
        urls = []
        if self.emulation_results and self.emulation_results.get('urls'):
            for url_info in self.emulation_results['urls']:
                urls.append(url_info['url'])
        return urls


class PackageObjectParser:
    """Parse OLE Package objects based on binary structure"""

    @staticmethod
    def read_cstring(data: bytes, offset: int) -> Tuple[str, int]:
        """Read null-terminated ASCII string, return (string, new_offset)"""
        end = data.find(b'\x00', offset)
        if end == -1:
            return "", offset
        try:
            string = data[offset:end].decode('latin-1', errors='ignore')
            return string, end + 1
        except:
            return "", offset

    @staticmethod
    def read_wstring(data: bytes, offset: int, length: int) -> Tuple[str, int]:
        """Read length-prefixed UTF-16LE string, return (string, new_offset)"""
        if length <= 0 or offset + length > len(data):
            return "", offset
        try:
            # UTF-16LE strings end with double null (0x0000)
            string = data[offset:offset+length].decode('utf-16le', errors='ignore')
            # Remove null terminator if present
            string = string.rstrip('\x00')
            return string, offset + length
        except:
            return "", offset + length

    @staticmethod
    def parse(data: bytes) -> Optional[PackageObject]:
        """
        Parse OLE Package object binary structure.

        Structure (all integers little-endian):
        - header (4 bytes): 0x0200
        - label (null-terminated string)
        - org_path (null-terminated string)
        - u_type (8 bytes): 0x300 (embedded) or 0x100 (linked)
        - data_path_len (8 bytes)
        - data_path (null-terminated string)
        - data_len (8 bytes)
        - data (variable bytes)
        - org_path_w_len (8 bytes)
        - org_path_w (UTF-16LE string)
        - label_len (8 bytes)
        - label_w (UTF-16LE string)
        - def_path_w_len (8 bytes)
        - def_path_w (UTF-16LE string)
        """
        if len(data) < 4:
            return None

        try:
            offset = 0

            # Header (4 bytes)
            header = struct.unpack_from('<I', data, offset)[0]
            offset += 4

            # Label (null-terminated)
            label, offset = PackageObjectParser.read_cstring(data, offset)

            # Original path (null-terminated)
            org_path, offset = PackageObjectParser.read_cstring(data, offset)

            # U_type (8 bytes)
            if offset + 8 > len(data):
                return None
            u_type = struct.unpack_from('<Q', data, offset)[0]
            offset += 8

            # Data path length (8 bytes)
            if offset + 8 > len(data):
                return None
            data_path_len = struct.unpack_from('<Q', data, offset)[0]
            offset += 8

            # Data path (null-terminated)
            data_path, offset = PackageObjectParser.read_cstring(data, offset)

            # Data length (8 bytes)
            if offset + 8 > len(data):
                # Partial parse - return what we have
                return PackageObject(
                    header=header,
                    label=label,
                    org_path=org_path,
                    u_type=u_type,
                    data_path=data_path,
                    data_len=0
                )

            data_len = struct.unpack_from('<Q', data, offset)[0]
            offset += 8

            # Extract embedded data
            embedded_data = None
            if offset + data_len <= len(data):
                embedded_data = data[offset:offset + data_len]
                offset += data_len
            else:
                # Data truncated, take what we can
                embedded_data = data[offset:]
                offset = len(data)

            # Wide string fields (optional)
            org_path_w = None
            label_w = None
            def_path_w = None

            # Original path wide (8-byte length + string)
            if offset + 8 <= len(data):
                org_path_w_len = struct.unpack_from('<Q', data, offset)[0]
                offset += 8
                if org_path_w_len > 0:
                    org_path_w, offset = PackageObjectParser.read_wstring(data, offset, org_path_w_len)

            # Label wide (8-byte length + string)
            if offset + 8 <= len(data):
                label_len = struct.unpack_from('<Q', data, offset)[0]
                offset += 8
                if label_len > 0:
                    label_w, offset = PackageObjectParser.read_wstring(data, offset, label_len)

            # Default path wide (8-byte length + string)
            if offset + 8 <= len(data):
                def_path_w_len = struct.unpack_from('<Q', data, offset)[0]
                offset += 8
                if def_path_w_len > 0:
                    def_path_w, offset = PackageObjectParser.read_wstring(data, offset, def_path_w_len)

            return PackageObject(
                header=header,
                label=label,
                org_path=org_path,
                u_type=u_type,
                data_path=data_path,
                data_len=data_len,
                org_path_w=org_path_w,
                label_w=label_w,
                def_path_w=def_path_w,
                embedded_data=embedded_data
            )

        except struct.error:
            return None


class OLE2LinkParser:
    """Parse OLE2Link/StdOleLink moniker objects"""

    @staticmethod
    def parse(data: bytes) -> Optional[OLE2LinkObject]:
        """
        Parse OLE2Link object to extract URL from moniker.

        Structure (approximate offsets from NCC Group analysis):
        - CLSID appears around offset 0x450
        - Moniker data starts around 0x800
        - Length field at ~0x818 (4 bytes, little-endian)
        - URL as UTF-16LE wide string follows
        """
        if len(data) < 0x850:
            return None

        try:
            # Look for URL Moniker CLSID or common patterns
            # Scan for wide-char URLs starting with http/https/ftp/file/mhtml
            wide_patterns = [
                b'h\x00t\x00t\x00p\x00:\x00/\x00/\x00',      # http://
                b'h\x00t\x00t\x00p\x00s\x00:\x00/\x00/\x00', # https://
                b'f\x00t\x00p\x00:\x00/\x00/\x00',           # ftp://
                b'f\x00i\x00l\x00e\x00:\x00/\x00/\x00',      # file://
                b'm\x00h\x00t\x00m?\x00l\x00:\x00',          # mhtml:
            ]

            for pattern in wide_patterns:
                offset = data.find(pattern)
                if offset != -1:
                    # Extract URL using double-null terminator
                    url_start = offset
                    url_end = offset
                    while url_end < len(data) - 1:
                        if data[url_end:url_end+2] == b'\x00\x00':
                            break
                        url_end += 2

                    if url_end > url_start:
                        try:
                            url = data[url_start:url_end].decode('utf-16le', errors='ignore')

                            # Try to get length field before URL
                            moniker_length = 0
                            if url_start >= 4:
                                moniker_length = struct.unpack_from('<I', data, url_start-4)[0]

                            return OLE2LinkObject(
                                clsid=b'\x00\x03\x00\x00' + b'\x00'*12,  # StdOleLink CLSID
                                moniker_length=moniker_length,
                                url=url
                            )
                        except:
                            continue

            return None

        except:
            return None


@dataclass
class ShellExplorerLinkObject:
    """Parsed Shell.Explorer.1 link object with extracted URLs"""
    urls: List[str]
    folders: List[str]
    items: List[Dict]

    def get_urls(self) -> List[str]:
        """Extract all URLs from link"""
        return self.urls


class ShellExplorerLinkParser:
    """
    Parse Shell.Explorer.1 OLE link objects (TheMissingLNK approach)

    Shell.Explorer.1 objects contain ShellLink structures with IDLIST items.
    Based on: https://github.com/wmetcalf/TheMissingLNK
    """

    # LNK header signature (0x4C000000 = 76 bytes header size)
    LNK_HEADER_SIG = b'\x4C\x00\x00\x00'

    # Known folders GUID mapping
    KNOWN_FOLDERS = None

    @classmethod
    def _load_known_folders(cls):
        """Load known folders mapping from JSON file"""
        if cls.KNOWN_FOLDERS is not None:
            return

        try:
            import json
            from pathlib import Path

            # Look for knownfolders.json in same directory as this script
            json_path = Path(__file__).parent / 'knownfolders.json'
            if json_path.exists():
                with open(json_path, 'r') as f:
                    cls.KNOWN_FOLDERS = json.load(f)
            else:
                cls.KNOWN_FOLDERS = {}
        except:
            cls.KNOWN_FOLDERS = {}

    @staticmethod
    def _parse_guid(data: bytes) -> str:
        """Parse GUID from little-endian binary format"""
        if len(data) < 16:
            return ""

        try:
            d1 = struct.unpack('<I', data[0:4])[0]
            d2 = struct.unpack('<H', data[4:6])[0]
            d3 = struct.unpack('<H', data[6:8])[0]
            d4 = data[8:10]
            d5 = data[10:16]
            return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4.hex()}-{d5.hex()}"
        except:
            return ""

    @staticmethod
    def _extract_utf16_strings(data: bytes, min_length: int = 4) -> List[str]:
        """Extract UTF-16LE strings from binary data"""
        import re

        # Find UTF-16LE strings (printable ASCII chars with null bytes)
        pattern = rb'(?:[ -~]\x00){' + str(min_length).encode() + rb',}'
        hits = re.findall(pattern, data)

        strings = []
        for hit in hits[:100]:  # Limit to first 100 strings
            try:
                s = hit.decode('utf-16le', errors='ignore')
                if len(s) >= min_length:
                    strings.append(s)
            except:
                pass

        return strings

    @staticmethod
    def _classify_string(s: str) -> Optional[str]:
        """Classify string as URL, UNC path, or drive path"""
        s_lower = s.lower()

        if s_lower.startswith('http://') or s_lower.startswith('https://'):
            return 'url'
        elif s_lower.startswith('ftp://') or s_lower.startswith('file://'):
            return 'url'
        elif s_lower.startswith('mhtml:') or s_lower.startswith('ms-'):
            return 'url'
        elif s_lower.startswith('shell:'):
            return 'url'
        elif s.startswith('\\\\'):
            return 'unc'
        elif len(s) >= 2 and s[1] == ':':
            return 'drive_path'

        return None

    @classmethod
    def parse(cls, data: bytes) -> Optional[ShellExplorerLinkObject]:
        """
        Parse Shell.Explorer.1 link object to extract URLs.

        Structure:
        - ShellLink header at offset 0x4C in CONTENTS stream
        - Header is 0x4C (76) bytes
        - Optional IDLIST follows (variable length shell items)
        - Items contain GUIDs, paths, URLs
        """
        cls._load_known_folders()

        urls = []
        folders = []
        items = []

        try:
            # Look for LNK header signature (0x4C000000)
            lnk_pos = data.find(cls.LNK_HEADER_SIG)

            if lnk_pos >= 0:
                # Parse ShellLink header (76 bytes)
                header_start = lnk_pos

                if len(data) < header_start + 0x4C:
                    return None

                # Parse link flags at offset 0x14 from header
                link_flags = struct.unpack('<I', data[header_start + 0x14:header_start + 0x18])[0]

                # Check if IDLIST is present (bit 0 of flags)
                has_idlist = (link_flags & 0x00000001) != 0

                if has_idlist:
                    # IDLIST starts after 76-byte header
                    idlist_offset = header_start + 0x4C

                    if len(data) < idlist_offset + 2:
                        return None

                    # Parse IDLIST size (2 bytes)
                    idlist_size = struct.unpack('<H', data[idlist_offset:idlist_offset + 2])[0]

                    if idlist_size > 0 and len(data) >= idlist_offset + 2 + idlist_size:
                        idlist_data = data[idlist_offset + 2:idlist_offset + 2 + idlist_size]

                        # Parse shell items sequentially
                        ptr = 0
                        while ptr + 2 <= len(idlist_data):
                            item_size = struct.unpack('<H', idlist_data[ptr:ptr + 2])[0]

                            if item_size == 0:
                                break  # End of list

                            if ptr + item_size > len(idlist_data):
                                break

                            item_data = idlist_data[ptr:ptr + item_size]

                            # Parse item based on type (first byte after size)
                            if len(item_data) >= 3:
                                class_type = item_data[2]

                                # 0x1F = Root folder with GUID
                                if class_type == 0x1F and len(item_data) >= 18:
                                    guid = cls._parse_guid(item_data[4:20])
                                    folder_name = cls.KNOWN_FOLDERS.get(guid, guid)
                                    folders.append(folder_name)
                                    items.append({'type': 'folder', 'guid': guid, 'name': folder_name})

                                # 0x61 = URI item
                                elif class_type == 0x61:
                                    # URI items contain URLs - extract UTF-16LE strings
                                    uri_strings = cls._extract_utf16_strings(item_data, min_length=8)
                                    for s in uri_strings:
                                        if cls._classify_string(s) == 'url':
                                            if s not in urls:
                                                urls.append(s)
                                                items.append({'type': 'uri', 'url': s})

                            ptr += item_size

            # Also scan for UTF-16LE URLs in entire data
            all_strings = cls._extract_utf16_strings(data, min_length=10)
            for s in all_strings:
                if cls._classify_string(s) == 'url':
                    if s not in urls:
                        urls.append(s)

            if urls or folders or items:
                return ShellExplorerLinkObject(
                    urls=urls,
                    folders=folders,
                    items=items
                )

            return None

        except:
            return None


class ScriptParser:
    """Parse embedded scripts for URLs (VBScript, JavaScript, PowerShell, etc.)"""

    @staticmethod
    def decode_base64_urls(data: bytes) -> List[str]:
        """Find and decode base64 strings, check if they contain URLs"""
        import re
        import base64

        urls = []

        try:
            # Convert to string if bytes
            if isinstance(data, bytes):
                text = data.decode('latin-1', errors='ignore')
            else:
                text = data

            # Find base64-like strings (alphanumeric + / + = padding)
            # Minimum length 20 to avoid false positives
            base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
            candidates = re.findall(base64_pattern, text)

            for candidate in candidates[:100]:  # Limit to first 100 candidates
                try:
                    decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore')

                    # Check if decoded contains URL patterns
                    if any(proto in decoded.lower() for proto in ['http://', 'https://', 'ftp://', 'file://', 'mhtml:']):
                        # Extract the URL
                        url_match = re.search(r'(https?://[^\s\'"<>]+|ftp://[^\s\'"<>]+|file://[^\s\'"<>]+|mhtml:[^\s\'"<>]+)', decoded, re.IGNORECASE)
                        if url_match:
                            url = url_match.group(1)
                            if url not in urls:
                                urls.append(url)
                except:
                    pass

        except:
            pass

        return urls

    @staticmethod
    def extract_script_urls(data: bytes) -> List[str]:
        """Extract URLs from script content (plaintext and base64-encoded)"""
        import re

        urls = []

        try:
            # Convert to string
            if isinstance(data, bytes):
                text = data.decode('latin-1', errors='ignore')
            else:
                text = data

            # Extract plaintext URLs
            url_patterns = [
                r'https?://[^\s\'"<>]+',
                r'ftp://[^\s\'"<>]+',
                r'file://[^\s\'"<>]+',
                r'mhtml:[^\s\'"<>]+',
            ]

            for pattern in url_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for url in matches:
                    # Clean up trailing punctuation
                    url = url.rstrip('.,;:)')
                    if url not in urls:
                        urls.append(url)

            # Try base64 decoding
            b64_urls = ScriptParser.decode_base64_urls(data)
            for url in b64_urls:
                if url not in urls:
                    urls.append(url)

        except:
            pass

        return urls

    @staticmethod
    def is_script_file(data: bytes, filename: str = '') -> bool:
        """Check if data appears to be a script file"""
        # Check by filename extension
        if filename:
            script_extensions = ['.vbs', '.vbe', '.js', '.jse', '.ps1', '.sct', '.wsf',
                               '.wsh', '.hta', '.bat', '.cmd', '.vb']
            if any(filename.lower().endswith(ext) for ext in script_extensions):
                return True

        # Check for script markers in content
        try:
            text_sample = data[:1000].decode('latin-1', errors='ignore').lower()
            script_markers = ['<script', 'vbscript', 'javascript', 'powershell',
                            'wscript', 'createobject', '<?xml', '<job', '<component']
            if any(marker in text_sample for marker in script_markers):
                return True
        except:
            pass

        return False

    @staticmethod
    def parse(data: bytes, filename: str = '') -> List[str]:
        """
        Parse embedded script file for URLs.

        Args:
            data: Raw script bytes
            filename: Optional filename for type detection

        Returns:
            List of extracted URLs
        """
        if not data or len(data) == 0:
            return []

        if ScriptParser.is_script_file(data, filename):
            return ScriptParser.extract_script_urls(data)

        return []


class EquationEditorParser:
    """Parse Equation Editor MTEF objects to extract shellcode"""

    @staticmethod
    def parse(data: bytes, emulate: bool = False, timeout: int = 10) -> Optional[EquationEditorObject]:
        """
        Parse MTEF format and extract shellcode from font record overflow.

        MTEF Structure:
        - Header (5 bytes):
            - version (1 byte): 0x03
            - platform (1 byte): 0x01
            - product (1 byte): 0x01
            - product_version (1 byte): 0x03
            - product_subversion (1 byte): 0x0a
        - Records follow (variable):
            - Font record (tag 0x08):
                - typeface (1 byte)
                - style (1 byte)
                - font_name (40 bytes max - buffer overflow!)
                - overflow continues for ~8 more bytes
                - shellcode follows
        """
        if len(data) < 5:
            return None

        try:
            # Check if data contains OLE compound file (CVE-2018-0802 variant)
            # OLE header may not be at offset 0 - search for it in first 200 bytes
            ole_pos = data.find(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 0, 200)
            if ole_pos >= 0:
                # Extract OLE data starting from the header
                ole_data = data[ole_pos:]

                # Parse OLE compound file to extract MTEF stream
                try:
                    import olefile
                    import io

                    ole = olefile.OleFileIO(io.BytesIO(ole_data))

                    # Look for "Equation Native" or "oLe10NATIVE" stream (CVE-2018-0802)
                    # Case-insensitive search since stream names can vary
                    mtef_data = None
                    target_streams = [
                        ('equation native', False),
                        ('\x01equation native', False),
                        ('eqnolefilehdr', False),
                        ('\x01ole10native', True),
                        ('ole10native', True)
                    ]

                    # Get all streams and search case-insensitively
                    for entry in ole.listdir():
                        entry_name = '/'.join(entry) if isinstance(entry, list) else str(entry)
                        entry_lower = entry_name.lower()

                        for target_name, is_ole10native in target_streams:
                            if entry_lower.endswith(target_name):
                                try:
                                    stream = ole.openstream(entry)
                                    stream_data = stream.read()

                                    # Check if this is OLE10NATIVE format (has 4-byte size header)
                                    if is_ole10native:
                                        # Skip first 4 bytes (size field) and extract payload
                                        if len(stream_data) > 4:
                                            mtef_data = stream_data[4:]
                                        else:
                                            mtef_data = stream_data
                                    else:
                                        mtef_data = stream_data
                                    break
                                except:
                                    continue

                        if mtef_data:
                            break

                    # If no specific stream found, try to find MTEF header in any stream
                    if not mtef_data:
                        for entry in ole.listdir():
                            try:
                                stream = ole.openstream(entry)
                                stream_data = stream.read()
                                # Look for MTEF header (03 01 01) or record size header (1c 00)
                                mtef_pos = stream_data.find(b'\x03\x01\x01')
                                if mtef_pos == -1:
                                    mtef_pos = stream_data.find(b'\x1c\x00')
                                
                                if mtef_pos >= 0:
                                    mtef_data = stream_data[mtef_pos:]
                                    break
                            except:
                                continue

                    ole.close()

                    if mtef_data:
                        # Recursively parse the extracted MTEF data
                        return EquationEditorParser.parse(mtef_data, emulate=emulate, timeout=timeout)
                    else:
                        # OLE file but no MTEF found
                        return None

                except ImportError:
                    # olefile not installed, fall back to searching for MTEF in raw data
                    mtef_pos = data.find(b'\x03\x01\x01')
                    if mtef_pos >= 0:
                        data = data[mtef_pos:]
                    else:
                        return None
                except Exception as e:
                    # OLE parsing failed, try to find MTEF in raw data
                    mtef_pos = data.find(b'\x03\x01\x01')
                    if mtef_pos >= 0:
                        data = data[mtef_pos:]
                    else:
                        return None

            # Parse MTEF header
            version = data[0]
            platform = data[1]
            product = data[2]
            product_ver = data[3] if len(data) > 3 else 0
            product_subver = data[4] if len(data) > 4 else 0

            # Look for all Font records (tag 0x08) throughout the stream
            font_record_offsets = []
            for i in range(5, len(data) - 43): 
                if data[i] == 0x08:  # Font record tag
                    # Basic validation: typeface and style bytes follow
                    # typeface: 0..4 (usually 0x01 or 0x02)
                    # style: usually small
                    typeface = data[i+1]
                    style = data[i+2]
                    
                    # Heuristic: Valid font records usually have low typeface/style values
                    # and often have non-zero data in the font name area (i+3 onwards)
                    if typeface <= 10 and style <= 32:
                         # Check if this looks like a potential overflow (non-zero name)
                         if any(b != 0 for b in data[i+3:i+43]):
                             font_record_offsets.append(i)

            if not font_record_offsets:
                return EquationEditorObject(
                    version=version,
                    platform=platform,
                    product=product,
                    font_record_found=False
                )

            # Generate candidate shellcode offsets
            # Font record structure:
            # [tag=0x08][typeface][style][font_name (40 bytes)][overflow...][shellcode]
            candidates = []
            for offset in font_record_offsets:
                # Primary candidate: exactly after the 40-byte buffer
                # 1 (tag) + 1 (typeface) + 1 (style) + 40 (buffer) = 43
                sc_offset = offset + 43
                if sc_offset < len(data):
                    candidates.append(sc_offset)

            # Use the first one for backwards compatibility in the object
            primary_sc_offset = candidates[0] if candidates else None
            shellcode = None
            if primary_sc_offset and primary_sc_offset < len(data):
                shellcode_end = min(primary_sc_offset + 1024, len(data))
                shellcode = data[primary_sc_offset:shellcode_end]

            # Optionally emulate shellcode to extract URLs/IOCs
            emulation_results = None
            if emulate and HAS_EMULATOR and shellcode and len(shellcode) > 10:
                try:
                    from .shellcode_emulator import scan_shellcode
                    # Use a focused scan on the candidates found
                    scan_res = scan_shellcode(data, arch='x86', timeout=timeout, limit=0, priority_offsets=candidates)
                    if scan_res.get('success'):
                        emulation_results = scan_res
                except Exception as e:
                    emulation_results = {'success': False, 'error': str(e), 'urls': []}

            return EquationEditorObject(
                version=version,
                platform=platform,
                product=product,
                font_record_found=True,
                shellcode=shellcode,
                shellcode_offset=primary_sc_offset,
                emulation_results=emulation_results
            )


            return EquationEditorObject(
                version=version,
                platform=platform,
                product=product,
                font_record_found=True
            )

        except:
            return None


def parse_ole_object(clsid: str, data: bytes, emulate_shellcode: bool = False, timeout: int = 10) -> Optional[Dict]:
    """
    Parse OLE object based on CLSID and return structured data.

    Args:
        clsid: CLSID string (e.g., "F20DA720-C02F-11CE-927B-0800095AE340")
        data: Raw object bytes
        emulate_shellcode: If True, emulate Equation Editor shellcode to extract URLs
        timeout: Emulation timeout in seconds (default: 10)

    Returns:
        Dictionary with parsed data including URLs, or None if parsing failed
    """
    clsid_upper = clsid.upper()

    # Package Object
    if clsid_upper == 'F20DA720-C02F-11CE-927B-0800095AE340' or clsid_upper == '':
        parsed = PackageObjectParser.parse(data)
        if parsed:
            all_urls = list(parsed.get_urls())

            # Parse embedded script for additional URLs
            if parsed.embedded_data:
                filename = parsed.data_path or parsed.org_path or ''
                script_urls = ScriptParser.parse(parsed.embedded_data, filename)
                for url in script_urls:
                    if url not in all_urls:
                        all_urls.append(url)

            return {
                'type': 'Package',
                'parsed': parsed,
                'urls': all_urls,
                'label': parsed.label_w or parsed.label,
                'org_path': parsed.org_path_w or parsed.org_path,
                'data_path': parsed.def_path_w or parsed.data_path,
                'embedded_size': len(parsed.embedded_data) if parsed.embedded_data else 0
            }

    # StdOleLink / OLE2Link
    elif clsid_upper == '00000300-0000-0000-C000-000000000046':
        parsed = OLE2LinkParser.parse(data)
        if parsed:
            return {
                'type': 'OLE2Link',
                'parsed': parsed,
                'urls': parsed.get_urls(),
                'url': parsed.url
            }

    # Shell.Explorer.1 (Shell Folder View) - multiple CLSIDs
    elif clsid_upper in ['9BA05972-F6A8-11CF-A442-00A0C90A8F39',  # Shell Folder View
                         'EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B']:  # Shell.Explorer.1 variant
        parsed = ShellExplorerLinkParser.parse(data)
        if parsed:
            return {
                'type': 'ShellExplorer',
                'parsed': parsed,
                'urls': parsed.get_urls(),
                'folders': parsed.folders,
                'items': parsed.items
            }

    # Equation Editor 3.0 (all variants)
    elif clsid_upper in ['0002CE02-0000-0000-C000-000000000046',  # Standard
                          '0002CE03-0000-0000-C000-000000000046',  # MathType variant
                          '20E02C00-0000-0000-0C00-000000000004']:  # Obfuscated variant
        parsed = EquationEditorParser.parse(data, emulate=emulate_shellcode, timeout=timeout)
        if parsed:
            result = {
                'type': 'EquationEditor',
                'parsed': parsed,
                'shellcode': parsed.shellcode,
                'shellcode_offset': parsed.shellcode_offset,
                'font_record_found': parsed.font_record_found,
                'urls': parsed.get_urls()  # URLs from emulation
            }
            if parsed.emulation_results:
                result['emulation'] = parsed.emulation_results
            return result

    return None


if __name__ == '__main__':
    # Test parsers
    print("OLE Object Structure Parsers")
    print("=" * 60)
    print()
    print("Supported object types:")
    print("  - Package Object (F20DA720-C02F-11CE-927B-0800095AE340)")
    print("  - OLE2Link/StdOleLink (00000300-0000-0000-C000-000000000046)")
    print("  - Equation Editor 3.0 (0002CE02-0000-0000-C000-000000000046)")
    print()
    print("Import this module to use the parsers:")
    print("  from ole_parsers import parse_ole_object")

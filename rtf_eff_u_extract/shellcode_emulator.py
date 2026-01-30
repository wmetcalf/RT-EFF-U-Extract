#!/usr/bin/env python3
"""
Shellcode Emulator using Speakeasy
===================================

Emulates Windows shellcode to extract URLs and IOCs without execution.
Uses Mandiant's Speakeasy emulator (cross-platform, runs on Linux/macOS).

Installation:
    pip install speakeasy-emulator

Usage:
    from shellcode_emulator import emulate_shellcode

    results = emulate_shellcode(shellcode_bytes, timeout=10)
    print(results['urls'])
    print(results['api_calls'])
"""

import sys
import signal
import multiprocessing
from typing import Dict, List, Optional

# Try to import speakeasy
try:
    import speakeasy
    from speakeasy.winenv import arch
    HAS_SPEAKEASY = True
except ImportError:
    HAS_SPEAKEASY = False


class TimeoutError(Exception):
    """Emulation timeout exception"""
    pass


def timeout_handler(signum, frame):
    """Signal handler for timeout"""
    raise TimeoutError("Emulation timeout")


class ShellcodeEmulator:
    """Emulate shellcode using Speakeasy to extract IOCs"""

    def __init__(self, arch='x86', timeout=10):
        """
        Initialize shellcode emulator.

        Args:
            arch: Architecture ('x86' or 'x64')
            timeout: Maximum emulation time in seconds
        """
        if not HAS_SPEAKEASY:
            raise ImportError("speakeasy-emulator not installed. Install with: pip install speakeasy-emulator")

        self.arch = arch
        self.timeout = timeout
        self.urls = []
        self.api_calls = []
        self.network_events = []
        self.file_operations = []
        self.process_events = []
        self.registry_events = []
        self.error = None

    def _api_hook(self, emu, api_name, func, params):
        """Hook API calls to extract IOCs"""

        # Record all API calls
        call_info = {
            'api': api_name,
            'params': {}
        }

        # Extract parameters
        for param_name, param_value in params.items():
            call_info['params'][param_name] = param_value

        self.api_calls.append(call_info)

        # Extract URLs from specific API calls
        if api_name in ['URLDownloadToFileA', 'URLDownloadToFileW']:
            # URLDownloadToFileA(pCaller, szURL, szFileName, dwReserved, lpfnCB)
            url = params.get('szURL', '')
            if url and isinstance(url, (str, bytes)):
                if isinstance(url, bytes):
                    url = url.decode('utf-8', errors='ignore')
                self.urls.append({
                    'url': url,
                    'source': 'URLDownloadToFile',
                    'destination': params.get('szFileName', '')
                })
                self.network_events.append({
                    'type': 'download',
                    'url': url,
                    'destination': params.get('szFileName', '')
                })

        elif api_name in ['InternetOpenUrlA', 'InternetOpenUrlW']:
            url = params.get('lpszUrl', '')
            if url and isinstance(url, (str, bytes)):
                if isinstance(url, bytes):
                    url = url.decode('utf-8', errors='ignore')
                self.urls.append({
                    'url': url,
                    'source': 'InternetOpenUrl'
                })
                self.network_events.append({
                    'type': 'web_request',
                    'url': url
                })

        elif api_name in ['WinExec', 'ShellExecuteA', 'ShellExecuteW', 'ShellExecuteExA', 'ShellExecuteExW']:
            # Command execution
            cmd = params.get('lpFile', params.get('lpCommandLine', ''))
            if cmd and isinstance(cmd, (str, bytes)):
                if isinstance(cmd, bytes):
                    cmd = cmd.decode('utf-8', errors='ignore')
                self.process_events.append({
                    'type': 'execute',
                    'command': cmd,
                    'api': api_name
                })

        elif api_name in ['CreateProcessA', 'CreateProcessW']:
            app = params.get('lpApplicationName', '')
            cmdline = params.get('lpCommandLine', '')
            if isinstance(app, bytes):
                app = app.decode('utf-8', errors='ignore')
            if isinstance(cmdline, bytes):
                cmdline = cmdline.decode('utf-8', errors='ignore')

            self.process_events.append({
                'type': 'create_process',
                'application': app,
                'command_line': cmdline
            })

        elif api_name in ['CreateFileA', 'CreateFileW', 'WriteFile', 'CopyFileA', 'CopyFileW']:
            # File operations
            filename = params.get('lpFileName', params.get('lpExistingFileName', ''))
            if filename and isinstance(filename, (str, bytes)):
                if isinstance(filename, bytes):
                    filename = filename.decode('utf-8', errors='ignore')
                self.file_operations.append({
                    'type': api_name,
                    'path': filename
                })

        elif api_name in ['RegOpenKeyA', 'RegOpenKeyW', 'RegSetValueA', 'RegSetValueW']:
            # Registry operations
            key = params.get('lpSubKey', params.get('lpKey', ''))
            if key and isinstance(key, (str, bytes)):
                if isinstance(key, bytes):
                    key = key.decode('utf-8', errors='ignore')
                self.registry_events.append({
                    'type': api_name,
                    'key': key,
                    'value': params.get('lpValueName', ''),
                    'data': params.get('lpData', '')
                })

    def emulate(self, shellcode: bytes) -> Dict:
        """
        Emulate shellcode and extract IOCs.

        Args:
            shellcode: Raw shellcode bytes

        Returns:
            Dictionary with extracted IOCs:
            {
                'success': bool,
                'urls': list,
                'api_calls': list,
                'network_events': list,
                'file_operations': list,
                'process_events': list,
                'registry_events': list,
                'report': dict,
                'error': str (if failed)
            }
        """
        if not HAS_SPEAKEASY:
            return {
                'success': False,
                'error': 'speakeasy-emulator not installed',
                'urls': [],
                'api_calls': [],
                'network_events': [],
                'file_operations': [],
                'process_events': [],
                'registry_events': []
            }

        try:
        # Set up timeout alarm (Unix only) - DISABLED: Using code_hook based timeout
        # old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        # signal.alarm(self.timeout)

            try:
                # Create emulator instance
                emu = speakeasy.Speakeasy()

                # Determine architecture
                arch_type = arch.ARCH_X86
                if self.arch == 'x64':
                    arch_type = arch.ARCH_AMD64

                # Pattern-based entry point scanning
                patterns = [
                    (b'\xe8\x1f\x00\x00\x00', "LCG_SETUP"),      # e8 1f 00 00 00 (Call $+1F)
                    (b'\xd9\x74\x24', "FNSTENV_GETEIP"),         # d9 74 24 (GetEIP)
                    (b'\xe8\x00\x00\x00\x00', "CALL_PLUS_5"),    # e8 00 00 00 00
                    (b'\xdd\x34\x24', "FNSAVE_GETEIP")           # dd 34 24
                ]

                offsets_to_try = [0] # Always try 0

                # Find all pattern occurrences
                for pattern, name in patterns:
                    start = 0
                    while True:
                        idx = shellcode.find(pattern, start)
                        if idx == -1:
                            break
                        if idx not in offsets_to_try:
                            offsets_to_try.append(idx)
                        start = idx + 1

                best_result = None

                for offset in offsets_to_try:
                    # Reset hooks and error for each attempt
                    self.error = None
                    self.urls = []
                    self.api_calls = []
                    self.network_events = []
                    self.file_operations = []
                    self.process_events = []
                    self.registry_events = []

                    try:
                        # Fresh emulator instance for each attempt
                        emu = speakeasy.Speakeasy()
                        emu.add_api_hook(self._api_hook, '*')


                        # Decryption loop hook - increased limit for LCG
                        import time
                        start_time = time.time()
                        ctx = {'insn_count': 0}
                        def code_hook(emu, addr, size, c):
                            ctx['insn_count'] += 1
                            if ctx['insn_count'] > 50000000: # 50M instruction limit
                                 # print(f"DEBUG: Instruction limit reached at address 0x{addr:x}")
                                 emu.stop()
                            
                            # Check time every 1000 instructions to avoid syscall overhead
                            if ctx['insn_count'] % 1000 == 0:
                                if time.time() - start_time > self.timeout:
                                    self.error = "Emulation timeout"
                                    emu.stop()
                        emu.add_code_hook(code_hook)

                        # STRATEGY CHANGE: Slice shellcode to force execution at offset 0
                        # This avoids "Invalid shellcode address" errors when starting in middle of blob
                        sliced_data = shellcode[offset:]

                        # Determine load mode
                        sc_addr = emu.load_shellcode(None, arch_type, data=sliced_data)

                        emu.run_shellcode(sc_addr) # Run from start of slice

                    except Exception as e:
                        # Check for timeout
                        if "timeout" in str(e).lower() or isinstance(e, TimeoutError):
                             self.error = "Emulation timeout"
                        else:
                             self.error = str(e)

                    # Check results
                    current_result = {
                        'success': True if not self.error else False,
                        'error': self.error,
                        'urls': self.urls,
                        'api_calls': self.api_calls,
                        'network_events': self.network_events,
                        'file_operations': self.file_operations,
                        'process_events': self.process_events,
                        'registry_events': self.registry_events,
                        'report': {}
                    }

                    # Also check internal report for nested APIs (generalized_analyzer fix)
                    try:
                        report = emu.get_report()
                        current_result['report'] = report
                        for ep in report.get('entry_points', []):
                            for api in ep.get('apis', []):
                                # Add APIs from report if missed by hook
                                api_name = api.get('api_name')
                                if api_name and not any(c['api'] == api_name for c in current_result['api_calls']):
                                    current_result['api_calls'].append({'api': api_name, 'params': {}})

                                # Check args for URLs
                                for arg in api.get('args', []):
                                    if isinstance(arg, str) and ("http" in arg.lower() or "vbs" in arg.lower()):
                                        if not any(u['url'] == arg for u in current_result['urls']):
                                            current_result['urls'].append({'url': arg, 'source': 'report_arg'})

                    except:
                        pass

                    # If we found something interesting, keep it and stop scanning
                    if current_result['urls'] or len(current_result['api_calls']) > 2:
                        best_result = current_result
                        break

                if best_result:
                    return best_result

                return {
                    'success': False,
                    'error': 'No significant APIs or IOCs found after scanning offsets',
                    'urls': [], 'api_calls': [], 'network_events': [], 'file_operations': [], 'process_events': [], 'registry_events': []
                }

            except TimeoutError:
                # Timeout occurred - return partial results if any
                return {
                    'success': False,
                    'error': f'Emulation timeout after {self.timeout}s',
                    'urls': self.urls,
                    'api_calls': self.api_calls,
                    'network_events': self.network_events,
                    'file_operations': self.file_operations,
                    'process_events': self.process_events,
                    'registry_events': self.registry_events
                }
            # finally:
                # Restore old signal handler and cancel alarm
                # signal.alarm(0)
                # signal.signal(signal.SIGALRM, old_handler)

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'urls': [], 'api_calls': [], 'network_events': [], 'file_operations': [], 'process_events': [], 'registry_events': []
            }


def emulate_shellcode(shellcode: bytes, arch='x86', timeout=10) -> Dict:
    """
    Convenience function to emulate shellcode and extract IOCs.
    Uses multiprocessing-based timeout for reliable termination.

    Args:
        shellcode: Raw shellcode bytes
        arch: Architecture ('x86' or 'x64')
        timeout: Maximum emulation time in seconds

    Returns:
        Dictionary with IOCs (URLs, API calls, network events, etc.)
    """
    if not HAS_SPEAKEASY:
        return {
            'success': False,
            'error': 'speakeasy-emulator not installed. Install with: pip install speakeasy-emulator',
            'urls': [],
            'api_calls': [],
            'network_events': [],
            'file_operations': [],
            'process_events': [],
            'registry_events': []
        }

    # Use multiprocessing-based timeout instead of signal-based (which doesn't work with ctypes)
    return emulate_with_process_timeout(shellcode, arch=arch, timeout=timeout)


if __name__ == '__main__':
    if not HAS_SPEAKEASY:
        print("Error: speakeasy-emulator not installed")
        print("Install with: pip install speakeasy-emulator")
        sys.exit(1)

    if len(sys.argv) != 2:
        print("Usage: python3 shellcode_emulator.py <shellcode.bin>")
        print()
        print("Emulates Windows shellcode using Speakeasy to extract:")
        print("  - URLs (URLDownloadToFile, InternetOpenUrl, etc.)")
        print("  - API calls")
        print("  - Network events")
        print("  - File operations")
        print("  - Process execution")
        print("  - Registry modifications")
        sys.exit(1)

    import json
    from pathlib import Path

    shellcode_path = Path(sys.argv[1])
    if not shellcode_path.exists():
        print(f"Error: File not found: {shellcode_path}")
        sys.exit(1)

    print(f"Emulating shellcode: {shellcode_path}")
    print(f"{'='*80}")

    shellcode = shellcode_path.read_bytes()
    print(f"Shellcode size: {len(shellcode)} bytes")
    print()

    # Try x86 first (most common for RTF malware)
    print("Attempting x86 emulation...")
    results = emulate_shellcode(shellcode, arch='x86', timeout=10)

    print(f"{'='*80}")
    print("Emulation Results:")
    print(f"{'='*80}")
    print()

    if not results['success']:
        print(f"[!] Emulation failed: {results.get('error', 'Unknown error')}")
        print()

    # URLs
    print(f"[+] URLs Extracted: {len(results['urls'])}")
    for url_info in results['urls']:
        print(f"    [{url_info.get('source', 'unknown')}] {url_info['url']}")
        if url_info.get('destination'):
            print(f"      -> {url_info['destination']}")
    print()

    # Network events
    print(f"[+] Network Events: {len(results['network_events'])}")
    for event in results['network_events'][:10]:  # Limit output
        print(f"    [{event['type']}] {event.get('url', event)}")
    if len(results['network_events']) > 10:
        print(f"    ... ({len(results['network_events']) - 10} more)")
    print()

    # Process events
    print(f"[+] Process Events: {len(results['process_events'])}")
    for event in results['process_events'][:10]:
        print(f"    [{event['type']}] {event.get('command', event.get('command_line', event.get('application', '')))}")
    if len(results['process_events']) > 10:
        print(f"    ... ({len(results['process_events']) - 10} more)")
    print()

    # File operations
    print(f"[+] File Operations: {len(results['file_operations'])}")
    for op in results['file_operations'][:10]:
        print(f"    [{op['type']}] {op.get('path', '')}")
    if len(results['file_operations']) > 10:
        print(f"    ... ({len(results['file_operations']) - 10} more)")
    print()

    # API calls summary
    print(f"[+] Total API Calls: {len(results['api_calls'])}")
    api_counts = {}
    for call in results['api_calls']:
        api = call['api']
        api_counts[api] = api_counts.get(api, 0) + 1

    if api_counts:
        print("    Top APIs called:")
        for api, count in sorted(api_counts.items(), key=lambda x: x[1], reverse=True)[:15]:
            print(f"      {api}: {count}")
    print()

    # Save JSON
    json_path = shellcode_path.with_suffix('.emulation.json')
    with open(json_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)


def _emulate_in_process(shellcode: bytes, arch: str, result_queue: multiprocessing.Queue):
    """
    Worker function for multiprocessing-based emulation.
    Runs in separate process to allow forceful termination.
    """
    try:
        emulator = ShellcodeEmulator(arch=arch, timeout=999)  # Signal timeout disabled, process will be killed
        result = emulator.emulate(shellcode)
        result_queue.put(result)
    except Exception as e:
        result_queue.put({
            'success': False,
            'error': f'Emulation exception: {str(e)}',
            'urls': [],
            'api_calls': [],
            'network_events': [],
            'file_operations': [],
            'process_events': [],
            'registry_events': []
        })


def emulate_with_process_timeout(shellcode: bytes, arch='x86', timeout=10) -> Dict:
    """
    Emulate shellcode with process-level timeout enforcement.
    Uses multiprocessing to forcefully terminate hung emulation.

    Args:
        shellcode: Shellcode bytes to emulate
        arch: Architecture ('x86' or 'x64')
        timeout: Maximum seconds to allow emulation

    Returns:
        Dict with emulation results or timeout error
    """
    if not HAS_SPEAKEASY:
        return {
            'success': False,
            'error': 'speakeasy-emulator not installed',
            'urls': [],
            'api_calls': [],
            'network_events': [],
            'file_operations': [],
            'process_events': [],
            'registry_events': []
        }

    result_queue = multiprocessing.Queue()
    process = multiprocessing.Process(
        target=_emulate_in_process,
        args=(shellcode, arch, result_queue)
    )

    process.start()
    process.join(timeout=timeout)

    if process.is_alive():
        # Timeout - force kill the process
        process.terminate()
        process.join(timeout=1)
        if process.is_alive():
            process.kill()
            process.join()

        return {
            'success': False,
            'error': f'Emulation timeout after {timeout}s (process killed)',
            'urls': [],
            'api_calls': [],
            'network_events': [],
            'file_operations': [],
            'process_events': [],
            'registry_events': []
        }

    # Process completed - get result
    if not result_queue.empty():
        return result_queue.get()
    else:
        return {
            'success': False,
            'error': 'Emulation process exited without result',
            'urls': [],
            'api_calls': [],
            'network_events': [],
            'file_operations': [],
            'process_events': [],
            'registry_events': []
        }


def find_shellcode_candidates(data: bytes, max_candidates=50) -> list:
    """
    Use heuristics to find likely shellcode entry points instead of brute-force scanning.

    Returns list of (offset, confidence_score) tuples sorted by confidence.
    """
    candidates = []

    # Heuristic 1: NOP sleds (0x90) - shellcode often starts after NOP padding
    i = 0
    while i < len(data) - 16:
        # Look for runs of NOPs (at least 4 in a row)
        if data[i:i+4] == b'\x90' * 4:
            nop_start = i
            while i < len(data) and data[i] == 0x90:
                i += 1
            nop_len = i - nop_start
            if nop_len >= 4:
                # Shellcode likely starts right after NOP sled
                candidates.append((i, 90 + min(nop_len, 10)))  # Higher confidence for longer sleds
        i += 1

    # Heuristic 2: Common x86 opcodes that start shellcode
    # PUSH/POP (0x50-0x5F), MOV (0x88-0x8B, 0xB0-0xBF), CALL (0xE8), JMP (0xE9, 0xEB)
    common_opcodes = {0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,  # PUSH
                      0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,  # POP
                      0xE8, 0xE9, 0xEB,  # CALL/JMP
                      0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF}  # MOV immediate

    for i in range(0, min(len(data) - 32, 512)):  # Only check first 512 bytes
        if data[i] in common_opcodes:
            # Check if followed by more valid instructions
            valid_run = 1
            for j in range(i+1, min(i+8, len(data))):
                if data[j] in common_opcodes or data[j] == 0x90:
                    valid_run += 1
            if valid_run >= 3:
                candidates.append((i, 70 + valid_run * 2))

    # Heuristic 4: MTEF structure parsing (CVE-2017-11882 / CVE-2018-0802)
    # Search for Font Record tag (0x08) and MTEF signatures
    if len(data) >= 50:
        # Search for Font Record tags (0x08)
        for i in range(len(data) - 43):
            if data[i] == 0x08:
                # Potential font record validation
                typeface = data[i+1]
                style = data[i+2]
                if typeface <= 10 and style <= 32:
                    if any(b != 0 for b in data[i+3:i+43]):
                        sc_offset = i + 43
                        if sc_offset < len(data):
                            candidates.append((sc_offset, 98))
                            candidates.append((sc_offset+1, 97))

    # Heuristic 5: Known MTEF font table overflow offsets (common patterns)
    # These are specific relative offsets observed across different variant samples
    # We give these absolute top priority (100)
    mtef_offsets = [0x11, 0x12, 0x83c, 0x844, 0x898]
    for off in mtef_offsets:
        if off < len(data):
            candidates.append((off, 100))  # Maximum confidence

    # Heuristic 6: Exhaustive 0x800-0x8FF range coverage (Shellcode "Sweet Spot")
    # Many Equation Editor exploits land in this range.
    for off in range(0x800, min(0x900, len(data)), 4):
         if off not in [c[0] for c in candidates]:
             candidates.append((off, 95))  # High confidence


    # Heuristic 5: Aligned boundaries (4, 8, 16-byte aligned)
    for off in [0, 4, 8, 12, 16, 32, 64, 68, 256, 288]:
        if off < len(data) and off not in [c[0] for c in candidates]:
            candidates.append((off, 60))

    # Sort by confidence (descending) and remove duplicates
    seen = set()
    unique_candidates = []
    for off, conf in sorted(candidates, key=lambda x: (-x[1], x[0])):
        if off not in seen:
            seen.add(off)
            unique_candidates.append(off)
            if len(unique_candidates) >= max_candidates:
                break

    return unique_candidates


def _worker_scan_offset(args):
    """Worker function for parallel scanning"""
    shellcode, offset, arch, timeout = args
    try:
        sliced_data = shellcode[offset:]
        if len(sliced_data) < 32:
            return None
            
        # Run emulation DIRECTLY in this worker process
        # Do NOT use emulate_with_process_timeout as we are already a daemon process
        emulator = ShellcodeEmulator(timeout=timeout, arch=arch)
        res = emulator.emulate(sliced_data)
        
        # Success case
        if res['success'] and (res['urls'] or len(res['api_calls']) >= 3):
            res['scan_offset'] = offset
            return res
            
        # Partial execution case (Timeouts or Crashes with API calls)
        is_timeout = 'timeout' in res.get('error', '').lower()
        has_apis = len(res.get('api_calls', [])) > 0
        
        if is_timeout or has_apis:
            return {
                'success': False, 
                'scan_offset': offset, 
                'note': 'timeout' if is_timeout else 'partial',
                'api_calls': res.get('api_calls', []),
                'error': res.get('error', '')
            }
            
        # DEBUG: Print error for specific offset if totally failed
        if offset == 12288: # 0x3000
             print(f"[DEBUG] Offset 0x3000 failed: {res.get('error')}", file=sys.stderr)
            
    except Exception as e:
        # Print actual exception to help debugging
        # print(f"Worker Error: {e}", file=sys.stderr)
        pass
    return None

def scan_shellcode(shellcode: bytes, arch='x86', stride=1, timeout=10, limit=0, workers=None, priority_offsets=None) -> Dict:
    """
    Scan for shellcode entry points using a sliding window with priority offsets.
    Uses multiprocessing for speed.

    Args:
        shellcode: Raw bytes to scan
        arch: Architecture
        stride: Step size for full scan
        timeout: Timeout per attempt
        limit: Max bytes to scan (0 = all)
        workers: Number of processes (default: cpu_count)

    Returns:
        Best extraction result found, or empty failure result.
    """
    if not HAS_SPEAKEASY:
        return {
            'success': False,
            'error': 'speakeasy-emulator not installed',
            'urls': [], 'api_calls': [], 'network_events': [],
            'file_operations': [], 'process_events': [], 'registry_events': []
        }

    size = len(shellcode)
    if limit > 0:
        size = min(size, limit)

    # Use heuristics to find likely shellcode entry points
    print(f"[DEBUG] Using heuristics to find shellcode candidates...", file=sys.stderr)
    heuristic_offsets = find_shellcode_candidates(shellcode, max_candidates=50)
    
    # Merge external priority offsets if provided
    if priority_offsets:
        # Put external ones first
        merged_offsets = []
        seen = set()
        for off in priority_offsets:
            if off < size and off not in seen:
                merged_offsets.append(off)
                seen.add(off)
        for off in heuristic_offsets:
            if off not in seen:
                merged_offsets.append(off)
                seen.add(off)
        priority_offsets = merged_offsets
    else:
        priority_offsets = heuristic_offsets

    print(f"[DEBUG] Final priority list: {[hex(x) for x in priority_offsets[:10]]}", file=sys.stderr)

    # Try heuristic-found offsets first (Sequential is fine for < 50 items)
    for offset in priority_offsets:
        res = _worker_scan_offset((shellcode, offset, arch, min(10, timeout)))
        if res and res.get('success'):
            print(f"[DEBUG] Found IOCs at priority offset 0x{offset:x} ({offset})", file=sys.stderr)
            return res

    # Exhaustive Fallback: Parallelized
    print(f"[DEBUG] Heuristics failed. Falling back to exhaustive sliding window scan (stride={stride}, parallel)...", file=sys.stderr)
    
    tasks = []
    checked_offsets = set(priority_offsets)
    
    for offset in range(0, size, stride):
        if offset in checked_offsets:
            continue
        tasks.append((shellcode, offset, arch, timeout))
        
    if workers is None:
        try:
            workers = multiprocessing.cpu_count()
        except:
            workers = 4
            
    # Initializer to ignore SIGINT so main process handles it
    original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
    pool = multiprocessing.Pool(workers)
    signal.signal(signal.SIGINT, original_sigint_handler)
    
    best_result = None
    timeout_offsets = []
    partial_results = []

    try:
        # Use imap_unordered to return as soon as we find something
        results_count = 0
        for result in pool.imap_unordered(_worker_scan_offset, tasks, chunksize=16):
            results_count += 1
            if result:
                if result.get('success'):
                    # FOUND IT!
                    pool.terminate()
                    return result
                    
                if result.get('note') == 'timeout':
                    timeout_offsets.append(result['scan_offset'])
                    
                elif result.get('note') == 'partial':
                    # Partial means we saw API calls but no URL or success flag
                    partial_results.append(result)
                    print(f"[DEBUG] Partial match at 0x{result['scan_offset']:x}: {len(result['api_calls'])} APIs", file=sys.stderr)
                    
    except KeyboardInterrupt:
        pool.terminate()
        pool.join()
        raise
        
    pool.close()
    pool.join()
    print(f"[DEBUG] Parallel scan finished. Processed {results_count} tasks.", file=sys.stderr)
    
    # Priority 1: Timeouts (loops often indicate shellcode start)
    if timeout_offsets:
         best_off = min(timeout_offsets)
         print(f"[DEBUG] Scan found {len(timeout_offsets)} timeout(s). Attempting deep emulation on best candidate 0x{best_off:x}...", file=sys.stderr)
         try:
            sliced_data = shellcode[best_off:]
            res = emulate_with_process_timeout(sliced_data, arch=arch, timeout=60)
            if res['success'] and (res['urls'] or len(res['api_calls']) > 0):
                res['scan_offset'] = best_off
                print(f"[DEBUG] Deep emulation SUCCESS at 0x{best_off:x}!", file=sys.stderr)
                return res
         except Exception:
             pass

    # Priority 2: Partial matches (executed code but maybe obfuscated URL)
    if partial_results:
        # Sort by number of API calls
        partial_results.sort(key=lambda x: len(x['api_calls']), reverse=True)
        best_partial = partial_results[0]
        print(f"[DEBUG] No full success, but found {len(partial_results)} partial executions. Returning best at 0x{best_partial['scan_offset']:x}", file=sys.stderr)
        
        # We return this as a success so the tool reports it
        best_partial['success'] = True
        return best_partial

    return {
        'success': False,
        'error': 'No significant IOCs found (checked heuristics + exhaustive)',
        'urls': [], 'api_calls': [], 'network_events': [],
        'file_operations': [], 'process_events': [], 'registry_events': []
    }


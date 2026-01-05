#!/usr/bin/env python3
"""
click_modbus_scanner.py - Query CLICK PLC for Modbus coils and register values.

Scans AutomationDirect CLICK PLCs via Modbus TCP to read coil and register values.
Designed for ICS/OT cybersecurity students and assessment personnel conducting
authorized testing.

Author:  Don C. Weber (cutaway)
Repository: https://github.com/cutaway-security/clickplc_modbus
"""

import sys
import argparse
import struct
import time
import csv
import re
import os
from datetime import datetime
from dataclasses import dataclass
from typing import Optional, Any, Dict, List, Tuple, Union

# =============================================================================
# Section: Imports and Dependency Check
# =============================================================================

PYMODBUS_AVAILABLE = False
try:
    from pymodbus.client import ModbusTcpClient
    from pymodbus.exceptions import ModbusException, ConnectionException
    PYMODBUS_AVAILABLE = True
except ImportError:
    pass


def check_dependencies() -> bool:
    """Check if required dependencies are available."""
    if not PYMODBUS_AVAILABLE:
        print("Error: PyModbus library not found.")
        print("")
        print("Install with: pip install pymodbus")
        print("Or: pip install -r requirements.txt")
        print("")
        print("PyModbus 3.x is required. Do not use version 2.x.")
        return False
    return True


# =============================================================================
# Section: Constants
# =============================================================================

# Default configuration values
DEFAULT_PORT = 502
DEFAULT_TIMEOUT = 5  # seconds
DEFAULT_RETRIES = 3

# Modbus function codes
FC_READ_COILS = 1
FC_READ_DISCRETE_INPUTS = 2
FC_READ_HOLDING_REGISTERS = 3
FC_READ_INPUT_REGISTERS = 4

# Data format identifiers
FMT_BOOL = "bool"
FMT_INT16 = "int16"
FMT_INT32 = "int32"
FMT_FLOAT = "float"
FMT_HEX = "hex"

# Rate limiting presets (delay in seconds between requests)
RATE_PRESETS: Dict[str, float] = {
    "normal": 0.05,    # 50ms - Local network, modern PLC
    "moderate": 0.20,  # 200ms - Shared network, older PLC
    "slow": 0.50,      # 500ms - WAN connection, sensitive environment
}


# =============================================================================
# Section: Data Structures
# =============================================================================

@dataclass
class AddressType:
    """Definition of a CLICK PLC address type."""
    name: str           # e.g., "DS", "DF", "X0"
    description: str    # e.g., "Data Register (INT16)"
    start_address: int  # Modbus start address (0-based, hex value)
    count: int          # Number of addresses in range
    function_code: int  # 1, 2, 3, or 4
    word_size: int      # 1 or 2 (for registers); 1 for coils
    data_format: str    # "bool", "int16", "int32", "float", "hex"


@dataclass
class ScanResult:
    """Result of scanning a single address."""
    address_type: str       # e.g., "DS"
    click_address: str      # e.g., "DS1"
    modbus_hex: str         # e.g., "0x0000"
    modbus_984: str         # e.g., "400001"
    raw_value: int          # Raw register/coil value
    converted_value: Any    # Formatted based on data type
    nickname: str           # From CSV config, or empty string


@dataclass
class ConfigEntry:
    """Entry from CLICK CSV configuration file."""
    click_address: str      # e.g., "X001", "DS3", "DF5"
    address_type: str       # e.g., "X0", "DS", "DF" (derived from click_address)
    data_type: str          # BIT, INT, INT2, FLOAT
    modbus_address: int     # 0-based Modbus address
    nickname: str           # Tag name from CSV


# CLICK PLC Address Type Definitions
# Based on CLICK PLC User Manual and ARCHITECTURE.md
CLICK_ADDRESS_TYPES: Dict[str, AddressType] = {
    # Priority 1: Physical I/O (Discrete Inputs - FC 02)
    "X0": AddressType("X0", "CPU Input Points", 0x0000, 36, FC_READ_DISCRETE_INPUTS, 1, FMT_BOOL),
    "X1": AddressType("X1", "Module 1 Input Points", 0x0020, 16, FC_READ_DISCRETE_INPUTS, 1, FMT_BOOL),
    "X2": AddressType("X2", "Module 2 Input Points", 0x0040, 16, FC_READ_DISCRETE_INPUTS, 1, FMT_BOOL),
    "X3": AddressType("X3", "Module 3 Input Points", 0x0060, 16, FC_READ_DISCRETE_INPUTS, 1, FMT_BOOL),
    "X4": AddressType("X4", "Module 4 Input Points", 0x0080, 16, FC_READ_DISCRETE_INPUTS, 1, FMT_BOOL),
    "X5": AddressType("X5", "Module 5 Input Points", 0x00A0, 16, FC_READ_DISCRETE_INPUTS, 1, FMT_BOOL),
    "X6": AddressType("X6", "Module 6 Input Points", 0x00C0, 16, FC_READ_DISCRETE_INPUTS, 1, FMT_BOOL),
    "X7": AddressType("X7", "Module 7 Input Points", 0x00E0, 16, FC_READ_DISCRETE_INPUTS, 1, FMT_BOOL),
    "X8": AddressType("X8", "Module 8 Input Points", 0x0100, 16, FC_READ_DISCRETE_INPUTS, 1, FMT_BOOL),

    # Priority 1: Physical I/O (Coils - FC 01)
    "Y0": AddressType("Y0", "CPU Output Points", 0x2000, 36, FC_READ_COILS, 1, FMT_BOOL),
    "Y1": AddressType("Y1", "Module 1 Output Points", 0x2020, 16, FC_READ_COILS, 1, FMT_BOOL),
    "Y2": AddressType("Y2", "Module 2 Output Points", 0x2040, 16, FC_READ_COILS, 1, FMT_BOOL),
    "Y3": AddressType("Y3", "Module 3 Output Points", 0x2060, 16, FC_READ_COILS, 1, FMT_BOOL),
    "Y4": AddressType("Y4", "Module 4 Output Points", 0x2080, 16, FC_READ_COILS, 1, FMT_BOOL),
    "Y5": AddressType("Y5", "Module 5 Output Points", 0x20A0, 16, FC_READ_COILS, 1, FMT_BOOL),
    "Y6": AddressType("Y6", "Module 6 Output Points", 0x20C0, 16, FC_READ_COILS, 1, FMT_BOOL),
    "Y7": AddressType("Y7", "Module 7 Output Points", 0x20E0, 16, FC_READ_COILS, 1, FMT_BOOL),
    "Y8": AddressType("Y8", "Module 8 Output Points", 0x2100, 16, FC_READ_COILS, 1, FMT_BOOL),

    # Priority 2: Control Logic (Coils - FC 01)
    "C": AddressType("C", "Control Relays", 0x4000, 2000, FC_READ_COILS, 1, FMT_BOOL),
    "T": AddressType("T", "Timer Status", 0xB000, 500, FC_READ_COILS, 1, FMT_BOOL),
    "CT": AddressType("CT", "Counter Status", 0xC000, 250, FC_READ_COILS, 1, FMT_BOOL),
    "SC": AddressType("SC", "System Control Relays", 0xF000, 1000, FC_READ_COILS, 1, FMT_BOOL),

    # Priority 3: Data Registers (Holding Registers - FC 03)
    "DS": AddressType("DS", "Data Register (INT16)", 0x0000, 4500, FC_READ_HOLDING_REGISTERS, 1, FMT_INT16),
    "DD": AddressType("DD", "Data Register (INT32)", 0x4000, 1000, FC_READ_HOLDING_REGISTERS, 2, FMT_INT32),
    "DH": AddressType("DH", "Data Register (HEX)", 0x6000, 500, FC_READ_HOLDING_REGISTERS, 2, FMT_HEX),
    "DF": AddressType("DF", "Data Register (FLOAT)", 0x7000, 500, FC_READ_HOLDING_REGISTERS, 2, FMT_FLOAT),

    # Priority 4: Timer/Counter Registers (Holding Registers - FC 03)
    "TD": AddressType("TD", "Timer Data", 0xB000, 500, FC_READ_HOLDING_REGISTERS, 1, FMT_INT16),
    "CTD": AddressType("CTD", "Counter Data", 0xC000, 250, FC_READ_HOLDING_REGISTERS, 2, FMT_INT32),

    # Priority 5: System and I/O Registers
    "SD": AddressType("SD", "System Data Register", 0xF000, 1000, FC_READ_HOLDING_REGISTERS, 1, FMT_INT16),
    "XD": AddressType("XD", "Input Register", 0xE000, 9, FC_READ_INPUT_REGISTERS, 2, FMT_INT32),
    "YD": AddressType("YD", "Output Register", 0xE200, 9, FC_READ_HOLDING_REGISTERS, 2, FMT_INT32),
    "TXT": AddressType("TXT", "Text Data", 0x9000, 1000, FC_READ_HOLDING_REGISTERS, 2, FMT_HEX),
}

# Common address types for default scanning (Standard set)
# Covers physical I/O + control relays + common data registers
COMMON_TYPES: List[str] = ["X0", "Y0", "C", "DS", "DD", "DF"]

# All available type names for validation
ALL_TYPE_NAMES: List[str] = list(CLICK_ADDRESS_TYPES.keys())


# =============================================================================
# Section: CSV Parsing
# =============================================================================

def derive_address_type(click_address: str) -> str:
    """
    Derive the address type from a CLICK address string.

    Args:
        click_address: CLICK address like "X001", "DS3", "DF5", "C32"

    Returns:
        Address type name like "X0", "DS", "DF", "C"
    """
    # Pattern to match address type prefix and optional module number
    # X001 -> X0, X121 -> X1, Y001 -> Y0, Y221 -> Y2
    # DS1 -> DS, DD3 -> DD, DF5 -> DF, C2 -> C, TD2 -> TD, CTD1 -> CTD
    addr_upper = click_address.upper()

    # Handle X and Y types with module numbers (X0-X8, Y0-Y8)
    # X001-X036 = X0, X101-X116 = X1, etc.
    # Y001-Y036 = Y0, Y101-Y116 = Y1, etc.
    if addr_upper.startswith('X') or addr_upper.startswith('Y'):
        match = re.match(r'^([XY])(\d+)$', addr_upper)
        if match:
            prefix = match.group(1)
            num = int(match.group(2))
            # Determine module based on address range
            # Module 0 (CPU): 1-36, Module 1-8: 101-116, 201-216, etc.
            if num <= 36:
                return f"{prefix}0"
            else:
                module = (num // 100)
                if 1 <= module <= 8:
                    return f"{prefix}{module}"
        return f"{addr_upper[0]}0"  # Default to module 0

    # Handle other types: CTD must come before CT, TD, etc.
    for prefix in ["CTD", "CT", "TD", "TXT", "SC", "SD", "XD", "YD", "DD", "DH", "DF", "DS", "C", "T"]:
        if addr_upper.startswith(prefix):
            return prefix

    # Fallback - return the alphabetic prefix
    match = re.match(r'^([A-Z]+)', addr_upper)
    if match:
        return match.group(1)

    return ""


def parse_modbus_address_hex(addr_str: str) -> int:
    """
    Parse a HEX format Modbus address (e.g., "0000h", "4001h").

    Args:
        addr_str: Address string with 'h' suffix

    Returns:
        Integer Modbus address (0-based)
    """
    # Remove 'h' suffix and parse as hex
    clean = addr_str.strip().lower().rstrip('h')
    return int(clean, 16)


def parse_modbus_address_984(addr_str: str, function_code: str) -> int:
    """
    Parse a 984 format Modbus address to 0-based address.

    The 984 format encodes function code in the address:
    - 0xxxxx or 00xxxx: Coils (FC 01)
    - 1xxxxx: Discrete Inputs (FC 02)
    - 3xxxxx: Input Registers (FC 04)
    - 4xxxxx: Holding Registers (FC 03)

    Note: CLICK uses non-standard 984 addresses for some coil types.

    Args:
        addr_str: 984 format address string
        function_code: FC string from CSV (e.g., "FC=02", "FC=01,05,15")

    Returns:
        Integer Modbus address (0-based)
    """
    addr_984 = int(addr_str.strip())

    # Extract primary function code from string like "FC=02" or "FC=01,05,15"
    fc_match = re.search(r'FC=(\d+)', function_code)
    if not fc_match:
        # Fallback: guess from 984 address range
        if addr_984 >= 400001:
            return addr_984 - 400001
        elif addr_984 >= 300001:
            return addr_984 - 300001
        elif addr_984 >= 100001:
            return addr_984 - 100001
        else:
            return addr_984 - 1

    fc = int(fc_match.group(1))

    # Standard 984 conversion based on function code
    if fc == 2:  # Discrete Inputs
        if addr_984 >= 100001:
            return addr_984 - 100001
        return addr_984 - 1
    elif fc == 4:  # Input Registers
        if addr_984 >= 300001:
            return addr_984 - 300001
        return addr_984 - 1
    elif fc == 3:  # Holding Registers
        if addr_984 >= 400001:
            return addr_984 - 400001
        return addr_984 - 1
    elif fc == 1:  # Coils
        # CLICK uses non-standard addressing for coils
        # Y001 at 984=8193 means offset from 0x2000 base
        # C2 at 984=16386 means offset from 0x4000 base
        if addr_984 >= 16385:  # C relays at 0x4000+
            return addr_984 - 16385 + 0x4000
        elif addr_984 >= 8193:  # Y outputs at 0x2000+
            return addr_984 - 8193 + 0x2000
        elif addr_984 >= 1:
            return addr_984 - 1
        return addr_984
    else:
        # Unknown FC, try to guess
        return addr_984 - 1


def detect_csv_format(modbus_addr_sample: str) -> str:
    """
    Detect whether CSV uses HEX or 984 format.

    Args:
        modbus_addr_sample: Sample Modbus Address value from CSV

    Returns:
        "hex" or "984"
    """
    if modbus_addr_sample.strip().lower().endswith('h'):
        return "hex"
    return "984"


def parse_click_csv(
    filepath: str,
    encoding: str = "utf-8"
) -> Tuple[bool, List[ConfigEntry], str]:
    """
    Parse a CLICK Programming Software CSV export file.

    Handles both HEX format (addresses like "0000h") and 984 format
    (addresses like "100001").

    Args:
        filepath: Path to the CSV file
        encoding: File encoding (default UTF-8, falls back to cp1252)

    Returns:
        Tuple of (success, list of ConfigEntry, error_message)
    """
    entries: List[ConfigEntry] = []

    # Try to read the file with specified encoding
    try:
        with open(filepath, 'r', encoding=encoding, newline='') as f:
            content = f.read()
    except UnicodeDecodeError:
        # Try Windows-1252 encoding as fallback
        try:
            with open(filepath, 'r', encoding='cp1252', newline='') as f:
                content = f.read()
        except Exception as e:
            return False, [], f"Failed to read file: {e}"
    except FileNotFoundError:
        return False, [], f"File not found: {filepath}"
    except Exception as e:
        return False, [], f"Error reading file: {e}"

    # Parse CSV content
    try:
        reader = csv.DictReader(content.splitlines())

        # Verify required columns exist
        required_cols = ["Address", "Modbus Address", "Nickname"]
        if reader.fieldnames is None:
            return False, [], "CSV file appears to be empty"

        missing_cols = [c for c in required_cols if c not in reader.fieldnames]
        if missing_cols:
            return False, [], f"Missing required columns: {', '.join(missing_cols)}"

        # Detect format from first data row
        csv_format = None

        for row in reader:
            # Detect format on first row
            if csv_format is None:
                csv_format = detect_csv_format(row.get("Modbus Address", ""))

            click_addr = row.get("Address", "").strip()
            if not click_addr:
                continue

            data_type = row.get("Data Type", "").strip().upper()
            modbus_addr_str = row.get("Modbus Address", "").strip()
            function_code = row.get("Function Code", "").strip()
            nickname = row.get("Nickname", "").strip()

            # Skip if no modbus address
            if not modbus_addr_str:
                continue

            # Parse modbus address based on format
            try:
                if csv_format == "hex":
                    modbus_addr = parse_modbus_address_hex(modbus_addr_str)
                else:
                    modbus_addr = parse_modbus_address_984(modbus_addr_str, function_code)
            except ValueError as e:
                print(f"Warning: Could not parse Modbus address '{modbus_addr_str}' for {click_addr}: {e}")
                continue

            # Derive address type
            addr_type = derive_address_type(click_addr)
            if not addr_type:
                print(f"Warning: Could not determine type for address '{click_addr}'")
                continue

            entry = ConfigEntry(
                click_address=click_addr,
                address_type=addr_type,
                data_type=data_type,
                modbus_address=modbus_addr,
                nickname=nickname
            )
            entries.append(entry)

    except csv.Error as e:
        return False, [], f"CSV parsing error: {e}"
    except Exception as e:
        return False, [], f"Error parsing CSV: {e}"

    if not entries:
        return False, [], "No valid entries found in CSV"

    return True, entries, ""


def extract_used_addresses(
    entries: List[ConfigEntry]
) -> Dict[str, Dict[str, ConfigEntry]]:
    """
    Group ConfigEntry objects by address type and create lookup dictionaries.

    Args:
        entries: List of ConfigEntry from parsed CSV

    Returns:
        Dictionary mapping address_type to dict of click_address -> ConfigEntry
        Example: {"DS": {"DS1": ConfigEntry(...), "DS3": ConfigEntry(...)}}
    """
    result: Dict[str, Dict[str, ConfigEntry]] = {}

    for entry in entries:
        if entry.address_type not in result:
            result[entry.address_type] = {}

        # Use uppercase CLICK address as key
        result[entry.address_type][entry.click_address.upper()] = entry

    return result


def get_types_from_config(entries: List[ConfigEntry]) -> List[str]:
    """
    Get unique address types from config entries, ordered by scan priority.

    Args:
        entries: List of ConfigEntry from parsed CSV

    Returns:
        List of unique address type names in scan order
    """
    # Get unique types
    unique_types = set(entry.address_type for entry in entries)

    # Order by position in ALL_TYPE_NAMES for consistent scan order
    ordered = []
    for type_name in ALL_TYPE_NAMES:
        if type_name in unique_types:
            ordered.append(type_name)

    return ordered


# =============================================================================
# Section: Modbus Communication
# =============================================================================

def connect_to_plc(
    host: str,
    port: int = DEFAULT_PORT,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES
) -> Optional[ModbusTcpClient]:
    """
    Establish TCP connection to CLICK PLC Modbus server.

    Args:
        host: IP address or hostname of the PLC
        port: Modbus TCP port (default 502)
        timeout: Connection timeout in seconds
        retries: Number of connection retry attempts

    Returns:
        Connected ModbusTcpClient instance, or None on failure
    """
    if not PYMODBUS_AVAILABLE:
        return None

    client = ModbusTcpClient(
        host=host,
        port=port,
        timeout=timeout,
        retries=retries
    )

    try:
        connected = client.connect()
        if connected:
            return client
        else:
            print(f"Failed to connect to {host}:{port}")
            print("Error: Connection refused or host unreachable")
            return None
    except ConnectionException as e:
        print(f"Failed to connect to {host}:{port}")
        print(f"Error: {e}")
        return None
    except Exception as e:
        print(f"Failed to connect to {host}:{port}")
        print(f"Unexpected error: {e}")
        return None


def disconnect_from_plc(client: ModbusTcpClient) -> None:
    """Close connection to PLC."""
    if client:
        try:
            client.close()
        except Exception:
            pass  # Ignore errors during disconnect


def read_coils(
    client: ModbusTcpClient,
    address: int,
    count: int = 1,
    device_id: int = 1
) -> Tuple[bool, Optional[List[bool]]]:
    """
    Read coils from PLC (Function Code 01).

    Args:
        client: Connected ModbusTcpClient
        address: Starting address (0-based)
        count: Number of coils to read
        device_id: Device/unit ID (default 1)

    Returns:
        Tuple of (success, list of bool values or None on error)
    """
    try:
        result = client.read_coils(address, count=count, device_id=device_id)
        if result.isError():
            return False, None
        return True, result.bits[:count]
    except ModbusException as e:
        print(f"Modbus error reading coils at 0x{address:04X}: {e}")
        return False, None
    except Exception as e:
        print(f"Error reading coils at 0x{address:04X}: {e}")
        return False, None


def read_discrete_inputs(
    client: ModbusTcpClient,
    address: int,
    count: int = 1,
    device_id: int = 1
) -> Tuple[bool, Optional[List[bool]]]:
    """
    Read discrete inputs from PLC (Function Code 02).

    Args:
        client: Connected ModbusTcpClient
        address: Starting address (0-based)
        count: Number of inputs to read
        device_id: Device/unit ID (default 1)

    Returns:
        Tuple of (success, list of bool values or None on error)
    """
    try:
        result = client.read_discrete_inputs(address, count=count, device_id=device_id)
        if result.isError():
            return False, None
        return True, result.bits[:count]
    except ModbusException as e:
        print(f"Modbus error reading discrete inputs at 0x{address:04X}: {e}")
        return False, None
    except Exception as e:
        print(f"Error reading discrete inputs at 0x{address:04X}: {e}")
        return False, None


def read_holding_registers(
    client: ModbusTcpClient,
    address: int,
    count: int = 1,
    device_id: int = 1
) -> Tuple[bool, Optional[List[int]]]:
    """
    Read holding registers from PLC (Function Code 03).

    Args:
        client: Connected ModbusTcpClient
        address: Starting address (0-based)
        count: Number of registers to read
        device_id: Device/unit ID (default 1)

    Returns:
        Tuple of (success, list of register values or None on error)
    """
    try:
        result = client.read_holding_registers(address, count=count, device_id=device_id)
        if result.isError():
            return False, None
        return True, result.registers
    except ModbusException as e:
        print(f"Modbus error reading holding registers at 0x{address:04X}: {e}")
        return False, None
    except Exception as e:
        print(f"Error reading holding registers at 0x{address:04X}: {e}")
        return False, None


def read_input_registers(
    client: ModbusTcpClient,
    address: int,
    count: int = 1,
    device_id: int = 1
) -> Tuple[bool, Optional[List[int]]]:
    """
    Read input registers from PLC (Function Code 04).

    Args:
        client: Connected ModbusTcpClient
        address: Starting address (0-based)
        count: Number of registers to read
        device_id: Device/unit ID (default 1)

    Returns:
        Tuple of (success, list of register values or None on error)
    """
    try:
        result = client.read_input_registers(address, count=count, device_id=device_id)
        if result.isError():
            return False, None
        return True, result.registers
    except ModbusException as e:
        print(f"Modbus error reading input registers at 0x{address:04X}: {e}")
        return False, None
    except Exception as e:
        print(f"Error reading input registers at 0x{address:04X}: {e}")
        return False, None


def scan_address_type(
    client: ModbusTcpClient,
    addr_type: AddressType,
    rate_delay: float = 0.05,
    device_id: int = 1
) -> List[ScanResult]:
    """
    Scan all addresses of a specific type.

    Args:
        client: Connected ModbusTcpClient
        addr_type: AddressType definition to scan
        rate_delay: Delay between requests in seconds
        device_id: Device/unit ID (default 1)

    Returns:
        List of ScanResult objects
    """
    results: List[ScanResult] = []

    # Determine the read function based on function code
    if addr_type.function_code == FC_READ_COILS:
        read_func = read_coils
    elif addr_type.function_code == FC_READ_DISCRETE_INPUTS:
        read_func = read_discrete_inputs
    elif addr_type.function_code == FC_READ_HOLDING_REGISTERS:
        read_func = read_holding_registers
    elif addr_type.function_code == FC_READ_INPUT_REGISTERS:
        read_func = read_input_registers
    else:
        print(f"Unknown function code: {addr_type.function_code}")
        return results

    # Determine starting index (most types start at 1, XD/YD start at 0)
    start_index = 0 if addr_type.name in ("XD", "YD") else 1

    # For coils/discrete inputs, we can read in larger chunks
    # For registers, respect the word_size for multi-word types
    if addr_type.function_code in (FC_READ_COILS, FC_READ_DISCRETE_INPUTS):
        # Read coils in chunks (max 2000 per Modbus spec, use 100 for safety)
        chunk_size = 100
        for chunk_start in range(0, addr_type.count, chunk_size):
            chunk_count = min(chunk_size, addr_type.count - chunk_start)
            modbus_addr = addr_type.start_address + chunk_start

            success, values = read_func(client, modbus_addr, chunk_count, device_id)

            if success and values:
                for i, value in enumerate(values):
                    idx = start_index + chunk_start + i
                    if idx >= start_index + addr_type.count:
                        break

                    click_addr = f"{addr_type.name}{idx}"
                    hex_addr = f"0x{modbus_addr + i:04X}"

                    # Calculate 984 address
                    if addr_type.function_code == FC_READ_DISCRETE_INPUTS:
                        addr_984 = f"{100001 + modbus_addr + i}"
                    else:  # FC_READ_COILS
                        addr_984 = f"{1 + modbus_addr + i:06d}"

                    result = ScanResult(
                        address_type=addr_type.name,
                        click_address=click_addr,
                        modbus_hex=hex_addr,
                        modbus_984=addr_984,
                        raw_value=1 if value else 0,
                        converted_value=value,
                        nickname=""
                    )
                    results.append(result)

            if rate_delay > 0:
                time.sleep(rate_delay)
    else:
        # Read registers - handle multi-word types
        # Max 125 registers per request, use 100 for safety
        chunk_size = 100 // addr_type.word_size

        for chunk_start in range(0, addr_type.count, chunk_size):
            chunk_count = min(chunk_size, addr_type.count - chunk_start)
            modbus_addr = addr_type.start_address + (chunk_start * addr_type.word_size)
            reg_count = chunk_count * addr_type.word_size

            success, values = read_func(client, modbus_addr, reg_count, device_id)

            if success and values:
                for i in range(chunk_count):
                    idx = start_index + chunk_start + i
                    if idx >= start_index + addr_type.count:
                        break

                    reg_offset = i * addr_type.word_size
                    click_addr = f"{addr_type.name}{idx}"
                    actual_modbus_addr = modbus_addr + reg_offset
                    hex_addr = f"0x{actual_modbus_addr:04X}"

                    # Calculate 984 address
                    if addr_type.function_code == FC_READ_INPUT_REGISTERS:
                        addr_984 = f"{300001 + actual_modbus_addr}"
                    else:  # FC_READ_HOLDING_REGISTERS
                        addr_984 = f"{400001 + actual_modbus_addr}"

                    # Extract raw value(s) for this address
                    if addr_type.word_size == 1:
                        raw = values[reg_offset]
                    else:
                        raw = values[reg_offset:reg_offset + addr_type.word_size]

                    # Convert value based on data format
                    converted = convert_value(raw, addr_type.data_format)

                    # For raw_value field, store as single int
                    # CLICK PLC uses little-endian word order (low word first)
                    if isinstance(raw, list):
                        raw_int = (raw[1] << 16) + raw[0] if len(raw) == 2 else raw[0]
                    else:
                        raw_int = raw

                    result = ScanResult(
                        address_type=addr_type.name,
                        click_address=click_addr,
                        modbus_hex=hex_addr,
                        modbus_984=addr_984,
                        raw_value=raw_int,
                        converted_value=converted,
                        nickname=""
                    )
                    results.append(result)

            if rate_delay > 0:
                time.sleep(rate_delay)

    return results


def scan_from_config(
    client: ModbusTcpClient,
    config_entries: List[ConfigEntry],
    address_lookup: Dict[str, Dict[str, ConfigEntry]],
    rate_delay: float = 0.05,
    device_id: int = 1
) -> List[ScanResult]:
    """
    Scan only addresses specified in config, merging nicknames.

    This function reads only the specific addresses from the config file,
    rather than scanning entire address ranges. It also merges nicknames
    from the config into the scan results.

    Args:
        client: Connected ModbusTcpClient
        config_entries: List of ConfigEntry from parsed CSV
        address_lookup: Dict from extract_used_addresses() for nickname lookup
        rate_delay: Delay between requests in seconds
        device_id: Device/unit ID (default 1)

    Returns:
        List of ScanResult objects with nicknames populated
    """
    results: List[ScanResult] = []

    # Group entries by address type for efficient reading
    types_to_scan = get_types_from_config(config_entries)

    for type_name in types_to_scan:
        if type_name not in CLICK_ADDRESS_TYPES:
            print(f"Warning: Unknown type '{type_name}' in config, skipping")
            continue

        addr_type = CLICK_ADDRESS_TYPES[type_name]
        type_entries = [e for e in config_entries if e.address_type == type_name]

        if not type_entries:
            continue

        print(f"Scanning {type_name} ({addr_type.description})...")

        # Determine the read function based on function code
        if addr_type.function_code == FC_READ_COILS:
            read_func = read_coils
        elif addr_type.function_code == FC_READ_DISCRETE_INPUTS:
            read_func = read_discrete_inputs
        elif addr_type.function_code == FC_READ_HOLDING_REGISTERS:
            read_func = read_holding_registers
        elif addr_type.function_code == FC_READ_INPUT_REGISTERS:
            read_func = read_input_registers
        else:
            print(f"Unknown function code: {addr_type.function_code}")
            continue

        # Read each configured address individually
        for entry in type_entries:
            modbus_addr = entry.modbus_address

            if addr_type.function_code in (FC_READ_COILS, FC_READ_DISCRETE_INPUTS):
                # Read single coil/discrete input
                success, values = read_func(client, modbus_addr, 1, device_id)

                if success and values:
                    value = values[0]
                    hex_addr = f"0x{modbus_addr:04X}"

                    # Calculate 984 address
                    if addr_type.function_code == FC_READ_DISCRETE_INPUTS:
                        addr_984 = f"{100001 + modbus_addr}"
                    else:  # FC_READ_COILS
                        addr_984 = f"{1 + modbus_addr:06d}"

                    result = ScanResult(
                        address_type=type_name,
                        click_address=entry.click_address.upper(),
                        modbus_hex=hex_addr,
                        modbus_984=addr_984,
                        raw_value=1 if value else 0,
                        converted_value=value,
                        nickname=entry.nickname
                    )
                    results.append(result)
            else:
                # Read register(s)
                reg_count = addr_type.word_size
                success, values = read_func(client, modbus_addr, reg_count, device_id)

                if success and values:
                    hex_addr = f"0x{modbus_addr:04X}"

                    # Calculate 984 address
                    if addr_type.function_code == FC_READ_INPUT_REGISTERS:
                        addr_984 = f"{300001 + modbus_addr}"
                    else:  # FC_READ_HOLDING_REGISTERS
                        addr_984 = f"{400001 + modbus_addr}"

                    # Extract raw value(s)
                    if addr_type.word_size == 1:
                        raw = values[0]
                    else:
                        raw = values[:addr_type.word_size]

                    # Convert value based on data format
                    converted = convert_value(raw, addr_type.data_format)

                    # For raw_value field, store as single int
                    # CLICK PLC uses little-endian word order (low word first)
                    if isinstance(raw, list):
                        raw_int = (raw[1] << 16) + raw[0] if len(raw) == 2 else raw[0]
                    else:
                        raw_int = raw

                    result = ScanResult(
                        address_type=type_name,
                        click_address=entry.click_address.upper(),
                        modbus_hex=hex_addr,
                        modbus_984=addr_984,
                        raw_value=raw_int,
                        converted_value=converted,
                        nickname=entry.nickname
                    )
                    results.append(result)

            if rate_delay > 0:
                time.sleep(rate_delay)

        print(f"  Read {len([r for r in results if r.address_type == type_name])} addresses")

    return results


# =============================================================================
# Section: Data Conversion
# =============================================================================

def convert_to_int16(value: int) -> int:
    """
    Convert unsigned 16-bit value to signed 16-bit.

    Args:
        value: Unsigned 16-bit register value

    Returns:
        Signed 16-bit integer
    """
    if value >= 0x8000:
        return value - 0x10000
    return value


def convert_to_int32(registers: List[int]) -> int:
    """
    Convert two 16-bit registers to signed 32-bit integer.
    CLICK PLC uses little-endian word order (low word first).

    Args:
        registers: List of two 16-bit register values [low, high]

    Returns:
        Signed 32-bit integer
    """
    if len(registers) != 2:
        return 0
    # Combine registers: low word first (CLICK PLC little-endian word order)
    unsigned = (registers[1] << 16) | registers[0]
    # Convert to signed if necessary
    if unsigned >= 0x80000000:
        return unsigned - 0x100000000
    return unsigned


def convert_to_float(registers: List[int]) -> float:
    """
    Convert two 16-bit registers to IEEE 754 float.
    CLICK PLC uses little-endian word order (low word first).

    Args:
        registers: List of two 16-bit register values [low, high]

    Returns:
        Float value
    """
    if len(registers) != 2:
        return 0.0
    # Pack with swapped word order (low word first from PLC)
    try:
        packed = struct.pack('>HH', registers[1], registers[0])
        return struct.unpack('>f', packed)[0]
    except Exception:
        return 0.0


def convert_to_hex(registers: List[int]) -> str:
    """
    Convert registers to hex string display.
    For 2-word values, displays as single 32-bit value with correct word order.
    CLICK PLC uses little-endian word order (low word first).

    Args:
        registers: List of 16-bit register values

    Returns:
        Hex string representation
    """
    if isinstance(registers, int):
        return f"0x{registers:04X}"
    if len(registers) == 1:
        return f"0x{registers[0]:04X}"
    elif len(registers) == 2:
        # CLICK PLC little-endian word order: low word first
        return f"0x{registers[1]:04X}{registers[0]:04X}"
    return "0x" + "".join(f"{r:04X}" for r in registers)


def convert_value(raw: Union[int, List[int]], data_format: str) -> Any:
    """
    Convert raw register value(s) based on data format.

    Args:
        raw: Raw register value or list of values
        data_format: Format identifier (bool, int16, int32, float, hex)

    Returns:
        Converted value appropriate for the format
    """
    if data_format == FMT_BOOL:
        return bool(raw) if isinstance(raw, int) else bool(raw[0]) if raw else False

    elif data_format == FMT_INT16:
        val = raw if isinstance(raw, int) else raw[0] if raw else 0
        return convert_to_int16(val)

    elif data_format == FMT_INT32:
        if isinstance(raw, list) and len(raw) >= 2:
            return convert_to_int32(raw)
        return raw if isinstance(raw, int) else 0

    elif data_format == FMT_FLOAT:
        if isinstance(raw, list) and len(raw) >= 2:
            return convert_to_float(raw)
        return 0.0

    elif data_format == FMT_HEX:
        return convert_to_hex(raw if isinstance(raw, list) else [raw])

    return raw


# =============================================================================
# Section: Output Formatting
# =============================================================================

def get_display_name(result: ScanResult) -> str:
    """
    Get display name for a scan result.
    Uses nickname if available, otherwise uses CLICK address.

    Args:
        result: ScanResult object

    Returns:
        Display name string
    """
    if result.nickname and result.nickname.strip():
        return result.nickname
    return result.click_address


def format_value(value: Any) -> str:
    """
    Format a value for display.

    Args:
        value: Value to format

    Returns:
        Formatted string
    """
    if isinstance(value, bool):
        return "True" if value else "False"
    elif isinstance(value, float):
        return f"{value:.4f}"
    else:
        return str(value)


def print_results_console(
    results: List[ScanResult],
    show_header: bool = True,
    show_984: bool = False
) -> None:
    """
    Print scan results to console.

    Args:
        results: List of ScanResult objects
        show_header: Whether to print header row
        show_984: Whether to show 984 addresses instead of HEX
    """
    if not results:
        return

    # Calculate column widths based on data
    max_addr = max(len(r.click_address) for r in results)
    max_name = max(len(get_display_name(r)) for r in results)
    max_val = max(len(format_value(r.converted_value)) for r in results)

    # Set minimum widths
    addr_width = max(max_addr, 8)
    name_width = max(max_name, 8)
    val_width = max(max_val, 10)

    # Header
    addr_col = "984 Addr" if show_984 else "Hex Addr"
    if show_header:
        print(f"{'Address':<{addr_width}}  {addr_col:<10}  {'Value':<{val_width}}  {'Name'}")
        print("-" * (addr_width + 10 + val_width + name_width + 10))

    for r in results:
        addr_str = r.modbus_984 if show_984 else r.modbus_hex
        val_str = format_value(r.converted_value)
        name_str = get_display_name(r)

        print(f"{r.click_address:<{addr_width}}  {addr_str:<10}  {val_str:<{val_width}}  {name_str}")


def generate_timestamp() -> str:
    """Generate timestamp string for filenames."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def write_results_csv(
    results: List[ScanResult],
    filepath: str,
    host: str,
    show_984: bool = False
) -> bool:
    """
    Write scan results to CSV file.

    Args:
        results: List of ScanResult objects
        filepath: Output file path
        host: Target host for metadata
        show_984: Whether to use 984 addresses

    Returns:
        True on success, False on failure
    """
    try:
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)

            # Header row
            writer.writerow([
                'address_type',
                'click_address',
                'modbus_hex',
                'modbus_984',
                'raw_value',
                'converted_value',
                'nickname'
            ])

            # Data rows
            for r in results:
                writer.writerow([
                    r.address_type,
                    r.click_address,
                    r.modbus_hex,
                    r.modbus_984,
                    r.raw_value,
                    format_value(r.converted_value),
                    get_display_name(r)
                ])

        print(f"CSV output written to: {filepath}")
        return True

    except IOError as e:
        print(f"Error writing CSV file: {e}")
        return False


def write_results_markdown(
    results: List[ScanResult],
    filepath: str,
    host: str,
    port: int,
    types_scanned: List[str],
    show_984: bool = False
) -> bool:
    """
    Write scan results to Markdown file.

    Args:
        results: List of ScanResult objects
        filepath: Output file path
        host: Target host
        port: Target port
        types_scanned: List of address types that were scanned
        show_984: Whether to use 984 addresses

    Returns:
        True on success, False on failure
    """
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            # Header
            f.write("# CLICK PLC Scan Results\n\n")
            f.write(f"**Target**: {host}:{port}\n")
            f.write(f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Types Scanned**: {', '.join(types_scanned)}\n")
            f.write(f"**Total Addresses**: {len(results)}\n\n")

            # Group results by address type
            results_by_type: Dict[str, List[ScanResult]] = {}
            for r in results:
                if r.address_type not in results_by_type:
                    results_by_type[r.address_type] = []
                results_by_type[r.address_type].append(r)

            # Write each type as a section
            for type_name in types_scanned:
                if type_name not in results_by_type:
                    continue

                type_results = results_by_type[type_name]
                addr_type = CLICK_ADDRESS_TYPES.get(type_name)
                type_desc = addr_type.description if addr_type else type_name

                f.write(f"## {type_name} - {type_desc}\n\n")

                # Table header
                addr_col = "984 Address" if show_984 else "Hex Address"
                f.write(f"| Address | {addr_col} | Value | Name |\n")
                f.write("|---------|------------|-------|------|\n")

                # Table rows
                for r in type_results:
                    addr_str = r.modbus_984 if show_984 else r.modbus_hex
                    val_str = format_value(r.converted_value)
                    name_str = get_display_name(r)
                    f.write(f"| {r.click_address} | {addr_str} | {val_str} | {name_str} |\n")

                f.write("\n")

            # Footer
            f.write("---\n\n")
            f.write("Generated by click_modbus_scanner.py\n")

        print(f"Markdown output written to: {filepath}")
        return True

    except IOError as e:
        print(f"Error writing Markdown file: {e}")
        return False


# =============================================================================
# Section: CLI
# =============================================================================

def build_argument_parser() -> argparse.ArgumentParser:
    """Build and return the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="click_modbus_scanner",
        description="Scan AutomationDirect CLICK PLC via Modbus TCP",
        epilog="For authorized security testing and educational purposes only."
    )

    parser.add_argument(
        "host",
        nargs="?",
        default=None,
        help="IP address or hostname of the CLICK PLC"
    )

    parser.add_argument(
        "--port", "-p",
        type=int,
        default=DEFAULT_PORT,
        help=f"Modbus TCP port (default: {DEFAULT_PORT})"
    )

    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT})"
    )

    parser.add_argument(
        "--type", "-T",
        type=str,
        default=None,
        help="Comma-separated address types to scan (e.g., DS,DF,X0). Default: common types"
    )

    parser.add_argument(
        "--rate", "-r",
        type=str,
        default="normal",
        choices=list(RATE_PRESETS.keys()),
        help="Scan rate preset: normal (50ms), moderate (200ms), slow (500ms)"
    )

    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="List available address types and exit"
    )

    parser.add_argument(
        "--full", "-f",
        action="store_true",
        help="Scan all address types (overrides --type)"
    )

    parser.add_argument(
        "--format", "-F",
        type=str,
        default="hex",
        choices=["hex", "984"],
        help="Address format for output display (default: hex)"
    )

    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Output file path (auto-detects format from extension: .csv or .md)"
    )

    parser.add_argument(
        "--config", "-c",
        type=str,
        default=None,
        help="CLICK CSV config file to filter addresses and import nicknames"
    )

    return parser


def validate_arguments(args: argparse.Namespace) -> bool:
    """
    Validate command-line arguments.

    Args:
        args: Parsed arguments from argparse

    Returns:
        True if all arguments are valid, False otherwise
    """
    # Skip validation if just listing types
    if args.list:
        return True

    # Host is required for scanning
    if not args.host:
        print("Error: Host argument is required for scanning")
        print("Use --list to see available address types")
        return False

    # Validate port range
    if args.port < 1 or args.port > 65535:
        print(f"Error: Invalid port number: {args.port}")
        print("Port must be between 1 and 65535")
        return False

    # Validate timeout
    if args.timeout < 1 or args.timeout > 300:
        print(f"Error: Invalid timeout: {args.timeout}")
        print("Timeout must be between 1 and 300 seconds")
        return False

    # Validate address type names if specified
    if args.type:
        type_names = [t.strip().upper() for t in args.type.split(",")]
        invalid_types = [t for t in type_names if t not in ALL_TYPE_NAMES]
        if invalid_types:
            print(f"Error: Invalid address type(s): {', '.join(invalid_types)}")
            print(f"Valid types: {', '.join(ALL_TYPE_NAMES)}")
            return False

    # Validate config file exists if specified
    if args.config:
        if not os.path.isfile(args.config):
            print(f"Error: Config file not found: {args.config}")
            return False

    return True


def list_address_types() -> None:
    """Print available address types and their details."""
    print("Available CLICK PLC Address Types")
    print("=" * 70)
    print(f"{'Type':<6} {'FC':<4} {'Start':<8} {'Count':<6} {'Format':<8} {'Description'}")
    print("-" * 70)

    for name, addr_type in CLICK_ADDRESS_TYPES.items():
        print(f"{name:<6} {addr_type.function_code:<4} "
              f"0x{addr_type.start_address:04X}  {addr_type.count:<6} "
              f"{addr_type.data_format:<8} {addr_type.description}")

    print()
    print(f"Common types (default): {', '.join(COMMON_TYPES)}")


# =============================================================================
# Section: Main
# =============================================================================

def main() -> int:
    """
    Main entry point for the scanner.

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    # Check dependencies first
    if not check_dependencies():
        return 1

    # Parse arguments
    parser = build_argument_parser()
    args = parser.parse_args()

    # Handle --list option
    if args.list:
        list_address_types()
        return 0

    # Validate arguments
    if not validate_arguments(args):
        return 1

    # Parse config file if provided
    config_entries: List[ConfigEntry] = []
    address_lookup: Dict[str, Dict[str, ConfigEntry]] = {}
    use_config = False

    if args.config:
        print(f"Loading config from: {args.config}")
        success, config_entries, error_msg = parse_click_csv(args.config)
        if not success:
            print(f"Error: {error_msg}")
            return 1
        address_lookup = extract_used_addresses(config_entries)
        use_config = True
        # Get types from config
        scan_types = get_types_from_config(config_entries)
        print(f"Config loaded: {len(config_entries)} addresses in {len(scan_types)} types")
    elif args.full:
        scan_types = ALL_TYPE_NAMES
    elif args.type:
        scan_types = [t.strip().upper() for t in args.type.split(",")]
    else:
        scan_types = COMMON_TYPES

    # Get rate delay
    rate_delay = RATE_PRESETS.get(args.rate, RATE_PRESETS["normal"])

    # Determine address format for display
    show_984 = (args.format == "984")

    # Attempt connection
    print(f"Connecting to {args.host}:{args.port}...")

    client = connect_to_plc(
        host=args.host,
        port=args.port,
        timeout=args.timeout
    )

    if client is None:
        return 1

    print(f"Connected to {args.host}:{args.port}")
    print(f"Scanning types: {', '.join(scan_types)}")
    print(f"Rate: {args.rate} ({rate_delay*1000:.0f}ms delay)")
    print()

    # Scan addresses
    all_results: List[ScanResult] = []
    total_errors = 0

    if use_config:
        # Scan only addresses from config with nicknames
        all_results = scan_from_config(
            client, config_entries, address_lookup, rate_delay
        )
        if not all_results:
            total_errors = 1
    else:
        # Standard scan: scan full address ranges
        for type_name in scan_types:
            if type_name not in CLICK_ADDRESS_TYPES:
                print(f"Warning: Unknown type '{type_name}', skipping")
                continue

            addr_type = CLICK_ADDRESS_TYPES[type_name]
            print(f"Scanning {type_name} ({addr_type.description})...")

            results = scan_address_type(client, addr_type, rate_delay)

            if results:
                all_results.extend(results)
                print(f"  Read {len(results)} addresses")
            else:
                print(f"  No results (possible error)")
                total_errors += 1

    # Display results
    print()
    if all_results:
        # Console output
        print_results_console(all_results, show_984=show_984)
        print()
        print(f"Total: {len(all_results)} addresses scanned")

        # File output if requested
        if args.output:
            output_path = args.output
            timestamp = generate_timestamp()

            # Auto-generate filename with timestamp if directory or no extension
            if output_path.endswith('/') or '.' not in output_path.split('/')[-1]:
                # Treat as directory or base name, add timestamp and default to CSV
                if output_path.endswith('/'):
                    output_path = f"{output_path}scan_{timestamp}.csv"
                else:
                    output_path = f"{output_path}_{timestamp}.csv"

            # Determine format from extension
            if output_path.lower().endswith('.csv'):
                write_results_csv(all_results, output_path, args.host, show_984)
            elif output_path.lower().endswith('.md'):
                write_results_markdown(
                    all_results, output_path, args.host, args.port,
                    scan_types, show_984
                )
            else:
                # Default to CSV for unknown extensions
                print(f"Unknown file extension, defaulting to CSV format")
                write_results_csv(all_results, output_path, args.host, show_984)
    else:
        print("No results to display")

    if total_errors > 0:
        print(f"Warnings: {total_errors} type(s) returned no data")

    # Clean up
    disconnect_from_plc(client)

    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
click_enip_scanner.py - Query CLICK PLC for EtherNet/IP CIP data.

Scans AutomationDirect CLICK PLCs via EtherNet/IP CIP Explicit Messaging to read
device identity, network information, and assembly data blocks. Designed for
ICS/OT cybersecurity students and assessment personnel conducting authorized testing.

Author:  Don C. Weber (cutaway)
Repository: https://github.com/cutaway-security/clickplc_modbus
"""

import sys
import argparse
import struct
from datetime import datetime
from dataclasses import dataclass
from typing import Optional, Any, Dict, List, Tuple

# =============================================================================
# Section: Imports and Dependency Check
# =============================================================================

PYCOMM3_AVAILABLE = False
try:
    from pycomm3 import CIPDriver
    PYCOMM3_AVAILABLE = True
except ImportError:
    pass


def check_dependencies() -> bool:
    """Check if required dependencies are available."""
    if not PYCOMM3_AVAILABLE:
        print("Error: pycomm3 library not found.")
        print("")
        print("Install with: pip install pycomm3")
        print("Or: pip install -r requirements.txt")
        print("")
        print("pycomm3 1.x or higher is required.")
        return False
    return True


# =============================================================================
# Section: Constants
# =============================================================================

# Default configuration values
DEFAULT_PORT = 44818
DEFAULT_TIMEOUT = 5  # seconds

# CIP Service Codes
SVC_GET_ATTRIBUTE_SINGLE = 0x0E
SVC_GET_ATTRIBUTES_ALL = 0x01

# CIP Object Classes
CLASS_IDENTITY = 0x01
CLASS_ASSEMBLY = 0x04
CLASS_TCP_IP_INTERFACE = 0xF5
CLASS_ETHERNET_LINK = 0xF6

# Assembly Instance mapping
ASSEMBLY_INSTANCES = {
    1: {"input": 101, "output": 102},  # Connection 1
    2: {"input": 103, "output": 104},  # Connection 2
}

# Identity Object Attribute definitions
IDENTITY_ATTRIBUTES = {
    1: ("Vendor ID", "H"),           # UINT (2 bytes)
    2: ("Device Type", "H"),         # UINT (2 bytes)
    3: ("Product Code", "H"),        # UINT (2 bytes)
    4: ("Revision", "BB"),           # Major.Minor (2 bytes)
    5: ("Status", "H"),              # WORD (2 bytes)
    6: ("Serial Number", "I"),       # UDINT (4 bytes)
    7: ("Product Name", None),       # SHORT_STRING (variable)
}

# Known Vendor IDs
VENDOR_NAMES = {
    482: "AutomationDirect",
}

# Known Device Types
DEVICE_TYPE_NAMES = {
    0: "Generic Device",
    14: "Programmable Logic Controller",
    43: "Generic Device (CLICK)",
}

# CIP General Status Codes (from CLICK EtherNet/IP documentation)
CIP_GENERAL_STATUS = {
    0x00: ("Success", "Operation completed successfully"),
    0x01: ("Connection Failure", "Connection-related error (see extended status)"),
    0x04: ("Path Segment Error", "Path segment identifier or syntax not understood"),
    0x05: ("Path Destination Error", "Object Class, Instance, or Attribute not supported"),
    0x08: ("Service Not Supported", "Requested service not implemented for this object"),
    0x09: ("Data Segment Error", "Error in data segment of Forward Open message"),
    0x0E: ("Attribute Not Settable", "Attempted to modify a read-only attribute"),
    0x0F: ("Privilege Violation", "Permission or privilege check failed"),
    0x13: ("Not Enough Data", "Insufficient data in service request"),
    0x14: ("Attribute Not Supported", "Requested attribute not supported"),
    0x15: ("Too Much Data", "Excessive data in service request"),
    0x16: ("Object Does Not Exist", "Specified object does not exist in device"),
    0x20: ("Invalid Parameter", "Parameter does not meet requirements"),
    0x26: ("Path Size Invalid", "Path size incorrect for routing request"),
}

# CIP Extended Status Codes for General Status 0x01 (Connection Failure)
CIP_EXTENDED_STATUS_0x01 = {
    0x0100: ("Connection In Use", "Connection already established or duplicate Forward Open"),
    0x0103: ("Transport Not Supported", "Transport class/trigger combination not supported"),
    0x0106: ("Owner Conflict", "Exclusive owner already configured for this connection point"),
    0x0107: ("Connection Not Found", "Target connection not found (may have timed out)"),
    0x0111: ("RPI Not Supported", "Requested Packet Interval not supported (min 10ms)"),
    0x0114: ("Vendor/Product Mismatch", "Vendor ID or Product Code mismatch"),
    0x0115: ("Device Type Mismatch", "Device Type mismatch in Forward Open"),
    0x0116: ("Revision Mismatch", "Major/minor revision not valid"),
    0x011A: ("Out of Connections", "Maximum connections exceeded"),
    0x0123: ("Invalid O->T Connection Type", "Originator to Target connection type not supported"),
    0x0124: ("Invalid T->O Connection Type", "Target to Originator connection type not supported"),
    0x0127: ("Invalid O->T Size", "Originator to Target data size mismatch"),
    0x0128: ("Invalid T->O Size", "Target to Originator data size mismatch"),
    0x012A: ("Invalid Consuming Path", "Consuming application path missing or incorrect"),
    0x012B: ("Invalid Producing Path", "Producing application path missing or incorrect"),
    0x012F: ("Inconsistent Path", "Configuration/Consuming/Producing paths inconsistent"),
    0x0132: ("Null Forward Open Not Supported", "NULL Forward Open function not supported"),
    0x0315: ("Invalid Segment", "Segment type or value not understood"),
    0x0813: ("Multicast Not Supported", "Off-subnet multicast not configurable"),
}

# Troubleshooting hints for common errors
CIP_TROUBLESHOOTING = {
    0x01: "Check network cabling, switches, and connections. Verify no other device is connected.",
    0x05: "Verify the CIP class, instance, and attribute values are correct for CLICK PLCs.",
    0x08: "This service is not supported by CLICK PLCs. Use Get Attribute Single (0x0E).",
    0x16: "The assembly instance may not be configured. Check EtherNet/IP setup in CLICK software.",
}


# =============================================================================
# Section: Data Structures
# =============================================================================

@dataclass
class DeviceIdentity:
    """Device identity information from Identity Object."""
    vendor_id: int = 0
    vendor_name: str = ""
    device_type: int = 0
    device_type_name: str = ""
    product_code: int = 0
    revision_major: int = 0
    revision_minor: int = 0
    status: int = 0
    serial_number: int = 0
    product_name: str = ""


@dataclass
class NetworkInfo:
    """Network information from TCP/IP and Ethernet Link Objects."""
    ip_address: str = ""
    subnet_mask: str = ""
    gateway: str = ""
    hostname: str = ""
    mac_address: str = ""
    link_speed: int = 0
    link_flags: int = 0


@dataclass
class AssemblyData:
    """Assembly data read from PLC."""
    connection: int = 1
    instance: int = 101
    size: int = 0
    data: bytes = b""
    error: str = ""


# =============================================================================
# Section: Error Handling
# =============================================================================

def parse_cip_error(error_string: str) -> Tuple[str, str, str]:
    """
    Parse a CIP error string and return formatted error information.

    Args:
        error_string: Error string from pycomm3 (e.g., "Object does not exist")

    Returns:
        Tuple of (error_name, description, troubleshooting_hint)
    """
    error_lower = error_string.lower()

    # Try to match known error patterns
    for status_code, (name, desc) in CIP_GENERAL_STATUS.items():
        if name.lower() in error_lower or desc.lower() in error_lower:
            hint = CIP_TROUBLESHOOTING.get(status_code, "")
            return name, desc, hint

    # Check for specific pycomm3 error patterns
    if "object does not exist" in error_lower:
        return (
            "Object Does Not Exist",
            "The specified CIP object does not exist in the device",
            CIP_TROUBLESHOOTING.get(0x16, "")
        )
    elif "service not supported" in error_lower:
        return (
            "Service Not Supported",
            "The requested CIP service is not implemented",
            CIP_TROUBLESHOOTING.get(0x08, "")
        )
    elif "path" in error_lower and "error" in error_lower:
        return (
            "Path Error",
            "CIP path is invalid or not supported",
            CIP_TROUBLESHOOTING.get(0x05, "")
        )
    elif "timeout" in error_lower or "timed out" in error_lower:
        return (
            "Connection Timeout",
            "Connection to PLC timed out",
            "Verify network connectivity and increase --timeout if needed."
        )
    elif "connection" in error_lower and ("refused" in error_lower or "failed" in error_lower):
        return (
            "Connection Refused",
            "Could not establish connection to PLC",
            "Verify IP address, port 44818 is open, and PLC is powered on."
        )

    # Unknown error - return as-is
    return error_string, "", ""


def format_cip_error(error_string: str, verbose: bool = True) -> str:
    """
    Format a CIP error for display to the user.

    Args:
        error_string: Raw error string
        verbose: Include troubleshooting hints

    Returns:
        Formatted error message
    """
    name, desc, hint = parse_cip_error(error_string)

    if desc:
        result = f"{name}: {desc}"
    else:
        result = name

    if verbose and hint:
        result += f"\n  Hint: {hint}"

    return result


def handle_connection_error(error: Exception, host: str, port: int) -> str:
    """
    Handle connection-related errors with helpful messages.

    Args:
        error: Exception that occurred
        host: Target host
        port: Target port

    Returns:
        Formatted error message
    """
    error_str = str(error).lower()

    if "timeout" in error_str or "timed out" in error_str:
        return (
            f"Connection timeout to {host}:{port}\n"
            f"  - Verify network connectivity: ping {host}\n"
            f"  - Check that EtherNet/IP is enabled on port {port}\n"
            f"  - Try increasing timeout with --timeout"
        )
    elif "refused" in error_str:
        return (
            f"Connection refused by {host}:{port}\n"
            f"  - Verify the PLC is powered on and connected\n"
            f"  - Check that EtherNet/IP adapter is enabled\n"
            f"  - Verify no firewall is blocking port {port}"
        )
    elif "no route" in error_str or "network is unreachable" in error_str:
        return (
            f"No route to {host}\n"
            f"  - Verify the IP address is correct\n"
            f"  - Check network configuration and routing\n"
            f"  - Ensure you are on the same network segment"
        )
    elif "name or service not known" in error_str or "nodename nor servname" in error_str:
        return (
            f"Cannot resolve hostname: {host}\n"
            f"  - Verify the hostname is correct\n"
            f"  - Try using the IP address directly"
        )
    elif "failed to open" in error_str:
        return (
            f"Failed to connect to {host}:{port}\n"
            f"  - Verify the IP address is correct and reachable: ping {host}\n"
            f"  - Check that the PLC is powered on\n"
            f"  - Verify EtherNet/IP is enabled on the PLC\n"
            f"  - Try increasing timeout with --timeout"
        )
    else:
        return f"Connection error: {error}"


# =============================================================================
# Section: CIP Communication
# =============================================================================

def connect_enip(
    host: str,
    port: int = DEFAULT_PORT,
    timeout: int = DEFAULT_TIMEOUT
) -> Optional[CIPDriver]:
    """
    Establish EtherNet/IP connection to CLICK PLC.

    Args:
        host: IP address or hostname of the PLC
        port: EtherNet/IP port (default 44818)
        timeout: Connection timeout in seconds

    Returns:
        Connected CIPDriver instance, or None on failure
    """
    if not PYCOMM3_AVAILABLE:
        return None

    try:
        # Create CIPDriver instance
        # Note: pycomm3 uses default port 44818
        plc = CIPDriver(host)
        plc.socket_timeout = timeout

        # Open connection
        plc.open()

        if plc.connected:
            return plc
        else:
            print(f"Failed to connect to {host}:{port}")
            print("Error: Connection failed")
            return None

    except Exception as e:
        print(handle_connection_error(e, host, port))
        return None


def disconnect_enip(plc: CIPDriver) -> None:
    """Close connection to PLC."""
    if plc:
        try:
            plc.close()
        except Exception:
            pass  # Ignore errors during disconnect


def read_cip_attribute(
    plc: CIPDriver,
    class_code: int,
    instance: int,
    attribute: int
) -> Tuple[bool, Optional[bytes], str]:
    """
    Read a single CIP attribute using Get Attribute Single service.

    Args:
        plc: Connected CIPDriver instance
        class_code: CIP object class code
        instance: Object instance number
        attribute: Attribute number to read

    Returns:
        Tuple of (success, raw_bytes, error_message)
    """
    try:
        result = plc.generic_message(
            service=SVC_GET_ATTRIBUTE_SINGLE,
            class_code=class_code,
            instance=instance,
            attribute=attribute,
        )

        if result.error:
            # Format the error with helpful information
            formatted_error = format_cip_error(str(result.error), verbose=False)
            return False, None, formatted_error

        return True, result.value, ""

    except Exception as e:
        return False, None, format_cip_error(str(e), verbose=False)


def get_identity(plc: CIPDriver) -> Tuple[bool, Optional[DeviceIdentity], str]:
    """
    Read device identity from Identity Object (Class 0x01).

    Args:
        plc: Connected CIPDriver instance

    Returns:
        Tuple of (success, DeviceIdentity, error_message)
    """
    identity = DeviceIdentity()
    errors = []

    for attr_id, (attr_name, fmt) in IDENTITY_ATTRIBUTES.items():
        success, raw, error = read_cip_attribute(
            plc, CLASS_IDENTITY, 1, attr_id
        )

        if not success:
            errors.append(f"Attr {attr_id} ({attr_name}): {error}")
            continue

        if raw is None:
            continue

        try:
            if attr_id == 1:  # Vendor ID
                identity.vendor_id = struct.unpack('<H', raw)[0]
                identity.vendor_name = VENDOR_NAMES.get(
                    identity.vendor_id, f"Unknown ({identity.vendor_id})"
                )
            elif attr_id == 2:  # Device Type
                identity.device_type = struct.unpack('<H', raw)[0]
                identity.device_type_name = DEVICE_TYPE_NAMES.get(
                    identity.device_type, f"Unknown ({identity.device_type})"
                )
            elif attr_id == 3:  # Product Code
                identity.product_code = struct.unpack('<H', raw)[0]
            elif attr_id == 4:  # Revision
                identity.revision_major, identity.revision_minor = struct.unpack('<BB', raw[:2])
            elif attr_id == 5:  # Status
                identity.status = struct.unpack('<H', raw)[0]
            elif attr_id == 6:  # Serial Number
                identity.serial_number = struct.unpack('<I', raw)[0]
            elif attr_id == 7:  # Product Name (SHORT_STRING)
                if raw and len(raw) > 0:
                    str_len = raw[0]
                    identity.product_name = raw[1:1+str_len].decode('ascii', errors='replace')
        except struct.error as e:
            errors.append(f"Attr {attr_id} ({attr_name}): Parse error - {e}")

    if errors:
        return True, identity, "; ".join(errors)

    return True, identity, ""


def get_network_info(plc: CIPDriver) -> Tuple[bool, Optional[NetworkInfo], str]:
    """
    Read network information from TCP/IP Interface and Ethernet Link Objects.

    Args:
        plc: Connected CIPDriver instance

    Returns:
        Tuple of (success, NetworkInfo, error_message)
    """
    info = NetworkInfo()
    errors = []

    # Read TCP/IP Interface Object (Class 0xF5, Instance 1)
    # Attribute 5: Interface Configuration
    success, raw, error = read_cip_attribute(plc, CLASS_TCP_IP_INTERFACE, 1, 5)
    if success and raw and len(raw) >= 12:
        # IP addresses stored in little-endian
        info.ip_address = '.'.join(str(b) for b in reversed(raw[0:4]))
        info.subnet_mask = '.'.join(str(b) for b in reversed(raw[4:8]))
        info.gateway = '.'.join(str(b) for b in reversed(raw[8:12]))
    elif error:
        errors.append(f"TCP/IP Config: {error}")

    # Attribute 6: Host Name
    success, raw, error = read_cip_attribute(plc, CLASS_TCP_IP_INTERFACE, 1, 6)
    if success and raw and len(raw) >= 2:
        str_len = struct.unpack('<H', raw[:2])[0]
        if str_len > 0 and len(raw) >= 2 + str_len:
            info.hostname = raw[2:2+str_len].decode('ascii', errors='replace')
    elif error:
        errors.append(f"Hostname: {error}")

    # Read Ethernet Link Object (Class 0xF6, Instance 1)
    # Attribute 1: Interface Speed
    success, raw, error = read_cip_attribute(plc, CLASS_ETHERNET_LINK, 1, 1)
    if success and raw:
        info.link_speed = struct.unpack('<I', raw)[0]
    elif error:
        errors.append(f"Link Speed: {error}")

    # Attribute 2: Interface Flags
    success, raw, error = read_cip_attribute(plc, CLASS_ETHERNET_LINK, 1, 2)
    if success and raw:
        info.link_flags = struct.unpack('<I', raw)[0]
    elif error:
        errors.append(f"Link Flags: {error}")

    # Attribute 3: Physical Address (MAC)
    success, raw, error = read_cip_attribute(plc, CLASS_ETHERNET_LINK, 1, 3)
    if success and raw and len(raw) >= 6:
        info.mac_address = ':'.join(f'{b:02X}' for b in raw[:6])
    elif error:
        errors.append(f"MAC Address: {error}")

    if errors:
        return True, info, "; ".join(errors)

    return True, info, ""


def get_assembly_data(
    plc: CIPDriver,
    connection: int = 1,
    max_size: int = 500
) -> Tuple[bool, Optional[AssemblyData], str]:
    """
    Read assembly data from Assembly Object (Class 0x04).

    Args:
        plc: Connected CIPDriver instance
        connection: Connection number (1 or 2)
        max_size: Maximum bytes to expect (for size mismatch warning)

    Returns:
        Tuple of (success, AssemblyData, error_message)
    """
    if connection not in ASSEMBLY_INSTANCES:
        return False, None, f"Invalid connection number: {connection}"

    instance = ASSEMBLY_INSTANCES[connection]["input"]

    assembly = AssemblyData(
        connection=connection,
        instance=instance
    )

    success, raw, error = read_cip_attribute(plc, CLASS_ASSEMBLY, instance, 3)

    if not success:
        assembly.error = error
        return False, assembly, error

    warning = ""
    if raw:
        assembly.data = raw
        assembly.size = len(raw)
        # Check for size mismatch
        if assembly.size != max_size:
            warning = f"Size mismatch: requested {max_size} bytes, received {assembly.size} bytes"

    return True, assembly, warning


# =============================================================================
# Section: Data Interpretation
# =============================================================================

def interpret_as_int16(data: bytes) -> List[int]:
    """
    Interpret byte data as signed 16-bit integers (little-endian).

    Args:
        data: Raw bytes to interpret

    Returns:
        List of signed 16-bit integer values
    """
    values = []
    for i in range(0, len(data) - 1, 2):
        value = struct.unpack('<h', data[i:i+2])[0]
        values.append(value)
    return values


def interpret_as_uint16(data: bytes) -> List[int]:
    """
    Interpret byte data as unsigned 16-bit integers (little-endian).

    Args:
        data: Raw bytes to interpret

    Returns:
        List of unsigned 16-bit integer values
    """
    values = []
    for i in range(0, len(data) - 1, 2):
        value = struct.unpack('<H', data[i:i+2])[0]
        values.append(value)
    return values


def interpret_as_int32(data: bytes) -> List[int]:
    """
    Interpret byte data as signed 32-bit integers (little-endian).

    Args:
        data: Raw bytes to interpret

    Returns:
        List of signed 32-bit integer values
    """
    values = []
    for i in range(0, len(data) - 3, 4):
        value = struct.unpack('<i', data[i:i+4])[0]
        values.append(value)
    return values


def interpret_as_float(data: bytes) -> List[float]:
    """
    Interpret byte data as IEEE 754 single-precision floats (little-endian).

    Args:
        data: Raw bytes to interpret

    Returns:
        List of float values
    """
    values = []
    for i in range(0, len(data) - 3, 4):
        value = struct.unpack('<f', data[i:i+4])[0]
        values.append(value)
    return values


def interpret_as_ascii(data: bytes) -> str:
    """
    Interpret byte data as ASCII string (printable characters only).

    Args:
        data: Raw bytes to interpret

    Returns:
        String with non-printable characters replaced by dots
    """
    return ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)


def format_row_hex(data: bytes, bytes_per_line: int = 16) -> str:
    """Format a row of bytes as hex string with spacing."""
    return ' '.join(f'{b:02x}' for b in data).ljust(bytes_per_line * 3 - 1)


def format_row_int16(data: bytes) -> str:
    """Format a row of bytes as INT16 values."""
    values = interpret_as_int16(data)
    return ' '.join(f'{v:6d}' for v in values)


def format_row_uint16(data: bytes) -> str:
    """Format a row of bytes as UINT16 values."""
    values = interpret_as_uint16(data)
    return ' '.join(f'{v:5d}' for v in values)


def format_row_int32(data: bytes) -> str:
    """Format a row of bytes as INT32 values."""
    values = interpret_as_int32(data)
    return ' '.join(f'{v:11d}' for v in values)


def format_row_float(data: bytes) -> str:
    """Format a row of bytes as FLOAT values."""
    values = interpret_as_float(data)
    formatted = []
    for v in values:
        # Handle special float values
        if v != v:  # NaN check
            formatted.append('       NaN')
        elif abs(v) == float('inf'):
            formatted.append('       Inf' if v > 0 else '      -Inf')
        elif abs(v) < 0.0001 or abs(v) > 999999:
            formatted.append(f'{v:10.2e}')
        else:
            formatted.append(f'{v:10.3f}')
    return ' '.join(formatted)


# =============================================================================
# Section: Output Formatting
# =============================================================================

def print_identity(identity: DeviceIdentity) -> None:
    """Print device identity information to console."""
    print("CLICK PLC Identity Information")
    print("=" * 40)
    print(f"Vendor ID:      {identity.vendor_id} ({identity.vendor_name})")
    print(f"Device Type:    {identity.device_type} ({identity.device_type_name})")
    print(f"Product Code:   {identity.product_code}")
    print(f"Revision:       {identity.revision_major}.{identity.revision_minor}")
    print(f"Status:         0x{identity.status:04X}")
    print(f"Serial Number:  0x{identity.serial_number:08X} ({identity.serial_number})")
    print(f"Product Name:   {identity.product_name}")


def print_network_info(info: NetworkInfo) -> None:
    """Print network information to console."""
    print("CLICK PLC Network Information")
    print("=" * 40)
    print(f"IP Address:     {info.ip_address}")
    print(f"Subnet Mask:    {info.subnet_mask}")
    print(f"Gateway:        {info.gateway}")
    print(f"Hostname:       {info.hostname}")
    print(f"MAC Address:    {info.mac_address}")
    print(f"Link Speed:     {info.link_speed} Mbps")


def print_assembly_hex(assembly: AssemblyData, bytes_per_line: int = 16) -> None:
    """Print assembly data as hex dump only (legacy format)."""
    print(f"Assembly Data - Connection {assembly.connection} (Instance {assembly.instance})")
    print("=" * 70)
    print(f"Size: {assembly.size} bytes")
    print()

    if not assembly.data:
        print("No data")
        return

    # Hex dump header
    print(f"{'Offset':<8}  {'Hex':<{bytes_per_line * 3}}  ASCII")
    print("-" * 70)

    for offset in range(0, len(assembly.data), bytes_per_line):
        chunk = assembly.data[offset:offset + bytes_per_line]

        # Hex representation
        hex_str = ' '.join(f'{b:02x}' for b in chunk)

        # ASCII representation (printable chars only)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)

        print(f"0x{offset:04X}    {hex_str:<{bytes_per_line * 3}}  {ascii_str}")


def print_assembly_multiformat(assembly: AssemblyData, bytes_per_line: int = 16) -> None:
    """
    Print assembly data with multiple format interpretations.

    Displays hex dump followed by INT16, INT32, and FLOAT interpretations
    to help identify data types when configuration is unknown.
    """
    print(f"Assembly Data - Connection {assembly.connection} (Instance {assembly.instance})")
    print("=" * 100)
    print(f"Size: {assembly.size} bytes")
    print()

    if not assembly.data:
        print("No data")
        return

    # Section 1: Hex Dump with ASCII
    print("--- Hex Dump ---")
    print(f"{'Offset':<8}  {'Hex':<{bytes_per_line * 3}}  ASCII")
    print("-" * 78)

    for offset in range(0, len(assembly.data), bytes_per_line):
        chunk = assembly.data[offset:offset + bytes_per_line]
        hex_str = format_row_hex(chunk, bytes_per_line)
        ascii_str = interpret_as_ascii(chunk)
        print(f"0x{offset:04X}    {hex_str}  {ascii_str}")

    print()

    # Section 2: INT16 Interpretation (signed)
    print("--- INT16 Interpretation (signed, little-endian) ---")
    print(f"{'Offset':<8}  Values (8 x INT16 per row)")
    print("-" * 78)

    for offset in range(0, len(assembly.data), bytes_per_line):
        chunk = assembly.data[offset:offset + bytes_per_line]
        int16_str = format_row_int16(chunk)
        print(f"0x{offset:04X}    {int16_str}")

    print()

    # Section 3: INT32 Interpretation (signed)
    print("--- INT32 Interpretation (signed, little-endian) ---")
    print(f"{'Offset':<8}  Values (4 x INT32 per row)")
    print("-" * 78)

    for offset in range(0, len(assembly.data), bytes_per_line):
        chunk = assembly.data[offset:offset + bytes_per_line]
        int32_str = format_row_int32(chunk)
        print(f"0x{offset:04X}    {int32_str}")

    print()

    # Section 4: FLOAT Interpretation
    print("--- FLOAT Interpretation (IEEE 754, little-endian) ---")
    print(f"{'Offset':<8}  Values (4 x FLOAT per row)")
    print("-" * 78)

    for offset in range(0, len(assembly.data), bytes_per_line):
        chunk = assembly.data[offset:offset + bytes_per_line]
        float_str = format_row_float(chunk)
        print(f"0x{offset:04X}    {float_str}")

    print()

    # Section 5: Data summary
    print("--- Data Summary ---")
    total_int16 = len(assembly.data) // 2
    total_int32 = len(assembly.data) // 4
    print(f"Total INT16 values: {total_int16}")
    print(f"Total INT32 values: {total_int32}")
    print(f"Total FLOAT values: {total_int32}")
    print()
    print("Note: Data shown in all formats. Actual format depends on PLC configuration.")
    print("      DS registers are INT16, DD registers are INT32/FLOAT.")


# =============================================================================
# Section: Markdown Output
# =============================================================================

SCANNER_VERSION = "1.0.0"


def format_markdown_header(host: str, port: int) -> str:
    """Generate Markdown report header."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "# CLICK PLC EtherNet/IP Scan Report",
        "",
        "| Parameter | Value |",
        "|-----------|-------|",
        f"| Target | {host}:{port} |",
        f"| Date | {timestamp} |",
        f"| Scanner | click_enip_scanner.py v{SCANNER_VERSION} |",
        "",
    ]
    return '\n'.join(lines)


def format_markdown_identity(identity: DeviceIdentity) -> str:
    """Format device identity as Markdown."""
    lines = [
        "## Device Identity",
        "",
        "| Attribute | Value |",
        "|-----------|-------|",
        f"| Vendor ID | {identity.vendor_id} ({identity.vendor_name}) |",
        f"| Device Type | {identity.device_type} ({identity.device_type_name}) |",
        f"| Product Code | {identity.product_code} |",
        f"| Revision | {identity.revision_major}.{identity.revision_minor} |",
        f"| Status | 0x{identity.status:04X} |",
        f"| Serial Number | 0x{identity.serial_number:08X} ({identity.serial_number}) |",
        f"| Product Name | {identity.product_name} |",
        "",
    ]
    return '\n'.join(lines)


def format_markdown_network(info: NetworkInfo) -> str:
    """Format network information as Markdown."""
    lines = [
        "## Network Information",
        "",
        "| Parameter | Value |",
        "|-----------|-------|",
        f"| IP Address | {info.ip_address} |",
        f"| Subnet Mask | {info.subnet_mask} |",
        f"| Gateway | {info.gateway} |",
        f"| Hostname | {info.hostname} |",
        f"| MAC Address | {info.mac_address} |",
        f"| Link Speed | {info.link_speed} Mbps |",
        "",
    ]
    return '\n'.join(lines)


def format_markdown_assembly(assembly: AssemblyData, bytes_per_line: int = 16) -> str:
    """Format assembly data as Markdown with hex dump and interpretations."""
    lines = [
        f"## Assembly Data - Connection {assembly.connection}",
        "",
        "| Parameter | Value |",
        "|-----------|-------|",
        f"| Instance | {assembly.instance} |",
        f"| Size | {assembly.size} bytes |",
        "",
    ]

    if not assembly.data:
        lines.append("No data available.")
        lines.append("")
        return '\n'.join(lines)

    # Hex dump section
    lines.append("### Hex Dump")
    lines.append("")
    lines.append("```")
    lines.append(f"{'Offset':<8}  {'Hex':<{bytes_per_line * 3}}  ASCII")
    lines.append("-" * 70)

    for offset in range(0, len(assembly.data), bytes_per_line):
        chunk = assembly.data[offset:offset + bytes_per_line]
        hex_str = format_row_hex(chunk, bytes_per_line)
        ascii_str = interpret_as_ascii(chunk)
        lines.append(f"0x{offset:04X}    {hex_str}  {ascii_str}")

    lines.append("```")
    lines.append("")

    # INT16 interpretation section
    lines.append("### INT16 Interpretation (signed, little-endian)")
    lines.append("")
    lines.append("```")
    lines.append(f"{'Offset':<8}  Values (8 x INT16 per row)")
    lines.append("-" * 70)

    for offset in range(0, len(assembly.data), bytes_per_line):
        chunk = assembly.data[offset:offset + bytes_per_line]
        int16_str = format_row_int16(chunk)
        lines.append(f"0x{offset:04X}    {int16_str}")

    lines.append("```")
    lines.append("")

    # INT32 interpretation section
    lines.append("### INT32 Interpretation (signed, little-endian)")
    lines.append("")
    lines.append("```")
    lines.append(f"{'Offset':<8}  Values (4 x INT32 per row)")
    lines.append("-" * 70)

    for offset in range(0, len(assembly.data), bytes_per_line):
        chunk = assembly.data[offset:offset + bytes_per_line]
        int32_str = format_row_int32(chunk)
        lines.append(f"0x{offset:04X}    {int32_str}")

    lines.append("```")
    lines.append("")

    # FLOAT interpretation section
    lines.append("### FLOAT Interpretation (IEEE 754, little-endian)")
    lines.append("")
    lines.append("```")
    lines.append(f"{'Offset':<8}  Values (4 x FLOAT per row)")
    lines.append("-" * 70)

    for offset in range(0, len(assembly.data), bytes_per_line):
        chunk = assembly.data[offset:offset + bytes_per_line]
        float_str = format_row_float(chunk)
        lines.append(f"0x{offset:04X}    {float_str}")

    lines.append("```")
    lines.append("")

    # Data summary
    total_int16 = len(assembly.data) // 2
    total_int32 = len(assembly.data) // 4
    lines.append("### Data Summary")
    lines.append("")
    lines.append(f"- Total INT16 values: {total_int16}")
    lines.append(f"- Total INT32 values: {total_int32}")
    lines.append(f"- Total FLOAT values: {total_int32}")
    lines.append("")
    lines.append("**Note**: Data shown in all formats. Actual format depends on PLC configuration.")
    lines.append("DS registers are INT16, DD registers are INT32/FLOAT.")
    lines.append("")

    return '\n'.join(lines)


def format_markdown_footer() -> str:
    """Generate Markdown report footer."""
    lines = [
        "---",
        "",
        "*Generated by click_enip_scanner.py - For authorized security testing only.*",
        "",
    ]
    return '\n'.join(lines)


def generate_output_filename(host: str) -> str:
    """Generate output filename with timestamp."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Sanitize host for filename (replace dots with underscores)
    safe_host = host.replace('.', '_').replace(':', '_')
    return f"click_enip_scan_{safe_host}_{timestamp}.md"


def write_markdown_report(
    filepath: str,
    host: str,
    port: int,
    identity: Optional[DeviceIdentity],
    network: Optional[NetworkInfo],
    assembly: Optional[AssemblyData]
) -> Tuple[bool, str]:
    """
    Write scan results to Markdown file.

    Args:
        filepath: Output file path
        host: Target host
        port: Target port
        identity: Device identity data (or None)
        network: Network info data (or None)
        assembly: Assembly data (or None)

    Returns:
        Tuple of (success, error_message)
    """
    try:
        content = []

        # Header
        content.append(format_markdown_header(host, port))

        # Identity section
        if identity:
            content.append(format_markdown_identity(identity))

        # Network section
        if network:
            content.append(format_markdown_network(network))

        # Assembly section
        if assembly:
            content.append(format_markdown_assembly(assembly))

        # Footer
        content.append(format_markdown_footer())

        # Write to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(content))

        return True, ""

    except IOError as e:
        return False, f"Failed to write file: {e}"
    except Exception as e:
        return False, f"Error generating report: {e}"


# =============================================================================
# Section: CLI
# =============================================================================

def build_argument_parser() -> argparse.ArgumentParser:
    """Build and return the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="click_enip_scanner",
        description="Scan AutomationDirect CLICK PLC via EtherNet/IP CIP",
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
        help=f"EtherNet/IP port (default: {DEFAULT_PORT})"
    )

    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT})"
    )

    # Mutually exclusive display mode options
    display_group = parser.add_mutually_exclusive_group()
    display_group.add_argument(
        "--info", "-i",
        action="store_true",
        help="Display device identity information only"
    )
    display_group.add_argument(
        "--network", "-n",
        action="store_true",
        help="Display network information only"
    )
    display_group.add_argument(
        "--full", "-f",
        action="store_true",
        help="Display all information (identity + network + assembly data)"
    )

    parser.add_argument(
        "--connection", "-c",
        type=int,
        default=1,
        choices=[1, 2],
        help="EtherNet/IP connection number (default: 1)"
    )

    parser.add_argument(
        "--size", "-s",
        type=int,
        default=500,
        help="Maximum bytes to read from assembly (default: 500)"
    )

    parser.add_argument(
        "--hex",
        action="store_true",
        help="Display hex dump only (default: multi-format display)"
    )

    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        metavar="FILE",
        help="Write output to Markdown file (auto-generates timestamped filename if no path given)"
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
    # Host is required for scanning
    if not args.host:
        print("Error: Host argument is required")
        print("Usage: click_enip_scanner.py <host> [options]")
        print("Use --help for more information")
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

    # Validate size
    if args.size < 1 or args.size > 65535:
        print(f"Error: Invalid size: {args.size}")
        print("Size must be between 1 and 65535 bytes")
        return False

    # Validate output file extension if specified
    if args.output and not args.output.endswith('.md'):
        print(f"Error: Output file must have .md extension: {args.output}")
        print("Use --output report.md or --output /path/to/report.md")
        return False

    return True


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

    # Validate arguments
    if not validate_arguments(args):
        return 1

    # Attempt connection
    print(f"Connecting to {args.host}:{args.port}...")

    plc = connect_enip(
        host=args.host,
        port=args.port,
        timeout=args.timeout
    )

    if plc is None:
        return 1

    print(f"Connected to {args.host}:{args.port}")
    print()

    # Track collected data for Markdown output
    identity_data: Optional[DeviceIdentity] = None
    network_data: Optional[NetworkInfo] = None
    assembly_data: Optional[AssemblyData] = None

    try:
        # Determine what to display based on options
        if args.info:
            # Identity only
            success, identity_data, error = get_identity(plc)
            if success and identity_data:
                print_identity(identity_data)
                if error:
                    print(f"\nWarnings: {error}")
            else:
                print(f"Failed to read identity: {error}")
                return 1

        elif args.network:
            # Network info only
            success, network_data, error = get_network_info(plc)
            if success and network_data:
                print_network_info(network_data)
                if error:
                    print(f"\nWarnings: {error}")
            else:
                print(f"Failed to read network info: {error}")
                return 1

        elif args.full:
            # Full output: identity + network + assembly data
            # Identity
            success, identity_data, error = get_identity(plc)
            if success and identity_data:
                print_identity(identity_data)
                if error:
                    print(f"Warnings: {error}")
            else:
                print(f"Warning: Could not read identity: {error}")
            print()

            # Network
            success, network_data, error = get_network_info(plc)
            if success and network_data:
                print_network_info(network_data)
                if error:
                    print(f"Warnings: {error}")
            else:
                print(f"Warning: Could not read network info: {error}")
            print()

            # Assembly data
            success, assembly_data, warning = get_assembly_data(
                plc,
                connection=args.connection,
                max_size=args.size
            )

            if success and assembly_data:
                if warning:
                    print(f"Note: {warning}")
                    print()
                if args.hex:
                    print_assembly_hex(assembly_data)
                else:
                    print_assembly_multiformat(assembly_data)
            else:
                print(f"Failed to read assembly data: {warning}")
                return 1

        else:
            # Default: read assembly data with identity header
            success, identity_data, error = get_identity(plc)
            if success and identity_data:
                print_identity(identity_data)
                print()
            else:
                print(f"Warning: Could not read identity: {error}")
                print()

            # Read assembly data
            success, assembly_data, warning = get_assembly_data(
                plc,
                connection=args.connection,
                max_size=args.size
            )

            if success and assembly_data:
                if warning:
                    print(f"Note: {warning}")
                    print()
                if args.hex:
                    print_assembly_hex(assembly_data)
                else:
                    print_assembly_multiformat(assembly_data)
            else:
                print(f"Failed to read assembly data: {warning}")
                return 1

        # Write Markdown output if requested
        if args.output:
            output_path = args.output
            success, error = write_markdown_report(
                filepath=output_path,
                host=args.host,
                port=args.port,
                identity=identity_data,
                network=network_data,
                assembly=assembly_data
            )
            if success:
                print()
                print(f"Report written to: {output_path}")
            else:
                print()
                print(f"Warning: Failed to write report: {error}")

    finally:
        # Clean up
        disconnect_enip(plc)

    return 0


if __name__ == "__main__":
    sys.exit(main())

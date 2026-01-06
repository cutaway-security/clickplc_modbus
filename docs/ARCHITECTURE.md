# ARCHITECTURE.md - System Design

## Overview

This project contains two Python scripts for scanning AutomationDirect CLICK PLCs:

1. **click_mb_scanner.py** - Modbus TCP scanner (COMPLETE)
2. **click_enip_scanner.py** - EtherNet/IP CIP scanner (IN DEVELOPMENT)

---

# Part 1: Modbus Scanner (click_mb_scanner.py)

## Overview

Single Python script that communicates with AutomationDirect CLICK PLCs via Modbus TCP to read coil and register values. Outputs results to console, CSV, or Markdown.

---

## Script Organization

```
click_mb_scanner.py
    |
    +-- Section: Imports and Dependency Check
    |       - Standard library imports
    |       - PyModbus import with graceful failure
    |
    +-- Section: Constants
    |       - CLICK address type definitions
    |       - Modbus function code mappings
    |       - Default configuration values
    |       - Rate limiting presets
    |
    +-- Section: Data Structures
    |       - AddressType dataclass
    |       - ScanResult dataclass
    |       - Configuration dataclass
    |
    +-- Section: CSV Parsing
    |       - parse_click_csv() - Import CLICK project export
    |       - extract_used_addresses() - Filter for configured addresses
    |
    +-- Section: Modbus Communication
    |       - connect_to_plc() - Establish TCP connection
    |       - read_coils() - FC 01
    |       - read_discrete_inputs() - FC 02
    |       - read_holding_registers() - FC 03
    |       - read_input_registers() - FC 04
    |       - scan_address_range() - Iterate through addresses
    |
    +-- Section: Data Conversion
    |       - convert_to_int16() - Signed 16-bit
    |       - convert_to_int32() - Signed 32-bit (DD type)
    |       - convert_to_float() - IEEE 754 float (DF type)
    |       - convert_to_hex() - Hex display (DH type)
    |
    +-- Section: Output Formatting
    |       - format_console() - Tab-separated display
    |       - format_csv() - CSV file output
    |       - format_markdown() - Markdown report
    |
    +-- Section: CLI
    |       - build_argument_parser() - argparse setup
    |       - validate_arguments() - Input validation
    |
    +-- Section: Main
            - main() - Entry point
```

---

## CLICK PLC Address Types

### Priority 1: Physical I/O (Coils)

| Type | Description | Range | Modbus Start (HEX) | Function Code |
|------|-------------|-------|-------------------|---------------|
| X0 | CPU Input Points | 1-36 | 0x0000 | 02 (Read Discrete Inputs) |
| X1-X8 | Module Input Points | 1-16 each | 0x0020-0x0100 | 02 |
| Y0 | CPU Output Points | 1-36 | 0x2000 | 01 (Read Coils) |
| Y1-Y8 | Module Output Points | 1-16 each | 0x2020-0x2100 | 01 |

### Priority 2: Control Logic (Coils)

| Type | Description | Range | Modbus Start (HEX) | Function Code |
|------|-------------|-------|-------------------|---------------|
| C | Control Relays | 1-2000 | 0x4000 | 01 |
| T | Timer Status | 1-500 | 0xB000 | 01 |
| CT | Counter Status | 1-250 | 0xC000 | 01 |
| SC | System Control Relays | 1-1000 | 0xF000 | 01 |

### Priority 3: Data Registers

| Type | Description | Range | Modbus Start (HEX) | Function Code | Size |
|------|-------------|-------|-------------------|---------------|------|
| DS | Data Register (INT16) | 1-4500 | 0x0000 | 03 | 1 word |
| DD | Data Register (INT32) | 1-1000 | 0x4000 | 03 | 2 words |
| DF | Data Register (FLOAT) | 1-500 | 0x7000 | 03 | 2 words |
| DH | Data Register (HEX) | 1-500 | 0x6000 | 03 | 2 words |

### Priority 4: Timer/Counter Registers

| Type | Description | Range | Modbus Start (HEX) | Function Code | Size |
|------|-------------|-------|-------------------|---------------|------|
| TD | Timer Data | 1-500 | 0xB000 | 03 | 1 word |
| CTD | Counter Data | 1-250 | 0xC000 | 03 | 2 words |

### Priority 5: System and I/O Registers

| Type | Description | Range | Modbus Start (HEX) | Function Code | Size |
|------|-------------|-------|-------------------|---------------|------|
| SD | System Data Register | 1-1000 | 0xF000 | 03 | 1 word |
| XD | Input Register | 0-8 | 0xE000 | 04 | 2 words |
| YD | Output Register | 0-8 | 0xE200 | 03 | 2 words |
| TXT | Text Data | 1-1000 | 0x9000 | 03 | 2 words |

---

## Modbus Function Codes Used

| Code | Name | CLICK Usage |
|------|------|-------------|
| 01 | Read Coils | Y, C, T, CT, SC |
| 02 | Read Discrete Inputs | X |
| 03 | Read Holding Registers | DS, DD, DH, DF, TD, CTD, SD, YD, TXT |
| 04 | Read Input Registers | XD |

---

## Address Format Conversion

### HEX Format (Default)
- Coils: 0x0000 - 0xFFFF
- Registers: 0x0000 - 0xFFFF

### 984 Format (Optional)
- Discrete Inputs (FC 02): 100001 - 165536
- Coils (FC 01): 000001 - 065536
- Input Registers (FC 04): 300001 - 365536
- Holding Registers (FC 03): 400001 - 465536

**Conversion**: 984 address = (function_prefix * 100000) + modbus_address + 1

---

## Data Structures

### AddressType
```python
@dataclass
class AddressType:
    name: str           # e.g., "DS", "DF", "X0"
    description: str    # e.g., "Data Register (INT16)"
    start_address: int  # Modbus start address (0-based)
    count: int          # Number of addresses in range
    function_code: int  # 1, 2, 3, or 4
    word_size: int      # 1 or 2 (registers only)
    data_format: str    # "bool", "int16", "int32", "float", "hex"
```

### ScanResult
```python
@dataclass
class ScanResult:
    address_type: str   # e.g., "DS"
    click_address: str  # e.g., "DS1"
    modbus_hex: str     # e.g., "0x0000"
    modbus_984: str     # e.g., "400001"
    raw_value: int      # Raw register/coil value
    converted_value: Any  # Formatted based on data type
    nickname: str       # From CSV config, or empty
```

---

## Rate Limiting

| Preset | Delay Between Requests | Use Case |
|--------|----------------------|----------|
| normal | 50ms | Local network, modern PLC |
| moderate | 200ms | Shared network, older PLC |
| slow | 500ms | WAN connection, sensitive environment |

---

## Error Handling Strategy

### Connection Errors
- Timeout after 5 seconds
- Retry up to 3 times with exponential backoff
- Clear error message with troubleshooting hints

### Read Errors
- Log specific Modbus exception codes
- Continue scanning remaining addresses
- Report failed addresses in summary

### Invalid Input
- Validate IP address format
- Validate port range (1-65535)
- Validate address type names
- Validate CSV format before processing

---

## Output Formats

### Console (Tab-Separated)
```
Address    Value    Description
DS1        0        Data Register 1
DS2        100      Temperature Setpoint
DF1        23.5     Current Temperature
```

### CSV
```csv
address_type,click_address,modbus_hex,modbus_984,raw_value,converted_value,nickname
DS,DS1,0x0000,400001,0,0,
DS,DS2,0x0001,400002,100,100,Temperature Setpoint
DF,DF1,0x7000,428673,17096,23.5,Current Temperature
```

### Markdown
```markdown
# CLICK PLC Scan Results

**Target**: 192.168.1.10:502
**Date**: 2025-01-05 14:30:00
**Types Scanned**: DS, DF

## Data Registers (DS)

| Address | Value | Description |
|---------|-------|-------------|
| DS1 | 0 | |
| DS2 | 100 | Temperature Setpoint |

## Data Registers Float (DF)

| Address | Value | Description |
|---------|-------|-------------|
| DF1 | 23.5 | Current Temperature |
```

---

## CSV Configuration Import

The script accepts CSV files exported from CLICK Programming Software.

### CSV Export Formats

Two export formats are available from CLICK Programming Software:

#### HEX Format
- Modbus Address uses hex with 'h' suffix (e.g., "0000h", "4001h", "7000h")
- Parse by stripping 'h' suffix and converting from hexadecimal

#### 984 Format
- Modbus Address uses decimal (e.g., "100001", "400001", "428673")
- Standard 984 ranges: FC02 (1xxxxx), FC03 (4xxxxx), FC04 (3xxxxx)
- CLICK uses non-standard ranges for some coil types (Y, C)

### CSV Columns

| Column | Description | Example |
|--------|-------------|---------|
| Address | CLICK address | "X001", "DS1", "DD3" |
| Data Type | BIT, INT, INT2, FLOAT | "BIT", "INT2", "FLOAT" |
| Modbus Address | HEX or 984 format | "0000h" or "100001" |
| Function Code | FC codes (quoted) | "FC=02", "FC=03,06,16" |
| Nickname | Tag name (may be empty) | "Tank_PSI_Display" |
| Initial Value | Default value | 0 |
| Retentive | Memory retention | "Yes", "No" |
| Address Comment | Description (ignored) | "Tank Pressure Display" |

### Nickname Handling
- Use Nickname field for display when available
- For empty nicknames, use CLICK Address as display name
- Do not truncate nicknames (important info may be at end)

### Test Files
- CLICKPLUS_C203CPU2_w2_C208DR6V_3_41_Modbus_Addresses_HEX.csv
- CLICKPLUS_C203CPU2_w2_C208DR6V_3_41_Modbus_Addresses_984.csv

### Filtering Logic
1. Parse CSV file (auto-detect HEX vs 984 format)
2. Extract all addresses from CSV
3. Group by address type
4. Generate scan list with nicknames

---

# Part 2: EtherNet/IP Scanner (click_enip_scanner.py)

## Overview

Single Python script that communicates with AutomationDirect CLICK PLCs via EtherNet/IP CIP Explicit Messaging to read configured data assemblies and device information. Outputs results to console or Markdown.

---

## Protocol Details

| Parameter | Value |
|-----------|-------|
| Protocol | EtherNet/IP CIP |
| Port | 44818 (default) |
| Messaging Type | Explicit (Unconnected) |
| Service | Get Attribute Single (0x0E) |
| Library | CPPPO 5.x (proxy_simple) |

**Important Notes**:
- CLICK operates as an Adapter (responds to connections, does not initiate)
- CLICK does NOT support Tag-Based (Symbolic) messaging or PCCC
- Maximum 2 concurrent EtherNet/IP connections
- Must use CPPPO's proxy_simple class (simple CIP device, not routing)

---

## CIP Addressing

CLICK exposes data via Assembly Objects with fixed Class/Instance/Attribute paths:

| Connection | Direction | Object Class | Instance | Attribute | CPPPO Path |
|------------|-----------|--------------|----------|-----------|------------|
| 1 | Input (T->O) | 4 | 101 (0x65) | 3 | @4/101/3 |
| 1 | Output (O->T) | 4 | 102 (0x66) | 3 | @4/102/3 |
| 2 | Input (T->O) | 4 | 103 (0x67) | 3 | @4/103/3 |
| 2 | Output (O->T) | 4 | 104 (0x68) | 3 | @4/104/3 |

**Note**: Input data is what CLICK sends TO the scanner. Output data is what the scanner writes TO CLICK (not used in read-only mode).

---

## Standard CIP Objects

| Object | Class | Instance | Attributes | Purpose |
|--------|-------|----------|------------|---------|
| Identity | 0x01 | 1 | 1-7 | Device identification (--info) |
| TCP/IP Interface | 0xF5 | 1 | Various | Network configuration (--network) |
| Ethernet Link | 0xF6 | 1 | Various | Ethernet statistics (--network) |
| Assembly | 0x04 | 101-104 | 3 | Configured data blocks (default) |

### Identity Object Attributes (Class 0x01, Instance 1)

| Attribute | Type | Description |
|-----------|------|-------------|
| 1 | UINT | Vendor ID |
| 2 | UINT | Device Type |
| 3 | UINT | Product Code |
| 4 | Revision | Major.Minor Revision |
| 5 | WORD | Status |
| 6 | UDINT | Serial Number |
| 7 | SHORT_STRING | Product Name |

### TCP/IP Interface Object Attributes (Class 0xF5, Instance 1)

| Attribute | Type | Description |
|-----------|------|-------------|
| 1 | UDINT | Status |
| 2 | UDINT | Configuration Capability |
| 3 | UDINT | Configuration Control |
| 5 | Struct | Interface Configuration (IP, Subnet, Gateway) |
| 6 | STRING | Host Name |

---

## Known Test Configuration

The test PLC has the following EtherNet/IP Adapter configuration:

**Connection 1 Input (to Scanner):**

| CLICK Address | Range | Byte Offset | Size | Data Type |
|---------------|-------|-------------|------|-----------|
| DS1-DS72 | 72 registers | 0-143 | 144 bytes | INT16 |
| DD3-DD74 | 72 registers | 144-431 | 288 bytes | INT32 |
| **Total** | | | **432 bytes** | |

---

## Data Interpretation Strategy

Since PLC configuration is typically unknown during assessments, data must be displayed in multiple formats simultaneously:

| Interpretation | Description | Use Case |
|----------------|-------------|----------|
| HEX | Raw bytes as hexadecimal | Low-level analysis |
| INT16 | Signed 16-bit integers (little-endian) | DS registers |
| UINT16 | Unsigned 16-bit integers | Positive values |
| INT32 | Signed 32-bit integers (little-endian) | DD registers |
| FLOAT | IEEE 754 single precision | DF registers |
| ASCII | Printable characters | TXT registers |

### Multi-Format Display Example

```
EtherNet/IP Assembly Data - Connection 1 Input (@4/101/3)
Read: 432 bytes

Offset    Hex (16 bytes)                            INT16[0-7]           INT32[0-3]           ASCII
--------  ----------------------------------------  -------------------  -------------------  ----------------
0x0000    01 00 64 00 FF FF 00 00 00 00 00 00 ...  1, 100, -1, 0 ...    6553601, -1, 0 ...   ..d.............
0x0010    ...
```

---

## Script Organization

```
click_enip_scanner.py
    |
    +-- Section: Imports and Dependency Check
    |       - Standard library imports
    |       - pycomm3 import with graceful failure
    |
    +-- Section: Constants
    |       - CIP object definitions (classes, instances, attributes)
    |       - Assembly instance mappings
    |       - Default configuration values
    |
    +-- Section: Data Structures
    |       - DeviceIdentity dataclass
    |       - NetworkInfo dataclass
    |       - AssemblyData dataclass
    |
    +-- Section: CIP Communication
    |       - connect_enip() - Establish EtherNet/IP session
    |       - get_identity() - Read Identity Object (--info)
    |       - get_network_info() - Read TCP/IP and Ethernet Link (--network)
    |       - get_assembly_data() - Read Assembly Object (default)
    |
    +-- Section: Data Interpretation
    |       - interpret_as_int16() - Little-endian signed 16-bit
    |       - interpret_as_uint16() - Little-endian unsigned 16-bit
    |       - interpret_as_int32() - Little-endian signed 32-bit
    |       - interpret_as_float() - IEEE 754 single precision
    |       - interpret_as_hex() - Raw bytes as hex string
    |       - interpret_as_ascii() - Printable characters
    |       - multi_format_display() - Combined interpretation view
    |
    +-- Section: Output Formatting
    |       - print_identity() - Device info display
    |       - print_network_info() - Network info display
    |       - print_assembly_multiformat() - Multi-format data display
    |       - format_markdown() - Markdown report (planned)
    |
    +-- Section: CLI
    |       - build_argument_parser() - argparse setup
    |       - validate_arguments() - Input validation
    |
    +-- Section: Main
            - main() - Entry point
```

---

## CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `<host>` | PLC IP address or hostname | Required |
| `--port` | EtherNet/IP port | 44818 |
| `--timeout` | Connection timeout in seconds | 5 |
| `--info` | Display device identity information | Off |
| `--network` | Display network information | Off |
| `--full` | Display all: info + network + data | Off |
| `--size` | Bytes to read from assembly | 500 |
| `--connection` | Connection number (1 or 2) | 1 |
| `--hex` | Display hex dump only (no multi-format) | Off |
| `--output` | Output file (.md only) | Console |

### Option Behavior

| Mode | Action |
|------|--------|
| (default) | Read Assembly data with identity header, multi-format display |
| --info | Read Identity Object only |
| --network | Read TCP/IP Interface and Ethernet Link Objects only |
| --full | --info + --network + assembly data (comprehensive view) |
| --hex | Use with default/--full for hex-only assembly output |

---

## Error Handling Strategy

### Connection Errors
- Timeout after configurable seconds (default 5)
- Clear error message with CIP error code if available
- Suggest checking port, IP, and PLC configuration

### CIP Errors
- Parse General Status and Extended Status codes
- Reference CLICK EtherNet/IP Error Code documentation
- Provide user-friendly error descriptions

### Assembly Size Mismatch
- Handle case where requested size exceeds configured size
- Report actual bytes returned with warning message
- Continue with available data

---

## Output Formats

### Console - Device Identity (--info)
```
CLICK PLC Identity Information
==============================
Vendor ID:      898 (AutomationDirect)
Device Type:    14 (Programmable Logic Controller)
Product Code:   1234
Revision:       3.41
Serial Number:  0x12345678
Product Name:   CLICK PLUS CPU
```

### Console - Network Information (--network)
```
CLICK PLC Network Information
=============================
IP Address:     192.168.0.10
Subnet Mask:    255.255.255.0
Gateway:        192.168.0.1
MAC Address:    00:0C:F1:XX:XX:XX
```

### Console - Assembly Data (default)
```
EtherNet/IP Assembly Data
=========================
Target:     192.168.0.10:44818
Connection: 1 (Instance 101)
Read:       432 bytes

Offset    Hex (16 bytes)                            INT16           INT32           ASCII
--------  ----------------------------------------  --------------  --------------  ----------------
0x0000    01 00 64 00 FF FF 00 00 00 00 00 00 ...  1, 100, -1 ...  6553601, -1 ... ..d.............
...
```

### Markdown Report
```markdown
# CLICK PLC EtherNet/IP Scan Report

**Target**: 192.168.0.10:44818
**Date**: 2026-01-05 14:30:00
**Scanner**: click_enip_scanner.py

## Device Identity

| Attribute | Value |
|-----------|-------|
| Vendor ID | 898 (AutomationDirect) |
| Device Type | 14 (PLC) |
| Product Code | 1234 |
| Revision | 3.41 |
| Serial Number | 0x12345678 |
| Product Name | CLICK PLUS CPU |

## Network Information

| Parameter | Value |
|-----------|-------|
| IP Address | 192.168.0.10 |
| Subnet Mask | 255.255.255.0 |
| Gateway | 192.168.0.1 |
| MAC Address | 00:0C:F1:XX:XX:XX |

## Assembly Data

Connection 1 Input (Instance 101) - 432 bytes

### Raw Hex Dump
...

### Interpreted as INT16
...
```

---

## pycomm3 Usage Notes

### Primary Library for CLICK PLCs

pycomm3 CIPDriver.generic_message() works reliably with CLICK PLCs:

```python
from pycomm3 import CIPDriver

# Connect to CLICK PLC
with CIPDriver("192.168.0.10") as plc:
    # Read Identity Vendor ID (Class 1, Instance 1, Attribute 1)
    result = plc.generic_message(
        service=0x0E,       # Get Attribute Single
        class_code=0x01,    # Identity Object
        instance=0x01,
        attribute=0x01,     # Vendor ID
    )
    if not result.error:
        vendor_id = struct.unpack('<H', result.value)[0]

    # Read Assembly Instance 101, Attribute 3
    result = plc.generic_message(
        service=0x0E,
        class_code=0x04,    # Assembly Object
        instance=101,
        attribute=0x03,     # Data attribute
    )
    if not result.error:
        raw_bytes = result.value  # Returns bytes object
```

### CPPPO Notes (Not Recommended)

CPPPO was originally planned but has compatibility issues with CLICK PLCs:
- `list_identity()` works for device discovery
- `proxy_simple.read()` fails with "Service not supported" (Status 0x08)
- CPPPO appears to use Read Tag service instead of Get Attribute Single

### Data Byte Order

- All multi-byte values use little-endian byte order
- IP addresses in TCP/IP Interface Object: stored as UDINT in little-endian
- Parse with `struct.unpack('<H', data)` for UINT, `struct.unpack('<I', data)` for UDINT

---

## Dependencies

| Dependency | Version | Purpose | Required |
|------------|---------|---------|----------|
| Python | 3.11+ | Runtime | Yes |
| pycomm3 | 1.x+ | EtherNet/IP CIP | Yes |

**Note**: This scanner uses EtherNet/IP CIP only - no Modbus dependency.

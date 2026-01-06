# ARCHITECTURE.md - System Design

## Overview

This project contains three scripts for scanning AutomationDirect CLICK PLCs:

1. **click_mb_scanner.py** - Modbus TCP scanner (COMPLETE)
2. **click_enip_scanner.py** - EtherNet/IP CIP scanner (COMPLETE)
3. **click-plc-info.nse** - Nmap NSE combined scanner (IN DEVELOPMENT)

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
- File typically named with "_HEX" suffix

#### 984 Format
- Modbus Address uses 984 convention (e.g., "400001", "404001", "407001")
- File typically named with "_984" suffix

### Auto-Detection Logic

The script auto-detects format by checking the first data row:
1. If Modbus Address ends with 'h' -> HEX format
2. If Modbus Address is numeric and > 100000 -> 984 format
3. Otherwise -> Error

---

# Part 2: EtherNet/IP Scanner (click_enip_scanner.py)

## Overview

Single Python script that communicates with AutomationDirect CLICK PLCs via EtherNet/IP CIP Explicit Messaging. Reads device identity, network configuration, and assembly data. Outputs to console or Markdown.

---

## CIP Object Model

### Identity Object (Class 0x01)

| Attribute | ID | Type | Description |
|-----------|-----|------|-------------|
| Vendor ID | 1 | UINT | 898 = AutomationDirect |
| Device Type | 2 | UINT | 14 = PLC |
| Product Code | 3 | UINT | Model identifier |
| Revision | 4 | STRUCT | Major.Minor |
| Status | 5 | WORD | Device status flags |
| Serial Number | 6 | UDINT | Unique identifier |
| Product Name | 7 | STRING | Device name |

### TCP/IP Interface Object (Class 0xF5)

| Attribute | ID | Type | Description |
|-----------|-----|------|-------------|
| Status | 1 | DWORD | Interface status |
| Config Capability | 2 | DWORD | Configuration options |
| Config Control | 3 | DWORD | Active configuration |
| Physical Link | 4 | STRUCT | Link object path |
| Interface Config | 5 | STRUCT | IP, Subnet, Gateway, DNS |
| Host Name | 6 | STRING | Device hostname |

### Ethernet Link Object (Class 0xF6)

| Attribute | ID | Type | Description |
|-----------|-----|------|-------------|
| Interface Speed | 1 | UDINT | Speed in Mbps |
| Interface Flags | 2 | DWORD | Link status flags |
| Physical Address | 3 | ARRAY[6] | MAC address |

### Assembly Object (Class 0x04)

| Instance | Direction | Description |
|----------|-----------|-------------|
| 100 | Output | Data TO scanner (Connection 1) |
| 101 | Input | Data FROM scanner (Connection 1) |
| 102 | Output | Data TO scanner (Connection 2) |
| 103 | Input | Data FROM scanner (Connection 2) |

**Note**: CLICK uses Input Assembly (Instance 101/103) for reading PLC data.

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

---

# Part 3: NSE Script (click-plc-info.nse)

## Overview

Nmap NSE script that combines Modbus TCP and EtherNet/IP detection for CLICK PLCs. Provides device information, network configuration, and basic I/O data query in a single scan.

---

## Script Organization

```
click-plc-info.nse
    |
    +-- Section: Headers
    |       - description, usage, output examples
    |       - author, license, categories
    |
    +-- Section: Requirements
    |       - local imports (comm, nmap, shortport, stdnse, string, table)
    |
    +-- Section: Portrule
    |       - Match ports 502 (Modbus) and 44818 (ENIP)
    |       - Support TCP and UDP
    |
    +-- Section: Lookup Tables
    |       - vendor_id (minimal: AutomationDirect, Rockwell, etc.)
    |       - device_type (PLC, Communications Adapter, etc.)
    |
    +-- Section: ENIP Functions
    |       - form_enip_list_identity() - Build List Identity packet
    |       - parse_enip_response() - Extract device info
    |       - enip_scan() - Main ENIP handler
    |
    +-- Section: Modbus Functions
    |       - form_modbus_request() - Build MBAP + PDU
    |       - parse_modbus_response() - Extract data bytes
    |       - read_input_registers() - FC 04 wrapper
    |       - read_holding_registers() - FC 03 wrapper
    |       - read_coils() - FC 01 wrapper
    |       - read_discrete_inputs() - FC 02 wrapper
    |       - modbus_scan() - Main Modbus handler
    |
    +-- Section: Data Conversion
    |       - bytes_to_int16() - Little-endian signed 16-bit
    |       - bytes_to_int32() - Little-endian signed 32-bit
    |       - format_ip() - Dotted decimal
    |       - format_mac() - Colon-separated hex
    |       - format_firmware() - Version string
    |
    +-- Section: Action
            - action(host, port) - Main entry point
            - Protocol detection and routing
            - Result aggregation
```

---

## Script Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `click-plc-info.modbus-only` | boolean | false | Skip ENIP, scan Modbus only |
| `click-plc-info.enip-only` | boolean | false | Skip Modbus, scan ENIP only |
| `click-plc-info.unit-id` | integer | 0 | Modbus Unit ID |
| `click-plc-info.coil-count` | integer | 10 | Number of X/Y coils to read |
| `click-plc-info.reg-count` | integer | 10 | Number of DS/DD registers to read |
| `click-plc-info.udp` | boolean | false | Use UDP for ENIP (default TCP) |

---

## Protocol Detection

```lua
portrule = shortport.port_or_service({502, 44818}, {"modbus", "EtherNet-IP-2"}, {"tcp", "udp"})
```

### Action Logic

```
if port == 502 then
    return modbus_scan(host, port)
elseif port == 44818 then
    return enip_scan(host, port)
end
```

---

## Modbus Data Collection

### Device Information (SD Registers)

| Data | SD Address | Modbus HEX | FC | Words |
|------|------------|------------|-----|-------|
| Firmware Version | SD5-SD8 | 0xF004-F007 | 04 | 4 |
| IP Address | SD80-SD83 | 0xF04F-F052 | 04 | 4 |
| Subnet Mask | SD84-SD87 | 0xF053-F056 | 04 | 4 |
| Gateway | SD88-SD91 | 0xF057-F05A | 04 | 4 |
| MAC Address | SD188-SD193 | 0xF0BB-F0C0 | 04 | 6 |
| EIP Status | SD101-SD102 | 0xF064-F065 | 04 | 2 |

### I/O Data

| Data | Type | FC | Start Address | Default Count |
|------|------|-----|---------------|---------------|
| Inputs (X) | Discrete Inputs | 02 | 0x0000 | 10 coils |
| Outputs (Y) | Coils | 01 | 0x2000 | 10 coils |
| DS Registers | Holding Registers | 03 | 0x0000 | 10 registers |
| DD Registers | Holding Registers | 03 | 0x4000 | 10 registers (20 words) |

### Modbus TCP Frame Format

```
MBAP Header (7 bytes):
  [0-1] Transaction ID: 0x0001 (increment per request)
  [2-3] Protocol ID: 0x0000 (Modbus)
  [4-5] Length: number of following bytes
  [6]   Unit ID: 0x00 (default for CLICK)

PDU:
  [0]   Function Code: 01, 02, 03, or 04
  [1-2] Starting Address: big-endian
  [3-4] Quantity: big-endian
```

### Response Parsing

```
MBAP Header (7 bytes): same as request
PDU:
  [0]   Function Code: echoed (or +0x80 for exception)
  [1]   Byte Count: number of data bytes
  [2-n] Data: coils packed as bits, registers as 2-byte words
```

---

## ENIP Data Collection

### List Identity Packet

```
Encapsulation Header (24 bytes):
  [0-1]   Command: 0x0063 (List Identity)
  [2-3]   Length: 0x0000
  [4-7]   Session Handle: 0x00000000
  [8-11]  Status: 0x00000000
  [12-19] Sender Context: 8 bytes (arbitrary)
  [20-23] Options: 0x00000000
```

### Response Parsing

| Offset | Field | Size | Description |
|--------|-------|------|-------------|
| 0 | Command | 2 | 0x0063 |
| 2 | Length | 2 | Data length |
| 24 | Item Count | 2 | Number of items |
| 26 | Type ID | 2 | 0x000C (Identity) |
| 28 | Length | 2 | Identity data length |
| 30 | Encap Version | 2 | Protocol version |
| 32 | Socket Address | 16 | IP and port |
| 48 | Vendor ID | 2 | Vendor identifier |
| 50 | Device Type | 2 | Device category |
| 52 | Product Code | 2 | Model number |
| 54 | Revision | 2 | Major.Minor |
| 56 | Status | 2 | Device status |
| 58 | Serial Number | 4 | Unique ID |
| 62 | Product Name Length | 1 | String length |
| 63 | Product Name | var | Device name |
| +1 | State | 1 | Device state |

---

## Vendor ID Table (Minimal)

```lua
local vendor_id = {
    [0] = "Reserved",
    [1] = "Rockwell Automation/Allen-Bradley",
    [47] = "Omron",
    [82] = "Mitsubishi Electric",
    [145] = "Siemens",
    [898] = "AutomationDirect",
}
```

---

## Device Type Table

```lua
local device_type = {
    [0] = "Generic Device",
    [2] = "AC Drive",
    [7] = "General Purpose Discrete I/O",
    [12] = "Communications Adapter",
    [14] = "Programmable Logic Controller",
    [24] = "Human-Machine Interface",
    [43] = "Generic Device (keyable)",
}
```

---

## Expected Output Format

### Modbus (Port 502)

```
PORT      STATE SERVICE
502/tcp   open  modbus
| click-plc-info:
|   Modbus Device Information:
|     Firmware: 3.41
|     IP Address: 192.168.0.10
|     Subnet Mask: 255.255.255.0
|     Gateway: 192.168.0.1
|     MAC Address: 00:0D:7C:1A:42:44
|     EIP Enabled: Yes (Status: 0x0001)
|   Inputs (X001-X010): 0 0 0 0 0 0 0 0 0 0
|   Outputs (Y001-Y010): 0 0 0 1 0 0 0 0 0 0
|   DS Registers (DS1-DS10): 0, 100, 0, 0, 0, 0, 0, 0, 0, 0
|_  DD Registers (DD1-DD10): 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
```

### ENIP (Port 44818)

```
PORT       STATE SERVICE
44818/tcp  open  EtherNet-IP-2
| click-plc-info:
|   Vendor: AutomationDirect (898)
|   Device Type: Programmable Logic Controller (14)
|   Product Name: CLICK PLUS CPU
|   Serial Number: 0x12345678
|   Product Code: 1234
|   Revision: 3.41
|   Status: 0x0030
|_  State: 0x03
```

---

## Data Type Conversions

### INT16 (DS Registers)

```lua
local function bytes_to_int16(b1, b2)
    local val = b1 + (b2 * 256)  -- little-endian
    if val >= 32768 then
        val = val - 65536  -- signed
    end
    return val
end
```

### INT32 (DD Registers)

```lua
local function bytes_to_int32(b1, b2, b3, b4)
    -- Little-endian word order: low word first
    local low_word = b1 + (b2 * 256)
    local high_word = b3 + (b4 * 256)
    local val = low_word + (high_word * 65536)
    if val >= 2147483648 then
        val = val - 4294967296  -- signed
    end
    return val
end
```

### IP Address

```lua
local function format_ip(b1, b2, b3, b4)
    return string.format("%d.%d.%d.%d", b1, b2, b3, b4)
end
```

### MAC Address

```lua
local function format_mac(b1, b2, b3, b4, b5, b6)
    return string.format("%02X:%02X:%02X:%02X:%02X:%02X", b1, b2, b3, b4, b5, b6)
end
```

---

## Error Handling

### Modbus Exceptions

| Code | Name | Action |
|------|------|--------|
| 0x01 | Illegal Function | Skip, continue |
| 0x02 | Illegal Data Address | Skip, continue |
| 0x03 | Illegal Data Value | Skip, continue |
| 0x04 | Slave Device Failure | Skip, continue |

On exception or timeout, omit that data section from output (minimal error reporting).

### ENIP Errors

On invalid response or timeout, return nil (no output for that port).

---

## Socket Handling

### TCP (Default)

```lua
local socket = nmap.new_socket()
socket:set_timeout(stdnse.get_timeout(host))
local status, err = socket:connect(host, port)
-- send/receive
socket:close()
```

### UDP (ENIP only)

```lua
local socket = nmap.new_socket("udp")
socket:set_timeout(stdnse.get_timeout(host))
local status, err = socket:connect(host, port)
-- send/receive
socket:close()
```

---

## Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| Nmap | 7.x+ | NSE runtime |
| Lua | 5.3+ | Scripting (bundled with Nmap) |

---

## Usage Examples

### Scan Both Protocols

```bash
nmap --script click-plc-info -p 502,44818 192.168.0.10
```

### Modbus Only

```bash
nmap --script click-plc-info --script-args='click-plc-info.modbus-only=true' -p 502 192.168.0.10
```

### ENIP Only (UDP)

```bash
nmap --script click-plc-info --script-args='click-plc-info.enip-only=true,click-plc-info.udp=true' -sU -p 44818 192.168.0.10
```

### Custom Unit ID and Counts

```bash
nmap --script click-plc-info --script-args='click-plc-info.unit-id=1,click-plc-info.coil-count=20,click-plc-info.reg-count=20' -p 502 192.168.0.10
```

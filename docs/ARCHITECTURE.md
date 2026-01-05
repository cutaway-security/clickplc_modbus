# ARCHITECTURE.md - System Design

## Overview

Single Python script that communicates with AutomationDirect CLICK PLCs via Modbus TCP to read coil and register values. Outputs results to console, CSV, or Markdown.

---

## Script Organization

```
click_modbus_scanner.py
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

### Expected CSV Columns
- Address (e.g., "DS1", "DF100")
- Data Type (e.g., "INT", "FLOAT")
- Modbus Address (HEX or 984 format)
- Function Code (e.g., "03,06,16")
- Nickname (user-assigned name)
- Initial Value
- Retentive (Yes/No)
- Address Comment

### Filtering Logic
1. Parse CSV file
2. Extract addresses with non-empty Nickname (indicates configured/used)
3. Group by address type
4. Generate scan list

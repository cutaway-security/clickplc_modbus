# USAGE.md - Detailed Usage Guide

## Table of Contents

- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Command-Line Options](#command-line-options)
- [Address Types](#address-types)
- [Output Formats](#output-formats)
- [Using CLICK Project CSV Files](#using-click-project-csv-files)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [CLICK PLC Modbus Reference](#click-plc-modbus-reference)

---

## Installation

### Requirements

- Python 3.11 or higher
- PyModbus 3.x

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Verify Installation

```bash
python click_modbus_scanner.py --help
```

---

## Basic Usage

### Scan Common Address Types

```bash
python click_modbus_scanner.py <PLC_IP>
```

This scans the default "common" types: X0, Y0, C, DS, DD, DF - covering physical I/O, control relays, and common data registers.

### Scan Specific Types

```bash
python click_modbus_scanner.py <PLC_IP> --type DS,DF,X0
```

### List Available Address Types

```bash
python click_modbus_scanner.py --list
```

---

## Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `<host>` | PLC IP address or hostname | Required |
| `--port PORT` | Modbus TCP port | 502 |
| `--timeout SEC` | Connection timeout in seconds | 5 |
| `--type TYPES` | Comma-separated address types to scan | Common types |
| `--full` | Scan all 32 address types | Off |
| `--config FILE` | CLICK project CSV for filtered scanning | None |
| `--output FILE` | Output file (.csv or .md) | Console |
| `--format FMT` | Address format: `hex` or `984` | hex |
| `--rate RATE` | Scan rate: `normal`, `moderate`, `slow` | normal |
| `--list` | Display available address types and exit | - |

### Rate Limiting

| Rate | Delay | Use Case |
|------|-------|----------|
| `normal` | 50ms | Standard scanning |
| `moderate` | 200ms | Busy networks |
| `slow` | 500ms | Sensitive environments |

---

## Address Types

CLICK PLCs support 32 address types organized by function:

### Discrete Inputs (FC 02)

| Type | Description | Count | Priority |
|------|-------------|-------|----------|
| X0 | CPU discrete inputs | 36 | Common |
| X1-X8 | Expansion module inputs | 16 each | Extended |

### Coil Outputs (FC 01)

| Type | Description | Count | Priority |
|------|-------------|-------|----------|
| Y0 | CPU discrete outputs | 36 | Common |
| Y1-Y8 | Expansion module outputs | 16 each | Extended |
| C | Control relays | 2000 | Common |
| T | Timer status bits | 500 | Extended |
| CT | Counter status bits | 250 | Extended |
| SC | System control relays | 1000 | Extended |

### Data Registers (FC 03)

| Type | Description | Data Type | Count | Priority |
|------|-------------|-----------|-------|----------|
| DS | Data registers | INT16 | 4500 | Common |
| DD | Double data registers | INT32 | 1000 | Common |
| DH | Hex data registers | HEX32 | 500 | Extended |
| DF | Float data registers | FLOAT | 500 | Common |
| TD | Timer current values | INT32 | 500 | Extended |
| CTD | Counter current values | INT32 | 250 | Extended |
| SD | System data registers | INT16 | 1000 | Extended |
| TXT | Text registers | HEX32 | 1000 | Extended |

### I/O Registers (FC 03/04)

| Type | Description | Data Type | Count | FC |
|------|-------------|-----------|-------|-----|
| XD | Discrete input registers | HEX32 | 9 | 04 |
| YD | Discrete output registers | HEX32 | 9 | 03 |

---

## Output Formats

### Console Output

Default output shows a formatted table:

```
Scanning X0 (CPU Discrete Inputs)...
Address      Modbus Addr    Value    Name
X001         0x0000         False    Start_Button
X002         0x0001         True     Stop_Button
X003         0x0002         False    X003
```

### CSV Output

```bash
python click_modbus_scanner.py 192.168.0.10 --output results.csv
```

CSV includes columns: `address_type`, `click_address`, `modbus_hex`, `modbus_984`, `raw_value`, `converted_value`, `nickname`

### Markdown Output

```bash
python click_modbus_scanner.py 192.168.0.10 --output results.md
```

Generates a formatted report with metadata header and tables per address type.

### Address Format Display

Use `--format` to change how Modbus addresses are displayed:

```bash
# HEX format (default)
python click_modbus_scanner.py 192.168.0.10 --format hex
# Shows: 0x0000, 0x0001, etc.

# 984 format
python click_modbus_scanner.py 192.168.0.10 --format 984
# Shows: 100001, 100002, etc.
```

---

## Using CLICK Project CSV Files

The scanner can import CSV files exported from CLICK Programming Software to:
- Scan only addresses defined in your project
- Display tag names (nicknames) in output
- Filter by used addresses instead of scanning full ranges

### Exporting from CLICK Programming Software

1. Open your project in CLICK Programming Software
2. Navigate to **Address Picker** (View > Address Picker or F5)
3. Click **Export** button in the Address Picker toolbar
4. Choose export options:
   - **Format**: Select either "HEX" or "984" address format
   - **Scope**: Export all addresses or filtered selection
5. Save the CSV file

The exported CSV contains columns:
- `Address Name` - CLICK address (e.g., X001, DS3)
- `Data Type` - BIT, INT, INT2, FLOAT
- `Modbus Address` - Protocol address (HEX with 'h' suffix or 984 decimal)
- `Nickname` - Your tag name

### Using the Config File

```bash
# Scan only addresses in your project with nicknames
python click_modbus_scanner.py 192.168.0.10 --config project_export.csv

# Combine with file output
python click_modbus_scanner.py 192.168.0.10 --config project.csv --output scan.md
```

### CSV Format Auto-Detection

The scanner automatically detects whether the CSV uses HEX or 984 format by examining the Modbus Address column:
- **HEX format**: Addresses end with 'h' (e.g., `0000h`, `1000h`)
- **984 format**: Addresses are decimal numbers (e.g., `100001`, `400001`)

---

## Examples

### Quick Connection Test

```bash
python click_modbus_scanner.py 192.168.0.10 --type X0
```

### Full System Scan

```bash
python click_modbus_scanner.py 192.168.0.10 --full --output full_scan.csv
```

### Scan Data Registers Only

```bash
python click_modbus_scanner.py 192.168.0.10 --type DS,DD,DF
```

### Project-Based Scan with Report

```bash
python click_modbus_scanner.py 192.168.0.10 --config my_project.csv --output report.md
```

### Slow Scan for Sensitive Environment

```bash
python click_modbus_scanner.py 192.168.0.10 --rate slow --type DS
```

### Non-Standard Port

```bash
python click_modbus_scanner.py 192.168.0.10 --port 5020 --type X0,Y0
```

---

## Troubleshooting

### Connection Refused

```
Error: Unable to connect to 192.168.0.10:502
```

**Solutions:**
- Verify PLC IP address and network connectivity: `ping 192.168.0.10`
- Check that Modbus TCP is enabled on the PLC
- Verify port 502 is not blocked by firewall
- Try increasing timeout: `--timeout 10`

### Connection Timeout

```
Error: Connection timed out
```

**Solutions:**
- Verify network path to PLC
- Check for network congestion
- Increase timeout value: `--timeout 15`

### Modbus Exception Response

```
Error reading address: Modbus exception 2 (Illegal Data Address)
```

**Solutions:**
- The address may not exist on this PLC model
- Try a different address type
- Use `--list` to see available types

### CSV Parse Error

```
Error parsing CSV: ...
```

**Solutions:**
- Verify CSV was exported from CLICK Programming Software
- Check file encoding (UTF-8 or Windows-1252)
- Ensure required columns exist: Address Name, Data Type, Modbus Address

### Incorrect Values for 32-bit Types

If DD or DF values seem wrong, verify the PLC model. This scanner is calibrated for CLICK PLUS PLCs which use little-endian word order for 32-bit values.

---

## CLICK PLC Modbus Reference

### Modbus Function Codes

| FC | Operation | CLICK Address Types |
|----|-----------|---------------------|
| 01 | Read Coils | Y0-Y8, C, T, CT, SC |
| 02 | Read Discrete Inputs | X0-X8 |
| 03 | Read Holding Registers | DS, DD, DH, DF, TD, CTD, SD, TXT, YD |
| 04 | Read Input Registers | XD |

### Complete Address Mapping

#### Physical I/O

| Type | Description | Range | Modbus Start (HEX) | FC |
|------|-------------|-------|-------------------|-----|
| X0 | CPU Input Points | 1-36 | 0x0000 | 02 |
| X1-X8 | Module Input Points | 1-16 each | 0x0020-0x0100 | 02 |
| Y0 | CPU Output Points | 1-36 | 0x2000 | 01 |
| Y1-Y8 | Module Output Points | 1-16 each | 0x2020-0x2100 | 01 |

#### Control Logic

| Type | Description | Range | Modbus Start (HEX) | FC |
|------|-------------|-------|-------------------|-----|
| C | Control Relays | 1-2000 | 0x4000 | 01 |
| T | Timer Status | 1-500 | 0xB000 | 01 |
| CT | Counter Status | 1-250 | 0xC000 | 01 |
| SC | System Control Relays | 1-1000 | 0xF000 | 01 |

#### Data Registers

| Type | Description | Range | Modbus Start (HEX) | FC | Size |
|------|-------------|-------|-------------------|-----|------|
| DS | Data Register (INT16) | 1-4500 | 0x0000 | 03 | 1 word |
| DD | Data Register (INT32) | 1-1000 | 0x4000 | 03 | 2 words |
| DH | Data Register (HEX) | 1-500 | 0x6000 | 03 | 2 words |
| DF | Data Register (FLOAT) | 1-500 | 0x7000 | 03 | 2 words |

#### Timer/Counter Registers

| Type | Description | Range | Modbus Start (HEX) | FC | Size |
|------|-------------|-------|-------------------|-----|------|
| TD | Timer Data | 1-500 | 0xB000 | 03 | 1 word |
| CTD | Counter Data | 1-250 | 0xC000 | 03 | 2 words |

#### System and I/O Registers

| Type | Description | Range | Modbus Start (HEX) | FC | Size |
|------|-------------|-------|-------------------|-----|------|
| SD | System Data Register | 1-1000 | 0xF000 | 03 | 1 word |
| XD | Input Register | 0-8 | 0xE000 | 04 | 2 words |
| YD | Output Register | 0-8 | 0xE200 | 03 | 2 words |
| TXT | Text Data | 1-1000 | 0x9000 | 03 | 2 words |

### Address Format Conversion

#### HEX Format (Default)
Direct Modbus protocol addresses:
- Coils/Discrete Inputs: 0x0000 - 0xFFFF
- Registers: 0x0000 - 0xFFFF

#### 984 Format
Legacy addressing with function code prefix:
- Discrete Inputs (FC 02): 100001 - 165536
- Coils (FC 01): 000001 - 065536
- Input Registers (FC 04): 300001 - 365536
- Holding Registers (FC 03): 400001 - 465536

**Conversion**: `984_address = (FC_prefix * 100000) + modbus_address + 1`

Note: CLICK uses non-standard 984 addressing for Y and C coils.

### Word Order for 32-bit Values

CLICK PLCs use **little-endian word order** (low word first) for 32-bit values.

**Affected types**: DD, DF, DH, CTD, XD, YD, TXT

**Example**: DD11 with raw registers `[0x5AA0, 0x0032]`
- Correct (little-endian): `(0x0032 << 16) | 0x5AA0` = 3,300,000
- Wrong (big-endian): `(0x5AA0 << 16) | 0x0032` = 1,520,435,250

### Request Limits

The scanner automatically chunks large requests:
- Coils/Discrete Inputs: 100 per request (Modbus spec allows 2000)
- Registers: 100 per request (Modbus spec allows 125)

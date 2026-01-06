# USAGE.md - Detailed Usage Guide

## Table of Contents

- [Installation](#installation)
- [Modbus Scanner](#modbus-scanner-click_modbus_scannerpy)
  - [Basic Usage](#basic-usage)
  - [Command-Line Options](#command-line-options)
  - [Address Types](#address-types)
  - [Output Formats](#output-formats)
  - [Using CLICK Project CSV Files](#using-click-project-csv-files)
  - [Examples](#examples)
  - [Troubleshooting](#troubleshooting)
  - [CLICK PLC Modbus Reference](#click-plc-modbus-reference)
- [EtherNet/IP Scanner](#ethernetip-scanner-click_enip_scannerpy)
  - [ENIP Basic Usage](#enip-basic-usage)
  - [ENIP Command-Line Options](#enip-command-line-options)
  - [ENIP Output Modes](#enip-output-modes)
  - [ENIP Examples](#enip-examples)
  - [ENIP Troubleshooting](#enip-troubleshooting)
  - [CIP Protocol Reference](#cip-protocol-reference)
- [Nmap NSE Script](#nmap-nse-script-click-plc-infonse)
  - [NSE Basic Usage](#nse-basic-usage)
  - [NSE Script Arguments](#nse-script-arguments)
  - [NSE Output](#nse-output)
  - [NSE Examples](#nse-examples)
  - [NSE Troubleshooting](#nse-troubleshooting)

---

## Installation

### Requirements (Both Scanners)

- Python 3.11 or higher
- PyModbus 3.x (Modbus scanner)
- pycomm3 1.x+ (EtherNet/IP scanner)

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Verify Installation

```bash
python click_modbus_scanner.py --help
python click_enip_scanner.py --help
```

---

# Modbus Scanner (click_modbus_scanner.py)

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

---

# EtherNet/IP Scanner (click_enip_scanner.py)

## ENIP Basic Usage

The EtherNet/IP scanner reads device information and assembly data from CLICK PLCs using CIP Explicit Messaging over EtherNet/IP.

### Read Device Identity

```bash
python click_enip_scanner.py 192.168.0.10 --info
```

Shows vendor ID, product name, serial number, and firmware revision.

### Read Network Configuration

```bash
python click_enip_scanner.py 192.168.0.10 --network
```

Shows IP address, subnet mask, gateway, MAC address, and hostname.

### Read Assembly Data (Default)

```bash
python click_enip_scanner.py 192.168.0.10
```

Reads assembly data with multi-format interpretation (INT16, INT32, FLOAT).

### Full Scan

```bash
python click_enip_scanner.py 192.168.0.10 --full
```

Combines identity, network, and assembly data in one scan.

---

## ENIP Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `<host>` | PLC IP address or hostname | Required |
| `--port PORT` | EtherNet/IP port | 44818 |
| `--timeout SEC` | Connection timeout in seconds | 5 |
| `--info` | Display device identity only | - |
| `--network` | Display network information only | - |
| `--full` | Display all information | - |
| `--connection {1,2}` | Assembly connection number | 1 |
| `--size SIZE` | Maximum assembly bytes to read | 500 |
| `--hex` | Display hex dump only (no multi-format) | - |
| `--output FILE` | Write Markdown report (.md extension) | Console |

Note: `--info`, `--network`, and `--full` are mutually exclusive.

---

## ENIP Output Modes

### Console Output (Default)

Default output shows formatted tables:

```
CLICK PLC Identity Information
========================================
Vendor ID:      482 (AutomationDirect)
Device Type:    43 (Generic Device (CLICK))
Product Code:   634
Revision:       1.1
Status:         0x0030
Serial Number:  0x35BF2B44 (901720900)
Product Name:   CLICK C2-03CPU-2
```

### Multi-Format Assembly Display

Assembly data is shown in multiple interpretations:
- **Hex Dump**: Raw bytes with ASCII representation
- **INT16**: Signed 16-bit integers (DS registers)
- **INT32**: Signed 32-bit integers (DD registers)
- **FLOAT**: IEEE 754 single precision (DF registers)

### Markdown Output

```bash
python click_enip_scanner.py 192.168.0.10 --full --output report.md
```

Generates a formatted Markdown report including:
- Scan metadata (target, date, scanner version)
- Device identity table
- Network configuration table
- Assembly data with all format interpretations

---

## ENIP Examples

### Quick Connection Test

```bash
python click_enip_scanner.py 192.168.0.10 --info
```

### Full System Scan with Report

```bash
python click_enip_scanner.py 192.168.0.10 --full --output scan_report.md
```

### Read Connection 2 Assembly

```bash
python click_enip_scanner.py 192.168.0.10 --connection 2
```

### Hex-Only Output

```bash
python click_enip_scanner.py 192.168.0.10 --hex
```

### Extended Timeout for Slow Networks

```bash
python click_enip_scanner.py 192.168.0.10 --timeout 15 --full
```

---

## ENIP Troubleshooting

### Connection Timeout

```
Connection timeout to 192.168.0.10:44818
```

**Solutions:**
- Verify network connectivity: `ping 192.168.0.10`
- Check that EtherNet/IP is enabled on the PLC
- Verify port 44818 is not blocked by firewall
- Try increasing timeout: `--timeout 15`

### Connection Refused

```
Connection refused by 192.168.0.10:44818
```

**Solutions:**
- Verify the PLC is powered on
- Check that EtherNet/IP adapter is enabled in CLICK software
- Verify no firewall is blocking port 44818

### Object Does Not Exist

```
Object Does Not Exist: The specified CIP object does not exist in the device
```

**Solutions:**
- The assembly connection may not be configured
- Check EtherNet/IP Adapter Setup in CLICK Programming Software
- Verify the correct connection number (1 or 2)

### Service Not Supported

```
Service Not Supported: Requested service not implemented for this object
```

**Solutions:**
- This error is rare with the scanner (uses Get Attribute Single)
- Ensure you are connecting to a CLICK PLC, not another device type

### Size Mismatch Warning

```
Note: Size mismatch: requested 500 bytes, received 432 bytes
```

This is informational, not an error. The scanner requested up to 500 bytes but the PLC returned its actual configured size (432 bytes). The scan completed successfully.

---

## CIP Protocol Reference

### CIP Object Classes Used

| Class | Name | Purpose |
|-------|------|---------|
| 0x01 | Identity Object | Device identification |
| 0x04 | Assembly Object | Configured I/O data |
| 0xF5 | TCP/IP Interface Object | IP configuration |
| 0xF6 | Ethernet Link Object | MAC and link status |

### Assembly Instance Mapping

| Connection | Input Instance | Output Instance |
|------------|----------------|-----------------|
| 1 | 101 | 102 |
| 2 | 103 | 104 |

### CIP Service Codes

| Code | Name | Description |
|------|------|-------------|
| 0x0E | Get Attribute Single | Read single attribute value |
| 0x01 | Get Attributes All | Read all attributes (not used) |

### Common CIP Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0x00 | Success | Operation completed |
| 0x05 | Path Destination Error | Invalid class/instance/attribute |
| 0x08 | Service Not Supported | Service not implemented |
| 0x16 | Object Does Not Exist | Assembly not configured |

### CLICK EtherNet/IP Limitations

- Maximum 2 concurrent connections
- Acts as Adapter only (does not initiate connections)
- Does NOT support Tag-Based (Symbolic) messaging
- Does NOT support PCCC
- Minimum RPI: 10ms

### Data Byte Order

All CIP data uses little-endian byte order:
- 16-bit values: Low byte first
- 32-bit values: Low word first
- IP addresses: Reversed (e.g., 192.168.0.10 stored as 10.0.168.192)

---

# Nmap NSE Script (click-plc-info.nse)

The Nmap NSE script provides combined Modbus TCP and EtherNet/IP scanning in a single script, suitable for network-wide ICS assessments.

## NSE Basic Usage

### Installation

Copy `click-plc-info.nse` to one of:
- Current directory (use `--script ./click-plc-info.nse`)
- Nmap scripts directory (`/usr/share/nmap/scripts/`)
- Custom scripts directory

### Scan Both Protocols

```bash
nmap --script click-plc-info -p 502,44818 192.168.0.10
```

### Scan Modbus Only

```bash
nmap --script click-plc-info -p 502 192.168.0.10
```

### Scan EtherNet/IP Only

```bash
nmap --script click-plc-info -p 44818 192.168.0.10
```

---

## NSE Script Arguments

All arguments are prefixed with `click-plc-info.`:

| Argument | Default | Range | Description |
|----------|---------|-------|-------------|
| `modbus-only` | false | - | Skip ENIP scan when both ports specified |
| `enip-only` | false | - | Skip Modbus scan when both ports specified |
| `unit-id` | 0 | 0-247 | Modbus Unit ID |
| `coil-count` | 10 | 1-100 | Number of X/Y coils to read |
| `reg-count` | 10 | 1-100 | Number of DS/DD registers to read |
| `udp` | false | - | Use UDP for ENIP instead of TCP |

### Argument Usage

```bash
# Custom coil and register counts
nmap --script click-plc-info -p 502 192.168.0.10 \
  --script-args='click-plc-info.coil-count=20,click-plc-info.reg-count=20'

# Different Modbus Unit ID
nmap --script click-plc-info -p 502 192.168.0.10 \
  --script-args='click-plc-info.unit-id=1'

# ENIP over UDP
nmap --script click-plc-info -p 44818 192.168.0.10 \
  --script-args='click-plc-info.udp=true'

# Skip ENIP when scanning both ports
nmap --script click-plc-info -p 502,44818 192.168.0.10 \
  --script-args='click-plc-info.modbus-only=true'
```

---

## NSE Output

### Modbus Output (Port 502)

```
PORT    STATE SERVICE
502/tcp open  modbus
| click-plc-info:
|   Device Information:
|     Firmware: 3.41
|     IP Address: 192.168.0.10
|     Subnet Mask: 255.255.255.0
|     Gateway: 0.0.0.0
|     MAC Address: 00:D0:7C:1A:42:44
|     EIP Enabled: No (Status: 0x0000)
|   Inputs (X001-X010): 0 0 0 0 0 0 0 0 0 0
|   Outputs (Y001-Y010): 0 1 1 1 0 0 0 0 0 0
|   DS Registers (DS1-DS10): 0, 0, 422, 0, 5, 252, 30, 0, 0, 0
|_  DD Registers (DD1-DD10): 0, 0, 422400000, 117333, 0, 0, 0, 0, 0, 0
```

### Device Information Fields

| Field | Source | Description |
|-------|--------|-------------|
| Firmware | SD5-SD6 | PLC firmware version (major.minor) |
| IP Address | SD80-SD83 | Configured IP address |
| Subnet Mask | SD84-SD87 | Network subnet mask |
| Gateway | SD88-SD91 | Default gateway |
| MAC Address | SD188-SD193 | Ethernet MAC address |
| EIP Enabled | SD101-SD102 | EtherNet/IP status |

### EtherNet/IP Output (Port 44818)

```
PORT       STATE SERVICE
44818/tcp  open  EtherNet-IP-2
| click-plc-info:
|   Vendor: Koyo Electronics (AutomationDirect) (482)
|   Device Type: Generic Device (keyable) (43)
|   Product Name: CLICK C2-03CPU-2
|   Serial Number: 0x35bf2b44
|   Product Code: 634
|   Revision: 1.1
|   Status: 0x0030
|   State: 0xff
|_  Device IP: 192.168.0.10
```

### ENIP Fields

| Field | Description |
|-------|-------------|
| Vendor | CIP vendor ID and name |
| Device Type | CIP device type ID and name |
| Product Name | Product identification string |
| Serial Number | Device serial number (hex) |
| Product Code | Vendor-specific product code |
| Revision | ENIP protocol revision (not firmware) |
| Status | Device status word |
| State | Device state byte |
| Device IP | Embedded IP address from response |

---

## NSE Examples

### Quick Network Scan

```bash
# Scan subnet for CLICK PLCs
nmap --script click-plc-info -p 502,44818 192.168.0.0/24
```

### Detailed Scan with Debug Output

```bash
nmap --script click-plc-info -p 502,44818 192.168.0.10 -d
```

### Read More I/O Points

```bash
nmap --script click-plc-info -p 502 192.168.0.10 \
  --script-args='click-plc-info.coil-count=36,click-plc-info.reg-count=50'
```

### UDP ENIP Scan

```bash
nmap --script click-plc-info -sU -p 44818 192.168.0.10 \
  --script-args='click-plc-info.udp=true'
```

### Save Results to XML

```bash
nmap --script click-plc-info -p 502,44818 192.168.0.10 -oX results.xml
```

---

## NSE Troubleshooting

### Script Not Found

```
NSE: Failed to load script: click-plc-info.nse
```

**Solutions:**
- Use full path: `--script ./click-plc-info.nse`
- Copy script to Nmap scripts directory
- Run `nmap --script-updatedb` after installing

### No Output Displayed

If the script runs but shows no output:
- Verify PLC is reachable: `ping 192.168.0.10`
- Check port is open: `nmap -p 502 192.168.0.10`
- Run with debug: `nmap --script click-plc-info -p 502 192.168.0.10 -d`

### Timeout Errors

```
TIMEOUT waiting for response
```

**Solutions:**
- Increase Nmap timeout: `--host-timeout 30s`
- Verify network path to PLC
- Check for firewall blocking

### Invalid Argument Values

Arguments are validated and clamped:
- `coil-count` and `reg-count` clamped to 1-100
- `unit-id` clamped to 0-247
- Invalid values logged in debug output (`-d` flag)

### Modbus Exception Errors

Debug output may show:
```
Exception 2: Illegal Data Address
```

This means the requested address doesn't exist on this PLC model. The script continues scanning other addresses.

### ENIP No Response

If ENIP scan shows no results:
- Verify EtherNet/IP is enabled on PLC
- Try UDP transport: `--script-args='click-plc-info.udp=true'`
- Check port 44818 is not blocked

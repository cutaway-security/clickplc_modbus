# CLICK PLC Scanners

Scan AutomationDirect CLICK PLCs via Modbus TCP and EtherNet/IP CIP protocols. Designed for ICS/OT cybersecurity students and assessment personnel conducting authorized testing.

## Scripts

| Script | Protocol | Port | Purpose |
|--------|----------|------|---------|
| click_mb_scanner.py | Modbus TCP | 502 | Read coils and registers |
| click_enip_scanner.py | EtherNet/IP CIP | 44818 | Read device info and assembly data |
| click-plc-info.nse | Modbus + ENIP | 502, 44818 | Nmap NSE script for combined scanning |

## Requirements

### Python Scanners
- Python 3.11+
- PyModbus 3.x (for Modbus scanner)
- pycomm3 1.x+ (for EtherNet/IP scanner)

### NSE Script
- Nmap 7.80+ with Lua 5.3

```bash
pip install -r requirements.txt
```

---

## Modbus Scanner (click_mb_scanner.py)

### Features

- Read coils and registers (FC 01, 02, 03, 04)
- Output to console, CSV, or Markdown
- Import CLICK project CSV for filtered scanning with tag names
- HEX and 984 address format support
- Rate limiting for sensitive environments

### Quick Start

```bash
# Scan common address types
python click_mb_scanner.py 192.168.0.10

# Scan specific types
python click_mb_scanner.py 192.168.0.10 --type DS,DF,X0

# Use CLICK project CSV for tag names
python click_mb_scanner.py 192.168.0.10 --config project_export.csv

# Save results to file
python click_mb_scanner.py 192.168.0.10 --output results.csv

# List available address types
python click_mb_scanner.py --list
```

---

## EtherNet/IP Scanner (click_enip_scanner.py)

### Features

- Read device identity (vendor, product name, serial number)
- Read network configuration (IP, MAC, hostname)
- Read assembly data with multi-format interpretation
- Output to console or Markdown report
- CIP error code parsing with troubleshooting hints

### Quick Start

```bash
# Read device identity
python click_enip_scanner.py 192.168.0.10 --info

# Read network configuration
python click_enip_scanner.py 192.168.0.10 --network

# Read assembly data (default)
python click_enip_scanner.py 192.168.0.10

# Full scan with all information
python click_enip_scanner.py 192.168.0.10 --full

# Save to Markdown report
python click_enip_scanner.py 192.168.0.10 --full --output report.md
```

---

## Nmap NSE Script (click-plc-info.nse)

### Features

- Combined Modbus TCP and EtherNet/IP scanning
- Device information via Modbus SD registers (firmware, IP, MAC)
- Basic I/O data (X inputs, Y outputs, DS/DD registers)
- EtherNet/IP List Identity parsing (vendor, product name, serial)
- TCP and UDP transport support for ENIP
- Configurable coil and register counts

### Quick Start

```bash
# Scan both Modbus and ENIP ports
nmap --script click-plc-info -p 502,44818 192.168.0.10

# Scan Modbus only
nmap --script click-plc-info -p 502 192.168.0.10

# Scan ENIP only
nmap --script click-plc-info -p 44818 192.168.0.10

# Custom coil and register counts
nmap --script click-plc-info -p 502 192.168.0.10 \
  --script-args='click-plc-info.coil-count=20,click-plc-info.reg-count=20'

# ENIP over UDP
nmap --script click-plc-info -p 44818 192.168.0.10 \
  --script-args='click-plc-info.udp=true'
```

### Script Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| modbus-only | false | Skip ENIP scan |
| enip-only | false | Skip Modbus scan |
| unit-id | 0 | Modbus Unit ID (0-247) |
| coil-count | 10 | Number of X/Y coils to read (1-100) |
| reg-count | 10 | Number of DS/DD registers to read (1-100) |
| udp | false | Use UDP for ENIP instead of TCP |

### Example Output

```
PORT      STATE SERVICE
502/tcp   open  modbus
| click-plc-info:
|   Device Information:
|     Firmware: 3.41
|     IP Address: 192.168.0.10
|     MAC Address: 00:D0:7C:1A:42:44
|   Inputs (X001-X010): 0 0 0 0 0 0 0 0 0 0
|   Outputs (Y001-Y010): 0 1 1 1 0 0 0 0 0 0
|   DS Registers (DS1-DS10): 0, 0, 422, 0, 5, 252, 30, 0, 0, 0
|_  DD Registers (DD1-DD10): 0, 0, 422400000, 117333, 0, 0, 0, 0, 0, 0
44818/tcp open  EtherNet-IP-2
| click-plc-info:
|   Vendor: Koyo Electronics (AutomationDirect) (482)
|   Product Name: CLICK C2-03CPU-2
|   Serial Number: 0x35bf2b44
|   Revision: 1.1
|_  Device IP: 192.168.0.10
```

---

## Documentation

See [USAGE.md](USAGE.md) for detailed usage, examples, and protocol references.

## Target Hardware

Tested against CLICK PLUS PLC C2-03CPU-2:
- Modbus TCP on port 502
- EtherNet/IP on port 44818

## License

See LICENSE file.

## Disclaimer

For authorized security testing and educational purposes only. Obtain proper authorization before scanning industrial control systems.

# CLICK PLC Scanners

Scan AutomationDirect CLICK PLCs via Modbus TCP and EtherNet/IP CIP protocols. Designed for ICS/OT cybersecurity students and assessment personnel conducting authorized testing.

## Scripts

| Script | Protocol | Port | Purpose |
|--------|----------|------|---------|
| click_mb_scanner.py | Modbus TCP | 502 | Read coils and registers |
| click_enip_scanner.py | EtherNet/IP CIP | 44818 | Read device info and assembly data |

## Requirements

- Python 3.11+
- PyModbus 3.x (for Modbus scanner)
- pycomm3 1.x+ (for EtherNet/IP scanner)

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

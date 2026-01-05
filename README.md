# CLICK PLC Modbus Scanner

Scan AutomationDirect CLICK PLCs via Modbus TCP. Designed for ICS/OT cybersecurity students and assessment personnel conducting authorized testing.

## Features

- Read coils and registers (FC 01, 02, 03, 04)
- Output to console, CSV, or Markdown
- Import CLICK project CSV for filtered scanning with tag names
- HEX and 984 address format support
- Rate limiting for sensitive environments

## Requirements

- Python 3.11+
- PyModbus 3.x

```bash
pip install -r requirements.txt
```

## Quick Start

```bash
# Scan common address types
python click_modbus_scanner.py 192.168.0.10

# Scan specific types
python click_modbus_scanner.py 192.168.0.10 --type DS,DF,X0

# Use CLICK project CSV for tag names
python click_modbus_scanner.py 192.168.0.10 --config project_export.csv

# Save results to file
python click_modbus_scanner.py 192.168.0.10 --output results.csv

# List available address types
python click_modbus_scanner.py --list
```

## Documentation

See [USAGE.md](USAGE.md) for detailed usage, examples, and CLICK PLC Modbus address reference.

## Target Hardware

Tested against CLICK PLUS PLC C2-03CPU-2 on Modbus TCP port 502.

## License

See LICENSE file.

## Disclaimer

For authorized security testing and educational purposes only. Obtain proper authorization before scanning industrial control systems.

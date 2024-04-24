# Automation Direct CLICK PLC Modbus Tools
Interacting with the Automation Direct CLICK PLC using the Modbus protocol to query coils and registers.

# Scripts

* click_mb_scanner.py - Query Click PLC for Modbus coils and register values. The CLICK Modbus maps are based on memory types that have specific data types. These are mapped out in the CLICK user manual. Exported full Modbus Map included the project as a CSV file.

# Requirements

* click_mb_scanner.py
  * [PyModbus](https://pymodbus.readthedocs.io/en/latest/): `pip install pymodbus`

# Usage:

## Click PLC Modbus Scanner - click_mb_scanner.py
### List Memory Types 
`./click_mb_scanner.py list`

or

`./click_mb_scanner.py <ip> list`

### List CPU Input Point Coils
`./click_mb_scanner.py <ip> X0`

### List Data Float Registers
`./click_mb_scanner.py <ip> DF`

# Resources

* [Click PLC User Manual](https://cdn.automationdirect.com/static/manuals/c0userm/ch2.pdf)
* Modbus Map Exported from CLICK PLUS PLC: CLICKPLUS_C2-03CPU-2_w2_C2-08DR-6V_V.7_3.41_Modbus_Addresses.csv

# TODO
* Fix command line arguments and help
* Optimize scanner
* Scan using a user provided tag / coil / register list
* Script to monitor specific tags, coils, and registers
* Script to change coil and register values
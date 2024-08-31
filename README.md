# Automation Direct CLICK PLC Modbus Tools
Interacting with the Automation Direct CLICK PLC using the Modbus protocol to query coils and registers.

# Scripts

* click_mb_scanner.py - Query Click PLC for Modbus coils and register values. The CLICK Modbus maps are based on memory types that have specific data types. These are mapped out in the CLICK user manual. Exported full Modbus Map included the project as a CSV file.

# Requirements

* click_mb_scanner.py
  * [PyModbus](https://pymodbus.readthedocs.io/en/latest/): 
  ```bash 
  pip install -r requirements.txt
  ```

# Usage:

## Click PLC Modbus Scanner - click_mb_scanner.py
### Help Menu 
`./click_mb_scanner.py -h`

```bash
usage: click_mb_scanner.py [-h] [--start START] [--count COUNT] [--mode {read,write}] [--value VALUE] [--verbose] [--timeout TIMEOUT] [--retries RETRIES] [--log-file LOG_FILE] [--port PORT]
                           [--protocol {tcp,rtu}]
                           [plc_ip] {X0,X1,X2,X3,X4,X5,X6,X7,X8,Y0,Y1,Y2,Y3,Y4,Y5,Y6,Y7,Y8,C,T,CT,SC,DS,DD,DH,DF,XD,YD,TD,CTD,SD,TXT}

Query Click PLC for Modbus coils and register values.

positional arguments:
  plc_ip                IP address of the Modbus PLC
  {X0,X1,X2,X3,X4,X5,X6,X7,X8,Y0,Y1,Y2,Y3,Y4,Y5,Y6,Y7,Y8,C,T,CT,SC,DS,DD,DH,DF,XD,YD,TD,CTD,SD,TXT}
                        Coil & Register Memory Type to query

options:
  -h, --help            show this help message and exit
  --start START         Starting address/register
  --count COUNT         Number of registers to read
  --mode {read,write}   Mode of operation: read or write (Default=read)
  --value VALUE         Value to write (required if mode is write)
  --verbose             Enable verbose output
  --timeout TIMEOUT     Timeout for PLC connection in seconds (Default=3.0)
  --retries RETRIES     Number of retries for PLC connection (Default=3)
  --log-file LOG_FILE   Path to a log file to write output
  --port PORT           Port number for Modbus connection
  --protocol {tcp,rtu}  Protocol to use for connection
  ```

### List CPU Input Point Coils
```bash
./click_mb_scanner.py <ip> X0
```

### List Data Float Registers
```bash
./click_mb_scanner.py <ip> DF
```

# Resources

* [Click PLC User Manual](https://cdn.automationdirect.com/static/manuals/c0userm/ch2.pdf)
* Modbus Map Exported from CLICK PLUS PLC: CLICKPLUS_C2-03CPU-2_w2_C2-08DR-6V_V.7_3.41_Modbus_Addresses.csv

# TODO
* Implement several items from the Help Menu: write & value, start address/register, count, verbosity, protocol, and log-file
* Fix command line arguments and help
* Optimize scanner
* Scan using a user provided tag / coil / register list
* Script to monitor specific tags, coils, and registers
* Script to change coil and register values
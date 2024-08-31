#!/usr/bin/env python3

######################################################
# click_mb_scanner.py - Query Click PLC for Modbus coils and register values.
#                       The CLICK Modbus maps are based on memory types that
#                       have specific data types. These are mapped out in the
#                       CLICK user manual. Exported full Modbus Map included
#                       in the project.
#
# Author:  Don C. Weber (cutaway)
# Refactored by Robert E. Litts
# Date:    20240831
# Version: 0.1
# Manual:  https://cdn.automationdirect.com/static/manuals/c0userm/ch2.pdf
# Mapping: CLICKPLUS_C2-03CPU-2_w2_C2-08DR-6V_V.7_3.41_Modbus_Addresses.csv
#
# Usage:
#         Help: ./click_mb_scanner.py -h
#                            ./click_mb_scanner.py <ip> list
#
#         List CPU Input Point Coils: ./click_mb_scanner.py <ip> X0
#         List Data Float Registers:  ./click_mb_scanner.py <ip> DF
#
######################################################

import struct
from pymodbus.client import ModbusTcpClient as ModbusClient
from pymodbus.exceptions import ModbusException, ModbusIOException
import argparse
import re

# Memory Types
type_names = {
    'X0': 'M0 Input Point', 'X1': 'M1 Input Point', 'X2': 'M2 Input Point',
    'Y0': 'M0 Output Point', 'X1': 'M1 Output Point', 'X2': 'M2 Output Point',
    'C': 'Control Relay', 'T': 'Timer', 'CT': 'Counter', 'SC': 'System Control Relay',
    'DS': 'Data Register int', 'TD': 'Timer Register', 'SD': 'System Data Register',
    'DD': 'Data Register int2', 'CTD': 'Counter Register', 'DF': 'Data Register float',
    'DH': 'Data Register hex', 'XD': 'Input Register', 'YD': 'Output Register', 'TXT': 'Text Data'
}

# Memory Ranges 
# Module 0 for inputs and output is unusual numbering
# Modules can be up to 8
type_ranges = {
    'X0': [1, 36], 'X1': [1, 16], 'X2': [1, 16], 'X3': [1, 16], 'X4': [1, 16],
    'X5': [1, 16], 'X6': [1, 16], 'X7': [1, 16], 'X8': [1, 16], 'Y0': [1, 36],
    'Y1': [1, 16], 'Y2': [1, 16], 'Y3': [1, 16], 'Y4': [1, 16], 'Y5': [1, 16],
    'Y6': [1, 16], 'Y7': [1, 16], 'Y8': [1, 16], 'C': [1, 2000], 'T': [1, 500],
    'CT': [1, 250], 'SC': [1, 1000], 'DS': [1, 4500], 'DD': [1, 1000], 'DH': [1, 500],
    'DF': [1, 500], 'XD': [0, 8], 'YD': [0, 8], 'TD': [1, 500], 'CTD': [1, 250],
    'SD': [1, 1000], 'TXT': [1, 1000]
}

# Modbus Mappings
coil_start_addrs = {
    'X0': 0x0000, 'X1': 0x0020, 'X2': 0x0040, 'X3': 0x0060, 'X4': 0x0080,
    'X5': 0x00a0, 'X6': 0x00c0, 'X7': 0x00e0, 'X8': 0x0100, 'Y0': 0x2000,
    'Y1': 0x2020, 'Y2': 0x2040, 'Y3': 0x2060, 'Y4': 0x2080, 'Y5': 0x20a0,
    'Y6': 0x20c0, 'Y7': 0x20e0, 'Y8': 0x2100, 'C': 0x4000, 'T': 0xB000,
    'CT': 0xC000, 'SC': 0xF000
}

#Register Addresses
reg_start_addrs = {
    'DS': 0x0000, 'DD': 0x4000, 'DH': 0x6000, 'DF': 0x7000, 'XD': 0xE000,
    'YD': 0xE200, 'TD': 0xB000, 'CTD': 0xC000, 'SD': 0xF000, 'TXT': 0x9000
}

# Data Type Sizes
reg_sizes = {
    'DS': 1, 'DD': 2, 'DH': 2, 'DF': 2, 'XD': 2, 'YD': 2, 'TD': 1,
    'CTD': 2, 'SD': 1, 'TXT': 2
}


coil_keys = coil_start_addrs.keys()

reg_keys = reg_start_addrs.keys()

def get_coils(client, query_type):
    """Query and print coil data based on the query type."""
    start_addr = coil_start_addrs[query_type]
    count = type_ranges[query_type][1]

    if query_type == 'C':
        rfull = []
        rfull.extend((client.read_coils(start_addr, 1000)).bits)
        rfull.extend((client.read_coils(1000, 1000)).bits)
        for e in range(len(rfull)):
            print(f'{query_type}{e+1} : {rfull[e]}')
    else:
        if query_type[0] == 'X':
            r = client.read_discrete_inputs(start_addr, count)
        else:
            r = client.read_coils(start_addr, count)
        for b in range(count):
            if query_type[0] == 'X' or query_type[0] == 'Y':
                print(f'{query_type}{b:02d} : {r.bits[b]}')
            else:
                print(f'{query_type}{b} : {r.bits[b]}')

def get_registers(client, query_type):
    """Query and print register data based on the query type."""
    start_addr = reg_start_addrs[query_type]
    count = type_ranges[query_type][1]
    name_cnt = type_ranges[query_type][0]

    if query_type in ['DS', 'TD', 'SD', 'DH', 'TXT']:
        block_size = 100
        curr_block = 0
        while curr_block <= count:
            r = client.read_holding_registers(start_addr + curr_block, block_size)
            if r.registers:
                for br in r.registers:
                    if query_type in ['DS', 'TD', 'SD']:
                        print(f'{query_type}{name_cnt} : {br}')
                    else:
                        print(f'{query_type}{name_cnt} : 0x{br:x}')
                    name_cnt += 1
            curr_block += block_size
    else:
        for b in range(type_ranges[query_type][0], count + 1, reg_sizes[query_type]):
            if query_type == 'XD':
                r = client.read_input_registers(start_addr + b, reg_sizes[query_type])
            else:
                r = client.read_holding_registers(start_addr + b, reg_sizes[query_type])
            if r.registers:
                if query_type in ['DD', 'CTD', 'XD', 'YD']:
                    bl = r.registers
                    a = [v for reg_val in bl for v in reg_val.to_bytes(2, 'big')]
                    rn = int.from_bytes(a, 'big', signed=False)
                    print(f'{query_type}{name_cnt} : {rn}')
                if query_type == 'DF':
                    bl = r.registers
                    a = [v for reg_val in bl for v in reg_val.to_bytes(2, 'big')]
                    fn = struct.unpack('>f', bytearray(a))[0]
                    print(f'{query_type}{name_cnt} : {fn:.4f}')
            name_cnt += 1

def parse_args():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Query Click PLC for Modbus coils and register values.')

    # Optional arguments that are only required if --list is not used
    parser.add_argument('plc_ip', type=validate_ip, nargs='?', help='IP address of the Modbus PLC')
    parser.add_argument('query_type', type=str, choices=list(coil_keys) + list(reg_keys), help='Coil & Register Memory Type to query')
    parser.add_argument('--start', type=int, help='Starting address/register')
    parser.add_argument('--count', type=int, help='Number of registers to read')
    parser.add_argument('--mode', type=str, choices=['read', 'write'], default='read', help='Mode of operation: read or write (Default=read)')
    parser.add_argument('--value', type=int, help='Value to write (required if mode is write)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--timeout', type=float, default=3.0, help='Timeout for PLC connection in seconds (Default=3.0)')
    parser.add_argument('--retries', type=int, default=3, help='Number of retries for PLC connection (Default=3)')
    parser.add_argument('--log-file', type=str, help='Path to a log file to write output')
    parser.add_argument('--port', type=validate_port, default=502, help='Port number for Modbus connection')
    parser.add_argument('--protocol', type=str, choices=['tcp', 'rtu'], default='tcp', help='Protocol to use for connection')

    return parser.parse_args()

def validate_ip(value):
    """
    Validates the IP address format.
    """
    ip_regex = re.compile(
        r'^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.){3}'
        r'(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'
    )
    if not ip_regex.match(value):
        raise argparse.ArgumentTypeError(f"Invalid IP address format: {value}")
    return value

def validate_port(value):
    """
    Validates the port number.
    """
    try:
        port = int(value)
        if port < 1 or port > 65535:
            raise argparse.ArgumentTypeError(f"Port number must be between 1 and 65535: {value}")
        return port
    except ValueError:
        raise argparse.ArgumentTypeError(f"Port number must be an integer: {value}")


def main():

    args = parse_args()
    query_type = args.query_type
    plc_ip = args.plc_ip
    port = args.port
    timeout=args.timeout
    retries = args.retries

    try:
        
        with ModbusClient(plc_ip, port=port, retries=retries, timeout=timeout) as client:
            # Check if the client is connected
            if not client.connect():
                raise ModbusIOException("Failed to connect to Modbus server")

            # Get Coils
            if args.query_type in coil_keys:
                get_coils(client, query_type)

            # Get Registers
            if args.query_type in reg_keys:
                get_registers(client, query_type)

    except ModbusIOException as e:
        print(f"Connection error: {e}")
    except ModbusException as e:
        print(f"Modbus error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    main()
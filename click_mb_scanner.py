#!/usr/bin/env python3

######################################################
# click_mb_scanner.py - Query Click PLC for Modbus coils and register values.
#                       The CLICK Modbus maps are based on memory types that
#                       have specific data types. These are mapped out in the
#                       CLICK user manual. Exported full Modbus Map included
#                       in the project.
#
# Author:  Don C. Weber (cutaway)
# Date:    20240424
# Version: 0.1
# Manual:  https://cdn.automationdirect.com/static/manuals/c0userm/ch2.pdf
# Mapping: CLICKPLUS_C2-03CPU-2_w2_C2-08DR-6V_V.7_3.41_Modbus_Addresses.csv
#
# Usage:
#         List Memory Types: ./click_mb_scanner.py list
#                            ./click_mb_scanner.py <ip> list
#
#         List CPU Input Point Coils: ./click_mb_scanner.py <ip> X0
#         List Data Float Registers:  ./click_mb_scanner.py <ip> DF
#
######################################################

import os,sys,time,struct
from pymodbus.client import ModbusTcpClient as ModbusClient

# Memory Types
type_names = {
    'X0':'M0 Input Point',
    'X1':'M1 Input Point',
    'X2':'M2 Input Point',
    'Y0':'M0 Output Point',
    'X1':'M1 Output Point',
    'X2':'M2 Output Point',
    'C':'Control Relay',
    'T':'Timer',
    'CT':'Counter',
    'SC':'System Control Relay',
    'DS':'Data Register int',
    'TD':'Timer Register',
    'SD':'System Data Register',
    'DD':'Data Register int2',
    'CTD':'Counter Register',
    'DF':'Data Register float',
    'DH':'Data Register hex',
    'XD':'Input Register',
    'YD':'Output Register',
    'TXT':'Text Data'
}

# Memory Ranges 
# Module 0 for inputs and output is unusual numbering
# Modules can be up to 8
type_ranges = {
    'X0':[1,36],
    'X1':[1,16],
    'X2':[1,16],
    'X3':[1,16],
    'X4':[1,16],
    'X5':[1,16],
    'X6':[1,16],
    'X7':[1,16],
    'X8':[1,16],
    'Y0':[1,36],
    'Y1':[1,16],
    'Y2':[1,16],
    'Y3':[1,16],
    'Y4':[1,16],
    'Y5':[1,16],
    'Y6':[1,16],
    'Y7':[1,16],
    'Y8':[1,16],
    'C':[1,2000],
    'T':[1,500],
    'CT':[1,250],
    'SC':[1,1000],
    'DS':[1,4500],
    'DD':[1,1000],
    'DH':[1,500],
    'DF':[1,500],
    'XD':[0,8],
    'YD':[0,8],
    'TD':[1,500],
    'CTD':[1,250],
    'SD':[1,1000],
    'TXT':[1,1000]
}

# Modbus Mappings
coil_start_addrs = {
    'X0' :0x0000,
    'X1' :0x0020,
    'X2' :0x0040,
    'X3' :0x0060,
    'X4' :0x0080,
    'X5' :0x00a0,
    'X6' :0x00c0,
    'X7' :0x00e0,
    'X8' :0x0100,
    'Y0' :0x2000,
    'Y1' :0x2020,
    'Y2' :0x2040,
    'Y3' :0x2060,
    'Y4' :0x2080,
    'Y5' :0x20a0,
    'Y6' :0x20c0,
    'Y7' :0x20e0,
    'Y8' :0x2100,
    'C'  :0x4000,
    'T'  :0xB000,
    'CT' :0xC000,
    'SC' :0xF000,
}
coil_keys = coil_start_addrs.keys()

reg_start_addrs = {
    'DS' :0x0000,
    'DD' :0x4000,
    'DH' :0x6000,
    'DF' :0x7000,
    'XD' :0xE000,
    'YD' :0xE200,
    'TD' :0xB000,
    'CTD':0xC000,
    'SD' :0xF000,
    'TXT':0x9000
}
reg_keys = reg_start_addrs.keys()

# Data Type Sizes
reg_sizes = {
    'DS' :1,
    'DD' :2,
    'DH' :2,
    'DF' :2,
    'XD' :2,
    'YD' :2,
    'TD' :1,
    'CTD':2,
    'SD' :1,
    'TXT':2
}

# Command Line Variables
if ((len(sys.argv) < 2) or (len(sys.argv) > 3)): 
    print("Check Readme for Usage")
    sys.exit()
plc_ip   = sys.argv[1]
plc_port = 502
if (len(sys.argv) > 2): query_type = sys.argv[2]
if (plc_ip == 'list' or query_type == 'list'):
    for e in type_names.keys():
        print('%s: %s'%(e,type_names[e]))
    sys.exit()

with ModbusClient(plc_ip, retries=3, retry_on_empty=True) as client:
    # Get Coils
    if (query_type in coil_keys):
        start_addr = coil_start_addrs[query_type]
        count = type_ranges[query_type][1]
        # C type has too many coils, split it up
        if (query_type == 'C'):
            rfull = []
            rfull.extend((client.read_coils(start_addr,1000,unit=0x01)).bits)
            rfull.extend((client.read_coils(1000,1000,unit=0x01)).bits)
            for e in range(len(rfull)):
                print('%s%s : %s'%(query_type,e+1,rfull[e]))
        else:
            if (query_type[0] == 'X'):
                r = client.read_discrete_inputs(start_addr,count,unit=0x01)
            else:
                r = client.read_coils(start_addr,count,unit=0x01)
            for b in range(1,count):
                if (query_type[0] == 'X' or query_type[0] == 'Y'):
                    print('%s%02d : %s'%(query_type,b,r.bits[b]))
                else:
                    print('%s%s : %s'%(query_type,b,r.bits[b]))
    # Get Registers
    if (query_type in reg_keys):
        start_addr = reg_start_addrs[query_type]
        count      = type_ranges[query_type][1]  
        name_cnt   = type_ranges[query_type][0]

        # Manage INT values by querying a block at a time
        if (query_type in ['DS','TD','SD','DH','TXT']):
            block_size = 100
            curr_block = 0
            while (curr_block <= count): 
                r = client.read_holding_registers(start_addr+curr_block,100,unit=0x01)
                if r.registers:
                    for br in r.registers:
                        if (query_type in ['DS','TD','SD']):
                            # Print decimal values as decimal
                            print('%s%s : %d'%(query_type,name_cnt,br))
                        else:
                            # Print byte values as hex
                            print('%s%s : 0x%x'%(query_type,name_cnt,br))
                        name_cnt = name_cnt + 1
                curr_block = curr_block + block_size
        else:
            # Manage non-INT values
            for b in range(type_ranges[query_type][0],count + 1,reg_sizes[query_type]):
                if (query_type == 'XD'):
                    r = client.read_input_registers(start_addr+b,reg_sizes[query_type],unit=0x01)
                else:
                    r = client.read_holding_registers(start_addr+b,reg_sizes[query_type],unit=0x01)
                if r.registers: 
                    if (query_type in ['DD','CTD','XD','YD']): 
                        bl = r.registers
                        # Returned registers contain two byte values and need to be split
                        a = []
                        for reg_val in bl:
                            for v in reg_val.to_bytes(2,'big'):
                                a.append(v)
                        rn = int.from_bytes(a,'big',signed=False)
                        print('%s%s : %s'%(query_type,name_cnt,rn))
                    # DF values are floats and need to be converted. 
                    # Bytes to Float Example: https://gregstoll.com/~gregstoll/floattohex/
                    # NOTE: there are some rounding differences in the PLC, not sure why
                    if (query_type == 'DF'):
                        bl = r.registers
                        # Returned registers contain two byte values and need to be split
                        a = []
                        for reg_val in bl:
                            for v in reg_val.to_bytes(2,'big'):
                                a.append(v)
                        fn = struct.unpack('>f',bytearray(a))[0]
                        print('%s%s : %04f'%(query_type,name_cnt,fn))
                name_cnt = name_cnt + 1

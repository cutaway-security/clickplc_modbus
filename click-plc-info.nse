local comm = require "comm"
local ipOps = require "ipOps"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enumerates AutomationDirect CLICK PLC information via Modbus TCP and EtherNet/IP.

This script queries CLICK PLCs on port 502 (Modbus TCP) and/or port 44818
(EtherNet/IP) to retrieve device information, network configuration, and
basic I/O data. Designed for ICS/OT security assessments and authorized
penetration testing.

Modbus TCP (port 502):
  - Device info from SD registers (firmware, IP, MAC, EIP status)
  - Basic I/O: X inputs, Y outputs, DS and DD registers

EtherNet/IP (port 44818):
  - List Identity response (vendor, device type, product name, serial)
  - Supports both TCP (default) and UDP transport
]]

---
-- @usage
-- nmap --script click-plc-info -p 502,44818 <target>
--
-- @args click-plc-info.modbus-only  Skip ENIP, scan Modbus only (default: false)
-- @args click-plc-info.enip-only    Skip Modbus, scan ENIP only (default: false)
-- @args click-plc-info.unit-id      Modbus Unit ID (default: 0)
-- @args click-plc-info.coil-count   Number of X/Y coils to read (default: 10)
-- @args click-plc-info.reg-count    Number of DS/DD registers to read (default: 10)
-- @args click-plc-info.udp          Use UDP for ENIP instead of TCP (default: false)
--
-- @output
-- PORT      STATE SERVICE
-- 502/tcp   open  modbus
-- | click-plc-info:
-- |   Modbus Device Information:
-- |     Firmware: 3.41
-- |     IP Address: 192.168.0.10
-- |     Subnet Mask: 255.255.255.0
-- |     Gateway: 192.168.0.1
-- |     MAC Address: 00:0D:7C:1A:42:44
-- |     EIP Enabled: Yes (Status: 0x0001)
-- |   Inputs (X001-X010): 0 0 0 0 0 0 0 0 0 0
-- |   Outputs (Y001-Y010): 0 0 0 1 0 0 0 0 0 0
-- |   DS Registers (DS1-DS10): 0, 100, 0, 0, 0, 0, 0, 0, 0, 0
-- |_  DD Registers (DD1-DD10): 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
--
-- PORT       STATE SERVICE
-- 44818/tcp  open  EtherNet-IP-2
-- | click-plc-info:
-- |   Vendor: AutomationDirect (898)
-- |   Device Type: Programmable Logic Controller (14)
-- |   Product Name: CLICK PLUS CPU
-- |   Serial Number: 0x12345678
-- |   Product Code: 1234
-- |   Revision: 3.41
-- |   Status: 0x0030
-- |_  State: 0x03
--
-- @xmloutput
-- <table key="Modbus Device Information">
--   <elem key="Firmware">3.41</elem>
--   <elem key="IP Address">192.168.0.10</elem>
--   <elem key="MAC Address">00:0D:7C:1A:42:44</elem>
-- </table>

author = "Cutaway Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "version"}

---
-- Portrule: Match Modbus TCP (502) or EtherNet/IP (44818)
---
portrule = shortport.port_or_service({502, 44818}, {"modbus", "EtherNet-IP-2"}, {"tcp", "udp"})

---
-- Vendor ID lookup table (minimal set for CLICK PLCs)
---
local vendor_id = {
    [0] = "Reserved",
    [1] = "Rockwell Automation/Allen-Bradley",
    [47] = "Omron",
    [82] = "Mitsubishi Electric",
    [145] = "Siemens",
    [482] = "Koyo Electronics (AutomationDirect)",
    [898] = "AutomationDirect",
}

---
-- Device type lookup table
---
local device_type = {
    [0] = "Generic Device",
    [2] = "AC Drive",
    [7] = "General Purpose Discrete I/O",
    [12] = "Communications Adapter",
    [14] = "Programmable Logic Controller",
    [24] = "Human-Machine Interface",
    [43] = "Generic Device (keyable)",
}

---
-- Modbus exception code lookup table
---
local modbus_exception = {
    [1] = "Illegal Function",
    [2] = "Illegal Data Address",
    [3] = "Illegal Data Value",
    [4] = "Slave Device Failure",
    [5] = "Acknowledge",
    [6] = "Slave Device Busy",
    [8] = "Memory Parity Error",
    [10] = "Gateway Path Unavailable",
    [11] = "Gateway Target Device Failed to Respond",
}

--------------------------------------------------------------------------------
-- ENIP Functions
--------------------------------------------------------------------------------

---
-- Look up vendor name from vendor ID
-- @param vennum Vendor ID number
-- @return Vendor name string or "Unknown Vendor"
---
local function vendor_lookup(vennum)
    return vendor_id[vennum] or "Unknown Vendor"
end

---
-- Look up device type from device type ID
-- @param devtype Device type ID number
-- @return Device type string or "Unknown Device Type"
---
local function device_type_lookup(devtype)
    return device_type[devtype] or "Unknown Device Type"
end

---
-- Build EtherNet/IP List Identity request packet
-- @return 24-byte List Identity command packet
---
local function form_enip_list_identity()
    -- EtherNet/IP Encapsulation Header (24 bytes):
    -- Command: 0x0063 (List Identity)
    -- Length: 0x0000
    -- Session Handle: 0x00000000
    -- Status: 0x00000000
    -- Sender Context: 8 bytes (arbitrary)
    -- Options: 0x00000000
    return stdnse.fromhex("63000000000000000000000000000000c1debed100000000")
end

---
-- Parse EtherNet/IP List Identity response
-- @param response Raw response bytes
-- @return Output table with device info, or nil on error
---
local function parse_enip_response(response)
    -- Minimum response length check
    if not response or #response < 27 then
        stdnse.debug1("ENIP response too short: %d bytes", response and #response or 0)
        return nil
    end

    -- Verify command is List Identity response (0x63)
    local command = string.unpack("B", response, 1)
    if command ~= 0x63 then
        stdnse.debug1("ENIP unexpected command: 0x%02x (expected 0x63)", command)
        return nil
    end

    -- Verify type ID is Identity (0x0C) at offset 27
    local type_id = string.unpack("B", response, 27)
    if type_id ~= 0x0C then
        stdnse.debug1("ENIP unexpected type ID: 0x%02x (expected 0x0C)", type_id)
        return nil
    end

    -- Need at least 63 bytes for full identity parsing
    if #response < 63 then
        stdnse.debug1("ENIP response incomplete: %d bytes (need 63+)", #response)
        return nil
    end

    -- Parse Device IP (offset 37, big-endian DWORD)
    local dword = string.unpack(">I4", response, 37)
    local device_ip = ipOps.fromdword(dword)

    -- Parse Vendor ID (offset 49, little-endian UINT16)
    local vendor_num, idx = string.unpack("<I2", response, 49)
    local vendor_str = vendor_lookup(vendor_num) .. " (" .. vendor_num .. ")"

    -- Parse Device Type (offset 51, little-endian UINT16)
    local device_num
    device_num, idx = string.unpack("<I2", response, idx)
    local device_str = device_type_lookup(device_num) .. " (" .. device_num .. ")"

    -- Parse Product Code (offset 53, little-endian UINT16)
    local product_code
    product_code, idx = string.unpack("<I2", response, idx)

    -- Parse Revision (offset 55-56, major.minor)
    local major, minor
    major, minor, idx = string.unpack("BB", response, idx)
    local revision = major .. "." .. minor

    -- Parse Status (offset 57, little-endian UINT16)
    local status
    status, idx = string.unpack("<I2", response, idx)
    local status_str = string.format("0x%04x", status)

    -- Parse Serial Number (offset 59, little-endian UINT32)
    local serial_num
    serial_num, idx = string.unpack("<I4", response, idx)
    local serial_str = string.format("0x%08x", serial_num)

    -- Parse Product Name (length-prefixed string at offset 63)
    local product_name
    product_name, idx = string.unpack("s1", response, idx)

    -- Parse State (1 byte after product name)
    local state = 0
    if idx <= #response then
        state = string.unpack("B", response, idx)
    end
    local state_str = string.format("0x%02x", state)

    -- Build output table
    local output = stdnse.output_table()
    output["Vendor"] = vendor_str
    output["Device Type"] = device_str
    output["Product Name"] = product_name
    output["Serial Number"] = serial_str
    output["Product Code"] = product_code
    output["Revision"] = revision
    output["Status"] = status_str
    output["State"] = state_str
    output["Device IP"] = device_ip

    return output
end

---
-- Perform EtherNet/IP scan over TCP
-- @param host Host object
-- @param port Port object
-- @return Output table with device info, or nil on error
---
local function enip_scan_tcp(host, port)
    local socket, try, catch

    -- Create new socket
    socket = nmap.new_socket()
    socket:set_timeout(stdnse.get_timeout(host))

    -- Define catch function for cleanup
    catch = function()
        socket:close()
    end

    -- Create try with catch handler
    try = nmap.new_try(catch)

    -- Connect to host
    try(socket:connect(host, port))
    stdnse.debug1("ENIP TCP connected to %s:%d", host.ip, port.number)

    -- Send List Identity request
    local query = form_enip_list_identity()
    try(socket:send(query))
    stdnse.debug1("ENIP sent List Identity request (%d bytes)", #query)

    -- Receive response
    local status, response = socket:receive()
    socket:close()

    if not status then
        stdnse.debug1("ENIP no response received")
        return nil
    end

    stdnse.debug1("ENIP received response (%d bytes)", #response)

    -- Parse and return response
    local output = parse_enip_response(response)
    if output then
        -- Set port version info
        port.state = "open"
        port.version.name = "EtherNet-IP-2"
        nmap.set_port_version(host, port)
    end

    return output
end

---
-- Perform EtherNet/IP scan over UDP
-- @param host Host object
-- @param port Port object
-- @return Output table with device info, or nil on error
---
local function enip_scan_udp(host, port)
    local socket, try, catch

    -- Create UDP socket
    socket = nmap.new_socket("udp")
    socket:set_timeout(stdnse.get_timeout(host))

    -- Define catch function for cleanup
    catch = function()
        socket:close()
    end

    -- Create try with catch handler
    try = nmap.new_try(catch)

    -- Connect to host (UDP is connectionless but this sets the target)
    try(socket:connect(host, port))
    stdnse.debug1("ENIP UDP socket created for %s:%d", host.ip, port.number)

    -- Send List Identity request
    local query = form_enip_list_identity()
    try(socket:send(query))
    stdnse.debug1("ENIP UDP sent List Identity request (%d bytes)", #query)

    -- Receive response (UDP may need multiple attempts)
    local status, response = socket:receive()
    socket:close()

    if not status then
        stdnse.debug1("ENIP UDP no response received")
        return nil
    end

    stdnse.debug1("ENIP UDP received response (%d bytes)", #response)

    -- Parse and return response
    local output = parse_enip_response(response)
    if output then
        -- Set port version info
        port.state = "open"
        port.version.name = "EtherNet-IP-2"
        nmap.set_port_version(host, port)
    end

    return output
end

--------------------------------------------------------------------------------
-- Modbus Functions
--------------------------------------------------------------------------------

-- Transaction ID counter (increments per request)
local transaction_id = 0

---
-- Build Modbus TCP request packet (MBAP header + PDU)
-- @param uid Unit ID (default 0 for CLICK)
-- @param fc Function code (01, 02, 03, or 04)
-- @param addr Starting address (0-based)
-- @param qty Quantity of coils/registers to read
-- @return Request packet as string
---
local function form_modbus_request(uid, fc, addr, qty)
    -- Increment transaction ID
    transaction_id = (transaction_id + 1) % 65536

    -- MBAP Header (7 bytes):
    -- [0-1] Transaction ID (big-endian)
    -- [2-3] Protocol ID: 0x0000 (Modbus)
    -- [4-5] Length: PDU length + 1 (for Unit ID)
    -- [6]   Unit ID

    -- PDU (5 bytes for read requests):
    -- [0]   Function Code
    -- [1-2] Starting Address (big-endian)
    -- [3-4] Quantity (big-endian)

    local pdu_length = 6  -- Unit ID (1) + FC (1) + Addr (2) + Qty (2)

    local packet = string.pack(">I2 >I2 >I2 B B >I2 >I2",
        transaction_id,     -- Transaction ID
        0x0000,             -- Protocol ID (Modbus)
        pdu_length,         -- Length
        uid,                -- Unit ID
        fc,                 -- Function Code
        addr,               -- Starting Address
        qty                 -- Quantity
    )

    stdnse.debug2("Modbus request: TID=%d, UID=%d, FC=%d, Addr=0x%04x, Qty=%d",
        transaction_id, uid, fc, addr, qty)

    return packet
end

---
-- Parse Modbus TCP response
-- @param response Raw response bytes
-- @param expected_fc Expected function code
-- @return data bytes on success, nil and error message on failure
---
local function parse_modbus_response(response, expected_fc)
    -- Minimum response length: MBAP (7) + FC (1) + ByteCount (1) = 9
    if not response or #response < 9 then
        return nil, "Response too short"
    end

    -- Parse MBAP header
    local tid, proto, length, uid, fc = string.unpack(">I2 >I2 >I2 B B", response)

    stdnse.debug2("Modbus response: TID=%d, Proto=%d, Len=%d, UID=%d, FC=%d",
        tid, proto, length, uid, fc)

    -- Check protocol ID
    if proto ~= 0x0000 then
        return nil, string.format("Invalid protocol ID: 0x%04x", proto)
    end

    -- Check for exception response (FC with high bit set)
    if fc == (expected_fc + 0x80) then
        local exception_code = string.unpack("B", response, 9)
        local exception_msg = modbus_exception[exception_code] or "Unknown exception"
        return nil, string.format("Exception %d: %s", exception_code, exception_msg)
    end

    -- Check function code matches
    if fc ~= expected_fc then
        return nil, string.format("Unexpected FC: %d (expected %d)", fc, expected_fc)
    end

    -- Get byte count
    local byte_count = string.unpack("B", response, 9)

    -- Verify we have all the data
    if #response < 9 + byte_count then
        return nil, string.format("Incomplete data: expected %d bytes, got %d",
            byte_count, #response - 9)
    end

    -- Extract data bytes
    local data = string.sub(response, 10, 9 + byte_count)

    stdnse.debug2("Modbus data: %d bytes", #data)

    return data, nil
end

---
-- Read coils (FC 01)
-- @param host Host object
-- @param port Port object
-- @param uid Unit ID
-- @param addr Starting address
-- @param qty Quantity of coils
-- @return Table of coil values (true/false), or nil on error
---
local function read_coils(host, port, uid, addr, qty)
    local socket = nmap.new_socket()
    socket:set_timeout(stdnse.get_timeout(host))

    local status, err = socket:connect(host, port)
    if not status then
        stdnse.debug1("Modbus connect failed: %s", err)
        return nil
    end

    local request = form_modbus_request(uid, 0x01, addr, qty)
    status, err = socket:send(request)
    if not status then
        socket:close()
        stdnse.debug1("Modbus send failed: %s", err)
        return nil
    end

    local response
    status, response = socket:receive()
    socket:close()

    if not status then
        stdnse.debug1("Modbus receive failed: %s", response)
        return nil
    end

    local data, parse_err = parse_modbus_response(response, 0x01)
    if not data then
        stdnse.debug1("Modbus parse failed: %s", parse_err)
        return nil
    end

    -- Unpack coil bits into table
    local coils = {}
    for i = 1, qty do
        local byte_idx = math.floor((i - 1) / 8) + 1
        local bit_idx = (i - 1) % 8
        if byte_idx <= #data then
            local byte_val = string.byte(data, byte_idx)
            coils[i] = ((byte_val >> bit_idx) & 0x01) == 1
        end
    end

    return coils
end

---
-- Read discrete inputs (FC 02)
-- @param host Host object
-- @param port Port object
-- @param uid Unit ID
-- @param addr Starting address
-- @param qty Quantity of inputs
-- @return Table of input values (true/false), or nil on error
---
local function read_discrete_inputs(host, port, uid, addr, qty)
    local socket = nmap.new_socket()
    socket:set_timeout(stdnse.get_timeout(host))

    local status, err = socket:connect(host, port)
    if not status then
        stdnse.debug1("Modbus connect failed: %s", err)
        return nil
    end

    local request = form_modbus_request(uid, 0x02, addr, qty)
    status, err = socket:send(request)
    if not status then
        socket:close()
        stdnse.debug1("Modbus send failed: %s", err)
        return nil
    end

    local response
    status, response = socket:receive()
    socket:close()

    if not status then
        stdnse.debug1("Modbus receive failed: %s", response)
        return nil
    end

    local data, parse_err = parse_modbus_response(response, 0x02)
    if not data then
        stdnse.debug1("Modbus parse failed: %s", parse_err)
        return nil
    end

    -- Unpack input bits into table
    local inputs = {}
    for i = 1, qty do
        local byte_idx = math.floor((i - 1) / 8) + 1
        local bit_idx = (i - 1) % 8
        if byte_idx <= #data then
            local byte_val = string.byte(data, byte_idx)
            inputs[i] = ((byte_val >> bit_idx) & 0x01) == 1
        end
    end

    return inputs
end

---
-- Read holding registers (FC 03)
-- @param host Host object
-- @param port Port object
-- @param uid Unit ID
-- @param addr Starting address
-- @param qty Quantity of registers
-- @return Raw data bytes, or nil on error
---
local function read_holding_registers(host, port, uid, addr, qty)
    local socket = nmap.new_socket()
    socket:set_timeout(stdnse.get_timeout(host))

    local status, err = socket:connect(host, port)
    if not status then
        stdnse.debug1("Modbus connect failed: %s", err)
        return nil
    end

    local request = form_modbus_request(uid, 0x03, addr, qty)
    status, err = socket:send(request)
    if not status then
        socket:close()
        stdnse.debug1("Modbus send failed: %s", err)
        return nil
    end

    local response
    status, response = socket:receive()
    socket:close()

    if not status then
        stdnse.debug1("Modbus receive failed: %s", response)
        return nil
    end

    local data, parse_err = parse_modbus_response(response, 0x03)
    if not data then
        stdnse.debug1("Modbus parse failed: %s", parse_err)
        return nil
    end

    return data
end

---
-- Read input registers (FC 04)
-- @param host Host object
-- @param port Port object
-- @param uid Unit ID
-- @param addr Starting address
-- @param qty Quantity of registers
-- @return Raw data bytes, or nil on error
---
local function read_input_registers(host, port, uid, addr, qty)
    local socket = nmap.new_socket()
    socket:set_timeout(stdnse.get_timeout(host))

    local status, err = socket:connect(host, port)
    if not status then
        stdnse.debug1("Modbus connect failed: %s", err)
        return nil
    end

    local request = form_modbus_request(uid, 0x04, addr, qty)
    status, err = socket:send(request)
    if not status then
        socket:close()
        stdnse.debug1("Modbus send failed: %s", err)
        return nil
    end

    local response
    status, response = socket:receive()
    socket:close()

    if not status then
        stdnse.debug1("Modbus receive failed: %s", response)
        return nil
    end

    local data, parse_err = parse_modbus_response(response, 0x04)
    if not data then
        stdnse.debug1("Modbus parse failed: %s", parse_err)
        return nil
    end

    return data
end

--------------------------------------------------------------------------------
-- Data Conversion Functions
--------------------------------------------------------------------------------

---
-- Convert 2 bytes to signed 16-bit integer (big-endian from Modbus)
-- @param b1 High byte
-- @param b2 Low byte
-- @return Signed 16-bit integer
---
local function bytes_to_int16(b1, b2)
    local val = (b1 * 256) + b2
    if val >= 32768 then
        val = val - 65536
    end
    return val
end

---
-- Convert 4 bytes to signed 32-bit integer (little-endian word order for CLICK)
-- CLICK uses low word first: [low_hi, low_lo, high_hi, high_lo]
-- @param b1 Low word high byte
-- @param b2 Low word low byte
-- @param b3 High word high byte
-- @param b4 High word low byte
-- @return Signed 32-bit integer
---
local function bytes_to_int32(b1, b2, b3, b4)
    -- Low word (first register)
    local low_word = (b1 * 256) + b2
    -- High word (second register)
    local high_word = (b3 * 256) + b4
    -- Combine: little-endian word order
    local val = (high_word * 65536) + low_word
    -- Handle signed
    if val >= 2147483648 then
        val = val - 4294967296
    end
    return val
end

---
-- Convert 4 bytes to IP address string
-- @param b1, b2, b3, b4 IP address bytes
-- @return Dotted decimal string
---
local function format_ip(b1, b2, b3, b4)
    return string.format("%d.%d.%d.%d", b1, b2, b3, b4)
end

---
-- Convert 6 bytes to MAC address string
-- @param b1-b6 MAC address bytes
-- @return Colon-separated hex string
---
local function format_mac(b1, b2, b3, b4, b5, b6)
    return string.format("%02X:%02X:%02X:%02X:%02X:%02X", b1, b2, b3, b4, b5, b6)
end

---
-- Convert register bytes to firmware version string
-- CLICK stores firmware version in SD5 (minor) and SD6 (major)
-- Format: major.minor (e.g., 3.41)
-- @param data Raw register data (8 bytes for 4 registers: SD5-SD8)
-- @return Firmware version string
---
local function format_firmware(data)
    if #data < 4 then
        return "Unknown"
    end

    -- Read register values (each register is 2 bytes, big-endian)
    -- SD5 = minor version, SD6 = major version
    local minor = (string.byte(data, 1) * 256) + string.byte(data, 2)  -- SD5
    local major = (string.byte(data, 3) * 256) + string.byte(data, 4)  -- SD6

    -- Format as major.minor (e.g., 3.41)
    return string.format("%d.%02d", major, minor)
end

--------------------------------------------------------------------------------
-- Modbus Scan Function
--------------------------------------------------------------------------------

---
-- Perform Modbus scan to retrieve device info and I/O data
-- @param host Host object
-- @param port Port object
-- @param unit_id Modbus Unit ID
-- @param coil_count Number of coils to read
-- @param reg_count Number of registers to read
-- @return Output table with device info and I/O data
---
local function modbus_scan(host, port, unit_id, coil_count, reg_count)
    local output = stdnse.output_table()
    local got_data = false  -- Track if we collected any data

    stdnse.debug1("Modbus scan starting: uid=%d, coils=%d, regs=%d",
        unit_id, coil_count, reg_count)

    -- SD Register addresses (FC 03 - Holding Registers, base 0xF000)
    -- SD is indexed from 1, so SD1 at 0xF000, SD5 at 0xF004, etc.
    local SD_BASE = 0xF000
    local SD_FIRMWARE = SD_BASE + 4      -- SD5-SD6: Firmware (SD5=minor, SD6=major)
    local SD_IP = SD_BASE + 79           -- SD80-SD83: IP Address (4 regs)
    local SD_SUBNET = SD_BASE + 83       -- SD84-SD87: Subnet Mask (4 regs)
    local SD_GATEWAY = SD_BASE + 87      -- SD88-SD91: Gateway (4 regs)
    local SD_EIP_STATUS = SD_BASE + 100  -- SD101-SD102: EIP Status (2 regs)
    local SD_MAC = SD_BASE + 187         -- SD188-SD193: MAC Address (6 regs)

    -- I/O addresses
    local X_BASE = 0x0000   -- X inputs (FC 02)
    local Y_BASE = 0x2000   -- Y outputs (FC 01)
    local DS_BASE = 0x0000  -- DS registers (FC 03)
    local DD_BASE = 0x4000  -- DD registers (FC 03, 2 words each)

    ----------------------------------------------------------------------------
    -- Device Information Section
    ----------------------------------------------------------------------------
    local device_info = stdnse.output_table()
    local got_device_info = false

    -- Read Firmware Version (SD5-SD6, 2 registers)
    -- SD5 = minor version, SD6 = major version -> format as major.minor
    local fw_data = read_holding_registers(host, port, unit_id, SD_FIRMWARE, 2)
    if fw_data then
        local firmware = format_firmware(fw_data)
        device_info["Firmware"] = firmware
        stdnse.debug1("Firmware: %s", firmware)
        got_device_info = true
    else
        stdnse.debug1("Failed to read firmware version")
    end

    -- Read IP Address (SD80-SD83, 4 registers = 8 bytes, but IP in first 4 bytes)
    local ip_data = read_holding_registers(host, port, unit_id, SD_IP, 4)
    if ip_data and #ip_data >= 8 then
        -- IP stored as 4 separate registers (one byte per register's low byte)
        local b1 = string.byte(ip_data, 2)  -- Low byte of first register
        local b2 = string.byte(ip_data, 4)  -- Low byte of second register
        local b3 = string.byte(ip_data, 6)  -- Low byte of third register
        local b4 = string.byte(ip_data, 8)  -- Low byte of fourth register
        local ip_str = format_ip(b1, b2, b3, b4)
        device_info["IP Address"] = ip_str
        stdnse.debug1("IP Address: %s", ip_str)
        got_device_info = true
    else
        stdnse.debug1("Failed to read IP address")
    end

    -- Read Subnet Mask (SD84-SD87, 4 registers)
    local subnet_data = read_holding_registers(host, port, unit_id, SD_SUBNET, 4)
    if subnet_data and #subnet_data >= 8 then
        local b1 = string.byte(subnet_data, 2)
        local b2 = string.byte(subnet_data, 4)
        local b3 = string.byte(subnet_data, 6)
        local b4 = string.byte(subnet_data, 8)
        local subnet_str = format_ip(b1, b2, b3, b4)
        device_info["Subnet Mask"] = subnet_str
        stdnse.debug1("Subnet Mask: %s", subnet_str)
        got_device_info = true
    else
        stdnse.debug1("Failed to read subnet mask")
    end

    -- Read Gateway (SD88-SD91, 4 registers)
    local gw_data = read_holding_registers(host, port, unit_id, SD_GATEWAY, 4)
    if gw_data and #gw_data >= 8 then
        local b1 = string.byte(gw_data, 2)
        local b2 = string.byte(gw_data, 4)
        local b3 = string.byte(gw_data, 6)
        local b4 = string.byte(gw_data, 8)
        local gw_str = format_ip(b1, b2, b3, b4)
        device_info["Gateway"] = gw_str
        stdnse.debug1("Gateway: %s", gw_str)
        got_device_info = true
    else
        stdnse.debug1("Failed to read gateway")
    end

    -- Read MAC Address (SD188-SD193, 6 registers)
    local mac_data = read_holding_registers(host, port, unit_id, SD_MAC, 6)
    if mac_data and #mac_data >= 12 then
        -- MAC stored as 6 separate registers (one byte per register's low byte)
        local m1 = string.byte(mac_data, 2)
        local m2 = string.byte(mac_data, 4)
        local m3 = string.byte(mac_data, 6)
        local m4 = string.byte(mac_data, 8)
        local m5 = string.byte(mac_data, 10)
        local m6 = string.byte(mac_data, 12)
        local mac_str = format_mac(m1, m2, m3, m4, m5, m6)
        device_info["MAC Address"] = mac_str
        stdnse.debug1("MAC Address: %s", mac_str)
        got_device_info = true
    else
        stdnse.debug1("Failed to read MAC address")
    end

    -- Read EIP Status (SD101-SD102, 2 registers)
    local eip_data = read_holding_registers(host, port, unit_id, SD_EIP_STATUS, 2)
    if eip_data and #eip_data >= 4 then
        local status = bytes_to_int16(string.byte(eip_data, 1), string.byte(eip_data, 2))
        local enabled = (status ~= 0) and "Yes" or "No"
        device_info["EIP Enabled"] = string.format("%s (Status: 0x%04x)", enabled, status)
        stdnse.debug1("EIP Status: 0x%04x", status)
        got_device_info = true
    else
        stdnse.debug1("Failed to read EIP status")
    end

    -- Add device info to output if we got any data
    if got_device_info then
        output["Device Information"] = device_info
        got_data = true
    end

    ----------------------------------------------------------------------------
    -- I/O Data Section
    ----------------------------------------------------------------------------

    -- Read X Inputs (FC 02)
    local x_inputs = read_discrete_inputs(host, port, unit_id, X_BASE, coil_count)
    if x_inputs then
        local input_str = {}
        for i = 1, coil_count do
            input_str[i] = x_inputs[i] and "1" or "0"
        end
        output[string.format("Inputs (X001-X%03d)", coil_count)] = table.concat(input_str, " ")
        stdnse.debug1("X Inputs: %s", table.concat(input_str, " "))
        got_data = true
    else
        stdnse.debug1("Failed to read X inputs")
    end

    -- Read Y Outputs (FC 01)
    local y_outputs = read_coils(host, port, unit_id, Y_BASE, coil_count)
    if y_outputs then
        local output_str = {}
        for i = 1, coil_count do
            output_str[i] = y_outputs[i] and "1" or "0"
        end
        output[string.format("Outputs (Y001-Y%03d)", coil_count)] = table.concat(output_str, " ")
        stdnse.debug1("Y Outputs: %s", table.concat(output_str, " "))
        got_data = true
    else
        stdnse.debug1("Failed to read Y outputs")
    end

    -- Read DS Registers (FC 03)
    local ds_data = read_holding_registers(host, port, unit_id, DS_BASE, reg_count)
    if ds_data then
        local ds_values = {}
        for i = 1, reg_count do
            local offset = (i - 1) * 2 + 1
            if offset + 1 <= #ds_data then
                local val = bytes_to_int16(string.byte(ds_data, offset), string.byte(ds_data, offset + 1))
                ds_values[i] = val
            end
        end
        output[string.format("DS Registers (DS1-DS%d)", reg_count)] = table.concat(ds_values, ", ")
        stdnse.debug1("DS Registers: %s", table.concat(ds_values, ", "))
        got_data = true
    else
        stdnse.debug1("Failed to read DS registers")
    end

    -- Read DD Registers (FC 03, 2 words each)
    local dd_qty = reg_count * 2  -- Each DD is 2 registers
    local dd_data = read_holding_registers(host, port, unit_id, DD_BASE, dd_qty)
    if dd_data then
        local dd_values = {}
        for i = 1, reg_count do
            local offset = (i - 1) * 4 + 1  -- 4 bytes per DD
            if offset + 3 <= #dd_data then
                local val = bytes_to_int32(
                    string.byte(dd_data, offset),
                    string.byte(dd_data, offset + 1),
                    string.byte(dd_data, offset + 2),
                    string.byte(dd_data, offset + 3)
                )
                dd_values[i] = val
            end
        end
        output[string.format("DD Registers (DD1-DD%d)", reg_count)] = table.concat(dd_values, ", ")
        stdnse.debug1("DD Registers: %s", table.concat(dd_values, ", "))
        got_data = true
    else
        stdnse.debug1("Failed to read DD registers")
    end

    -- Check if we got any results
    if not got_data then
        stdnse.debug1("Modbus scan returned no data")
        return nil
    end

    -- Set port version info
    port.version.name = "modbus"
    nmap.set_port_version(host, port)

    return output
end

--------------------------------------------------------------------------------
-- Action Function
--------------------------------------------------------------------------------

action = function(host, port)
    -- Get script arguments
    local modbus_only = stdnse.get_script_args("click-plc-info.modbus-only") or false
    local enip_only = stdnse.get_script_args("click-plc-info.enip-only") or false
    local unit_id = tonumber(stdnse.get_script_args("click-plc-info.unit-id")) or 0
    local coil_count = tonumber(stdnse.get_script_args("click-plc-info.coil-count")) or 10
    local reg_count = tonumber(stdnse.get_script_args("click-plc-info.reg-count")) or 10
    local use_udp = stdnse.get_script_args("click-plc-info.udp") or false

    -- Validate arguments
    if unit_id < 0 or unit_id > 247 then
        stdnse.debug1("Invalid unit-id %d, using default 0", unit_id)
        unit_id = 0
    end
    if coil_count < 1 or coil_count > 100 then
        stdnse.debug1("Invalid coil-count %d, clamping to 1-100", coil_count)
        coil_count = math.max(1, math.min(100, coil_count))
    end
    if reg_count < 1 or reg_count > 100 then
        stdnse.debug1("Invalid reg-count %d, clamping to 1-100", reg_count)
        reg_count = math.max(1, math.min(100, reg_count))
    end

    stdnse.debug1("Script args: modbus_only=%s, enip_only=%s, unit_id=%d, coil_count=%d, reg_count=%d, udp=%s",
        tostring(modbus_only), tostring(enip_only), unit_id, coil_count, reg_count, tostring(use_udp))

    local results = stdnse.output_table()

    -- Route based on port number
    if port.number == 502 then
        if enip_only then
            stdnse.debug1("Skipping Modbus scan (enip-only mode)")
            return nil
        end

        -- Perform Modbus scan
        results = modbus_scan(host, port, unit_id, coil_count, reg_count)
        if not results then
            stdnse.debug1("Modbus scan returned no results")
            return nil
        end

    elseif port.number == 44818 then
        if modbus_only then
            stdnse.debug1("Skipping ENIP scan (modbus-only mode)")
            return nil
        end
        -- Perform ENIP scan (TCP or UDP based on argument/port protocol)
        local is_udp = use_udp or (port.protocol == "udp")
        if is_udp then
            stdnse.debug1("Using ENIP UDP scan")
            results = enip_scan_udp(host, port)
        else
            stdnse.debug1("Using ENIP TCP scan")
            results = enip_scan_tcp(host, port)
        end
        if not results then
            stdnse.debug1("ENIP scan returned no results")
            return nil
        end

    else
        stdnse.debug1("Unexpected port: %d", port.number)
        return nil
    end

    return results
end

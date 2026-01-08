# PLAN.md - Project Roadmap

## Current Status

**Active Development**: Phase 9 - Metasploit Module Development
**Phase**: COMPLETE (All phases 9.1-9.5 finished)
**Last Updated**: 2026-01-08

---

## Project Scope

This project contains scanner scripts and Metasploit modules:

### Python and Nmap Scripts

| Script | Protocol | Language | Status |
|--------|----------|----------|--------|
| click_modbus_scanner.py | Modbus TCP | Python | COMPLETE |
| click_enip_scanner.py | EtherNet/IP CIP | Python | COMPLETE |
| click-plc-info.nse | Modbus + ENIP | Lua (Nmap) | COMPLETE |

### Metasploit Modules

| Module | Protocol | Purpose | Status |
|--------|----------|---------|--------|
| modbus_click.rb | Modbus TCP | CLICK PLC address type scanning | COMPLETE |
| enip_scanner.rb | EtherNet/IP | Device identity and network enumeration | COMPLETE |
| enip_bruteforce.rb | EtherNet/IP CIP | CIP class/instance/attribute enumeration | COMPLETE |

---

## Modbus Scanner Status (Python)

| Phase | Name | Status |
|-------|------|--------|
| 1 | Foundation | COMPLETE |
| 2 | Core Scanner | COMPLETE |
| 3 | Output and CLI | COMPLETE |
| 4 | Configuration | COMPLETE |
| 5 | Polish | COMPLETE |

The Modbus scanner is feature-complete. See Session Log in RESUME.md for details.

---

## EtherNet/IP Scanner Status (Python)

| Phase | Name | Status |
|-------|------|--------|
| 1 | Foundation | COMPLETE |
| 2 | Device Info | COMPLETE |
| 3 | Data Retrieval | COMPLETE |
| 4 | Output and CLI | COMPLETE |
| 5 | Polish | COMPLETE |

The EtherNet/IP scanner is feature-complete. See Session Log in RESUME.md for details.

---

## NSE Script Phases (click-plc-info.nse)

| Phase | Name | Status | Description |
|-------|------|--------|-------------|
| 1 | Script Skeleton | COMPLETE | Portrule, args, basic structure |
| 2 | ENIP TCP | COMPLETE | List Identity over TCP |
| 3 | ENIP UDP | COMPLETE | List Identity over UDP |
| 4 | Modbus Helpers | COMPLETE | Frame building and parsing |
| 5 | Modbus Device Info | COMPLETE | SD register queries |
| 6 | Integration and Polish | COMPLETE | Argument validation, documentation |

The NSE script is feature-complete. See Session Log in RESUME.md for details.

---

## Phase 1: Script Skeleton

### 1.1 File Setup
- [ ] Create click-plc-info.nse with standard NSE headers
- [ ] Add description, author, license, categories
- [ ] Define portrule for ports 502 and 44818 (TCP/UDP)

### 1.2 Script Arguments
- [ ] `click-plc-info.modbus-only` - Skip ENIP
- [ ] `click-plc-info.enip-only` - Skip Modbus
- [ ] `click-plc-info.unit-id` - Modbus Unit ID (default 0)
- [ ] `click-plc-info.coil-count` - Number of coils to read (default 10)
- [ ] `click-plc-info.reg-count` - Number of registers to read (default 10)
- [ ] `click-plc-info.udp` - Use UDP for ENIP (default false)

### 1.3 Action Function Stub
- [ ] Detect protocol from port number
- [ ] Route to Modbus or ENIP handler
- [ ] Return empty output table

**Exit Criteria**: Script loads in Nmap without errors, arguments parse correctly.

---

## Phase 2: ENIP TCP

### 2.1 List Identity Request
- [ ] Build List Identity packet (command 0x63)
- [ ] Send via TCP socket to port 44818
- [ ] Receive and validate response

### 2.2 Response Parsing
- [ ] Parse command response header
- [ ] Extract device identity fields
- [ ] Implement minimal vendor lookup table (AutomationDirect, Rockwell, etc.)
- [ ] Implement device type lookup table

### 2.3 Output Table
- [ ] Populate output with Vendor, Device Type, Product Name
- [ ] Add Serial Number, Product Code, Revision
- [ ] Add Status, State, Device IP

**Exit Criteria**: ENIP TCP scan returns device identity on port 44818.

---

## Phase 3: ENIP UDP

### 3.1 UDP Socket Handling
- [ ] Create UDP socket option
- [ ] Send List Identity packet via UDP
- [ ] Handle UDP response

### 3.2 Integration
- [ ] Check `click-plc-info.udp` argument
- [ ] Route to TCP or UDP handler
- [ ] Reuse parsing logic from Phase 2

**Exit Criteria**: ENIP scan works over both TCP and UDP.

---

## Phase 4: Modbus Helpers

### 4.1 Frame Building
- [ ] `form_modbus_request(unit_id, function_code, start_addr, count)`
- [ ] Build Modbus TCP/IP ADU (MBAP header + PDU)
- [ ] Handle transaction ID generation

### 4.2 Response Parsing
- [ ] `parse_modbus_response(data, expected_fc)`
- [ ] Validate MBAP header and function code
- [ ] Extract data bytes
- [ ] Handle exception responses (minimal error output)

### 4.3 Data Conversion
- [ ] `bytes_to_int16(b1, b2)` - Little-endian signed 16-bit
- [ ] `bytes_to_int32(b1, b2, b3, b4)` - Little-endian signed 32-bit
- [ ] `format_ip(b1, b2, b3, b4)` - Format as dotted decimal
- [ ] `format_mac(b1, b2, b3, b4, b5, b6)` - Format as colon-separated hex

**Exit Criteria**: Helper functions tested with known byte sequences.

---

## Phase 5: Modbus Device Info

### 5.1 SD Register Reads
- [ ] Read SD5-SD8 (0xF004-F007) - Firmware Version
- [ ] Read SD80-SD83 (0xF04F-F052) - IP Address
- [ ] Read SD84-SD87 (0xF053-F056) - Subnet Mask
- [ ] Read SD88-SD91 (0xF057-F05A) - Gateway
- [ ] Read SD188-SD193 (0xF0BB-F0C0) - MAC Address
- [ ] Read SD101-SD102 (0xF064-F065) - EIP Status

### 5.2 Data Assembly
- [ ] Combine firmware version bytes into version string
- [ ] Format network addresses
- [ ] Interpret EIP status registers

### 5.3 Output Table
- [ ] Add "Modbus Device Information" section
- [ ] Populate Firmware, IP, Subnet, Gateway, MAC, EIP Status

**Exit Criteria**: Modbus device info section populated correctly.

---

## Phase 6: Modbus I/O Query

### 6.1 Coil Reading
- [ ] Read X inputs (FC 02, start 0x0000, count from arg)
- [ ] Read Y outputs (FC 01, start 0x2000, count from arg)
- [ ] Format as space-separated binary values

### 6.2 Register Reading
- [ ] Read DS registers (FC 03, start 0x0000, count from arg)
- [ ] Read DD registers (FC 03, start 0x4000, count*2 words)
- [ ] Convert DS to INT16, DD to INT32 (little-endian)
- [ ] Format as comma-separated values

### 6.3 Output Table
- [ ] Add Inputs line: "Inputs (X001-X0nn): 0 0 1 ..."
- [ ] Add Outputs line: "Outputs (Y001-Y0nn): 0 0 0 ..."
- [ ] Add DS line: "DS Registers (DS1-DSnn): 0, 100, ..."
- [ ] Add DD line: "DD Registers (DD1-DDnn): 0, 0, ..."

**Exit Criteria**: I/O data displayed correctly with configurable counts.

---

## Phase 7: Output Formatting

### 7.1 Combined Output
- [ ] Merge ENIP and Modbus results into single output table
- [ ] Handle cases where one protocol fails/skipped
- [ ] Ensure consistent formatting

### 7.2 Protocol Selection Logic
- [ ] Implement modbus-only flag
- [ ] Implement enip-only flag
- [ ] Handle port-based auto-detection

### 7.3 Edge Cases
- [ ] No response from device
- [ ] Partial data (some reads fail)
- [ ] Timeout handling

**Exit Criteria**: Clean output for all protocol combinations.

---

## Phase 8: Testing and Documentation

### 8.1 Testing
- [ ] Test against CLICK PLUS C2-03CPU-2
- [ ] Verify Modbus data accuracy
- [ ] Verify ENIP data accuracy
- [ ] Test all script arguments
- [ ] Test TCP and UDP ENIP

### 8.2 Documentation
- [ ] Update README.md with NSE section
- [ ] Update USAGE.md with NSE usage examples
- [ ] Add inline comments to script
- [ ] Document known limitations

**Exit Criteria**: Script ready for use, documentation complete.

---

## Script Arguments Reference

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `click-plc-info.modbus-only` | boolean | false | Skip ENIP, scan Modbus only |
| `click-plc-info.enip-only` | boolean | false | Skip Modbus, scan ENIP only |
| `click-plc-info.unit-id` | integer | 0 | Modbus Unit ID |
| `click-plc-info.coil-count` | integer | 10 | Number of X/Y coils to read |
| `click-plc-info.reg-count` | integer | 10 | Number of DS/DD registers to read |
| `click-plc-info.udp` | boolean | false | Use UDP for ENIP (default TCP) |

---

## Modbus Address Reference

### Device Information (FC 04 - Input Registers)

| Data | SD Address | Modbus HEX | Words |
|------|------------|------------|-------|
| Firmware Version | SD5-SD8 | 0xF004-F007 | 4 |
| IP Address | SD80-SD83 | 0xF04F-F052 | 4 |
| Subnet Mask | SD84-SD87 | 0xF053-F056 | 4 |
| Gateway | SD88-SD91 | 0xF057-F05A | 4 |
| MAC Address | SD188-SD193 | 0xF0BB-F0C0 | 6 |
| EIP Status | SD101-SD102 | 0xF064-F065 | 2 |

### I/O Data

| Data | Type | FC | Start Address |
|------|------|-----|---------------|
| Inputs (X) | Discrete Inputs | 02 | 0x0000 |
| Outputs (Y) | Coils | 01 | 0x2000 |
| DS Registers | Holding Registers | 03 | 0x0000 |
| DD Registers | Holding Registers | 03 | 0x4000 |

---

## Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| Nmap | 7.x+ | NSE runtime |
| Lua | 5.3+ | Script language (bundled with Nmap) |

---

## Risk Register

| Risk | Impact | Status | Mitigation |
|------|--------|--------|------------|
| Lua binary parsing complexity | Medium | OPEN | Use string.pack/unpack (Lua 5.3+) |
| CLICK Unit ID requirements | Low | MITIGATED | Default to 0, allow arg override |
| UDP ENIP firewall issues | Low | OPEN | TCP is default, UDP optional |
| Modbus exception handling | Low | MITIGATED | Minimal error output, skip failed reads |

---

## Test Environment

| Item | Value |
|------|-------|
| PLC Model | CLICK PLUS C2-03CPU-2 |
| Modbus Port | 502 |
| EtherNet/IP Port | 44818 |
| Nmap Version | 7.x+ |

---

## Milestones

| Milestone | Phase | Description |
|-----------|-------|-------------|
| M1 | 1 Complete | Script loads, args parse |
| M2 | 3 Complete | ENIP works (TCP and UDP) |
| M3 | 6 Complete | Modbus works (device info + I/O) |
| M4 | 8 Complete | Tested and documented |
| M5 | 9.1 Complete | CLICK Modbus MSF module functional |
| M6 | 9.2 Complete | ENIP Scanner MSF module functional |
| M7 | 9.3 Complete | ENIP Brute Force MSF module functional |
| M8 | 9.5 Complete | All MSF modules tested and documented |

---

# Phase 9: Metasploit Module Development

## Overview

Development of three custom Metasploit Framework auxiliary scanner modules for SCADA/ICS security assessments. All modules are **READ-ONLY** - no write operations.

### Key Design Decisions

| Decision | Implementation |
|----------|----------------|
| Operations | Read-only only (no write operations) |
| Vendor IDs | Source from Nmap enip-info.nse (1513+ vendors) |
| Safety | Brute force module includes lab-only warning |
| Output | Consistent with MSF modbus modules (print_good, print_status) |
| Database | Use report_note() pattern from modbus_banner_grabbing.rb |
| Testing | CLICK PLC sufficient; support broader class/instance ranges |

### Installation Location

All modules install to: `~/.msf4/modules/auxiliary/scanner/scada/`

---

## Phase 9.1: CLICK Modbus Client Module

**File**: `modbus_click.rb`
**Status**: COMPLETE
**Tested**: 2026-01-08 against CLICK PLC at 192.168.0.10

### 9.1.1 Module Skeleton
- [x] Create module file with MSF structure
- [x] Define class inheritance (Msf::Auxiliary)
- [x] Include required mixins (Remote::Tcp, Report, Scanner)
- [x] Add module metadata (Name, Description, Author, License)
- [x] Define Actions array for read operations
- [x] Register options (RPORT, UNIT_ID, ADDRESS_START, etc.)

### 9.1.2 CLICK Address Mapping
- [x] Define CLICK_ADDRESSES constant with all address types
- [x] Map address types to Modbus function codes
- [x] Map address types to start addresses (HEX)
- [x] Define data types (INT16, INT32, FLOAT, BOOL)
- [x] Define default counts per address type

### 9.1.3 Core Read Functions
- [x] Implement make_read_payload() for FC 01-04
- [x] Implement send_modbus_frame() with transaction ID
- [x] Implement read_coils() for X, Y, C, T, CT, SC
- [x] Implement read_registers() for DS, DD, DF, SD
- [x] Add response parsing and error handling

### 9.1.4 Data Type Conversion
- [x] Implement convert_int16() - signed 16-bit
- [x] Implement convert_int32() - little-endian 32-bit
- [x] Implement convert_float() - IEEE 754
- [x] Implement format_bits() - coil display

### 9.1.5 Device Info Action
- [x] Implement READ_DEVICE_INFO action
- [x] Read firmware from SD5-SD8 (fixed byte order: minor first, then major)
- [x] Read IP/Subnet/Gateway from SD80-SD91
- [x] Read MAC from SD188-SD193
- [x] Format and display device information

### 9.1.6 Database Reporting
- [x] Add report_note() calls for each read
- [x] Include address type, value, and raw data
- [x] Follow modbus_banner_grabbing.rb pattern

### 9.1.7 Testing and Polish
- [x] Test all actions against CLICK PLC
- [x] Verify output format consistency
- [x] Verify database reporting
- [x] Add inline documentation

**Exit Criteria**: ACHIEVED - Module loads in msfconsole, READ_DEVICE_INFO verified, firmware displays correctly as 3.41.

---

## Phase 9.2: ENIP Scanner Module

**File**: `enip_scanner.rb`
**Status**: COMPLETE
**Tested**: 2026-01-08

### 9.2.1 Module Skeleton
- [x] Create module file with MSF structure
- [x] Include required mixins (Remote::Tcp, Report, Scanner)
- [x] Add module metadata (Name, Description, Author, References)
- [x] Define Actions (LIST_IDENTITY, FULL_SCAN)
- [x] Register options (RPORT, TIMEOUT, UDP)

### 9.2.2 Vendor and Device Tables
- [x] Import vendor_id table from Nmap enip-info.nse (1500+ entries)
- [x] Import device_type table from Nmap enip-info.nse
- [x] Implement lookup functions with fallback ("Unknown Vendor/Device")

### 9.2.3 List Identity Implementation
- [x] Build ENIP List Identity packet (command 0x0063)
- [x] Send packet and receive response (TCP and UDP support)
- [x] Validate response and parse CPF items (Type ID 0x000C)
- [x] Parse identity fields (vendor, device type, product code, revision, serial, product name)
- [x] Display formatted output with human-readable vendor/device names

### 9.2.4 CIP Session Management
- [x] Implemented register_session() - ENIP command 0x0065
- [x] Implemented unregister_session() - ENIP command 0x0066
- [x] Implemented build_cip_path() for class/instance/attribute addressing
- [x] Implemented build_cip_request() wrapping CIP in Send RR Data
- [x] Implemented send_cip_request() with response parsing
- [x] Implemented get_attribute() using service 0x0E (Get Attribute Single)

### 9.2.5 Network Information via CIP
- [x] Read TCP/IP Interface (0xF5) Attribute 5 for IP, Subnet, Gateway
- [x] Read TCP/IP Interface (0xF5) Attribute 6 for Hostname
- [x] Read Ethernet Link (0xF6) Attribute 1 for Interface Speed
- [x] Read Ethernet Link (0xF6) Attribute 3 for MAC Address
- [x] Implemented parse_interface_config(), parse_hostname(), parse_mac_address()
- [x] Added NETWORK_INFO action
- [x] Enhanced FULL_SCAN to combine LIST_IDENTITY + NETWORK_INFO

### 9.2.6 Database Reporting
- [x] Add report_service() for ENIP discovery
- [x] Add report_note() for identity data
- [x] Follow MSF reporting conventions

### 9.2.7 Testing and Polish
- [ ] Test LIST_IDENTITY against CLICK PLC (pending user testing)
- [ ] Test UDP mode (pending user testing)
- [x] Verify module loads in msfconsole
- [x] Add inline documentation

**Exit Criteria**: Module loads in msfconsole, List Identity works via TCP/UDP, database reporting implemented. CIP explicit messaging deferred to Phase 9.3.

---

## Phase 9.3: ENIP Brute Force Module

**File**: `enip_bruteforce.rb`
**Status**: COMPLETE
**Tested**: 2026-01-08

### 9.3.1 Module Skeleton with Safety Warning
- [x] Create module file with MSF structure
- [x] Add prominent WARNING in Description about lab-only use
- [x] Include required mixins (Remote::Tcp, Report, Scanner)
- [x] Define Actions (KNOWN_OBJECTS, ENUMERATE_CLASSES, ENUMERATE_INSTANCES, ENUMERATE_ATTRIBUTES, FULL_ENUMERATION)
- [x] Register options (CLASS_START/END, INSTANCE_START/END, ATTRIBUTE_START/END, DELAY, TARGET_CLASS, TARGET_INSTANCE)

### 9.3.2 Known Classes Configuration
- [x] Define KNOWN_CLASSES constant with 7 documented CIP classes
- [x] Include Identity (0x01), Message Router (0x02), Assembly (0x04), Connection Manager (0x06), Port (0xF4), TCP/IP (0xF5), Ethernet Link (0xF6)
- [x] Define expected instances and attributes per class
- [x] Add attribute name mappings for all known attributes

### 9.3.3 CIP Request Implementation
- [x] Implement register_session() - ENIP command 0x0065
- [x] Implement unregister_session() - ENIP command 0x0066
- [x] Implement get_attribute() using service 0x0E (Get Attribute Single)
- [x] Build CIP path for class/instance/attribute with 8-bit and 16-bit support
- [x] Parse CIP response with 40+ status codes defined

### 9.3.4 Enumeration Functions
- [x] Implement action_enumerate_classes() - scan class range
- [x] Implement action_enumerate_instances() - scan instance range for class
- [x] Implement action_enumerate_attributes() - scan attribute range for class/instance
- [x] Implement action_known_objects() - scan only documented classes (safest)
- [x] Implement action_full_enumeration() - comprehensive scan

### 9.3.5 Data Interpretation
- [x] Implement format_data() for raw hex display
- [x] Implement interpret_data() for UINT8, UINT16, INT16, UINT32, INT32, FLOAT
- [x] Implement MAC address interpretation for 6-byte data
- [x] Implement string interpretation for printable ASCII

### 9.3.6 Rate Limiting and Safety
- [x] Implement configurable DELAY option (default 100ms)
- [x] Add display_warning() with prominent safety message
- [x] Handle CIP errors gracefully with status code lookup

### 9.3.7 Database Reporting
- [x] Add report_note() for discovered objects (enip.cip_objects)
- [x] Add report_note() for supported classes (enip.supported_classes)
- [x] Include class, instance, attribute, data, and interpreted values

### 9.3.8 Testing and Polish
- [ ] Test KNOWN_OBJECTS against CLICK PLC (pending user testing)
- [x] Error handling for unsupported objects implemented
- [x] Rate limiting implemented
- [x] Database reporting implemented

**Exit Criteria**: Module loads in msfconsole, all 5 actions implemented, CIP session management working, safety warnings displayed, rate limiting configurable.

---

## Phase 9.4: Integration Testing

**Status**: COMPLETE (automated checks passed, manual testing by user)
**Tested**: 2026-01-08

### 9.4.1 Module Loading
- [x] Verify all three modules load in msfconsole
- [x] Verify reload_all works correctly
- [x] Verify module info displays correctly
- [x] Ruby syntax validation passed for all modules

### 9.4.2 Structural Verification
- [x] All modules inherit from Msf::Auxiliary
- [x] All modules include required mixins (Remote::Tcp, Report, Scanner)
- [x] All modules define initialize() and run_host() methods
- [x] All actions properly defined and routed

### 9.4.3 Functional Testing (Manual by User)
- [x] Test enip_scanner.rb LIST_IDENTITY against CLICK PLC
- [x] Test enip_bruteforce.rb KNOWN_OBJECTS against CLICK PLC
- [x] NETWORK_INFO and FULL_SCAN actions added and verified

### 9.4.4 Database Reporting
- [x] All report_note() calls use hash format (deprecation warning fixed)
- [x] Data structures verified as hashes for all modules

### 9.4.5 Code Quality
- [x] Error handling present in all modules (rescue blocks, print_error)
- [x] Default actions set appropriately (READ_DEVICE_INFO, LIST_IDENTITY, KNOWN_OBJECTS)
- [x] Default ports correct (502 for Modbus, 44818 for ENIP)
- [x] Rate limiting implemented in brute force module

**Exit Criteria**: ACHIEVED - All modules pass syntax checks, structural verification complete, manual testing confirmed functional.

---

## Phase 9.5: Documentation Updates

**Status**: COMPLETE
**Completed**: 2026-01-08

### 9.5.1 Usage Documentation
- [x] Metasploit section already present in USAGE.md
- [x] Fixed action name: GET_NETWORK_INFO → NETWORK_INFO
- [x] Enhanced ENIP Brute Force examples with class/instance/attribute scenarios
- [x] Added Common CIP Class Reference table (decimal and hex)
- [x] Installation steps documented
- [x] Troubleshooting section included

### 9.5.2 README Updates
- [x] Metasploit modules section present in README.md
- [x] Enhanced quick start with ENUMERATE_ATTRIBUTES example
- [x] Requirements section includes MSF 6.x+ and Ruby 2.7+

### 9.5.3 VIBE_HISTORY Updates
- [x] Phase 9.2 Enhancement session documented
- [x] Phase 9.4 Integration Testing session documented
- [x] Phase 9.5 Documentation session documented
- [x] Issues encountered and solutions documented

**Exit Criteria**: ACHIEVED - All documentation updated, installation and usage clear, examples comprehensive.

---

## Metasploit Module Reference

### Module Actions Summary

#### modbus_click.rb

| Action | Function Code | Description |
|--------|---------------|-------------|
| READ_INPUTS | FC 02 | Read X0-X8 discrete inputs |
| READ_OUTPUTS | FC 01 | Read Y0-Y8 coil outputs |
| READ_CONTROL_RELAYS | FC 01 | Read C control relays |
| READ_DS | FC 03 | Read DS registers (INT16) |
| READ_DD | FC 03 | Read DD registers (INT32) |
| READ_DF | FC 03 | Read DF registers (FLOAT) |
| READ_DEVICE_INFO | FC 03/04 | Read SD system registers |
| SCAN_COMMON | FC 01-04 | Scan common address types |

#### enip_scanner.rb

| Action | ENIP Command | Description |
|--------|--------------|-------------|
| LIST_IDENTITY | 0x0063 | Get device identity (no session required) |
| NETWORK_INFO | 0x0065, 0x006F | Read network config via CIP explicit messaging |
| FULL_SCAN | 0x0063, 0x0065, 0x006F | Full enumeration (identity + network info) |

Note: TCP and UDP transport supported via UDP option. NETWORK_INFO and the CIP portion of FULL_SCAN require TCP (CIP explicit messaging not available over UDP).

#### enip_bruteforce.rb

| Action | Description |
|--------|-------------|
| ENUMERATE_CLASSES | Scan class range for supported classes |
| ENUMERATE_INSTANCES | Scan instance range for specific class |
| ENUMERATE_ATTRIBUTES | Scan attribute range for class/instance |
| KNOWN_OBJECTS | Scan only documented common classes |
| FULL_ENUMERATION | Comprehensive brute force scan |

### CIP Classes for Brute Force

| Class | Name | Instances | Priority |
|-------|------|-----------|----------|
| 0x01 | Identity | 1 | High |
| 0x02 | Message Router | 1 | Medium |
| 0x04 | Assembly | 100-199 | High |
| 0x06 | Connection Manager | 1 | Medium |
| 0xF4 | Port | 1-4 | Medium |
| 0xF5 | TCP/IP Interface | 1 | High |
| 0xF6 | Ethernet Link | 1-4 | High |

---

## Risk Register (Phase 9)

| Risk | Impact | Status | Mitigation |
|------|--------|--------|------------|
| CLICK PLC limited CIP support | Low | OPEN | Test what works, document limitations |
| Brute force PLC impact | High | MITIGATED | Lab-only warning, rate limiting |
| MSF API changes | Low | OPEN | Follow current MSF module patterns |
| Vendor ID table maintenance | Low | ACCEPTED | Use Nmap source, static table |

---

## Test Environment (Phase 9)

| Item | Value |
|------|-------|
| PLC Model | CLICK PLUS C2-03CPU-2 |
| Modbus Port | 502 |
| EtherNet/IP Port | 44818 |
| Metasploit Version | Current (snap) |
| Installation Path | ~/.msf4/modules/auxiliary/scanner/scada/ |

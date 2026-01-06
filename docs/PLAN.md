# PLAN.md - Project Roadmap

## Current Status

**Active Development**: None - All scripts complete
**Phase**: Project Complete
**Last Updated**: 2026-01-06

---

## Project Scope

This project contains three scanner scripts:

| Script | Protocol | Language | Status |
|--------|----------|----------|--------|
| click_modbus_scanner.py | Modbus TCP | Python | COMPLETE |
| click_enip_scanner.py | EtherNet/IP CIP | Python | COMPLETE |
| click-plc-info.nse | Modbus + ENIP | Lua (Nmap) | COMPLETE |

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

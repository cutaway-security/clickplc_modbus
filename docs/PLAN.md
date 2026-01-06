# PLAN.md - Project Roadmap

## Current Status

**Phase**: 1 - ENIP Foundation
**Step**: 1.1 - Project Setup
**Last Updated**: 2026-01-05

---

## Project Scope

This project contains two scanner scripts:

| Script | Protocol | Status |
|--------|----------|--------|
| click_mb_scanner.py | Modbus TCP | COMPLETE |
| click_enip_scanner.py | EtherNet/IP CIP | IN PROGRESS |

---

## Modbus Scanner Status

| Phase | Name | Status |
|-------|------|--------|
| 1 | Foundation | COMPLETE |
| 2 | Core Scanner | COMPLETE |
| 3 | Output and CLI | COMPLETE |
| 4 | Configuration | COMPLETE |
| 5 | Polish | COMPLETE |

The Modbus scanner is feature-complete. See Session Log in RESUME.md for details.

---

## EtherNet/IP Scanner Phases

| Phase | Name | Status | Description |
|-------|------|--------|-------------|
| 1 | Foundation | NOT STARTED | Project setup, CPPPO testing, basic connectivity |
| 2 | Device Info | NOT STARTED | Identity and Network object reading |
| 3 | Data Retrieval | NOT STARTED | Assembly data reading, multi-format interpretation |
| 4 | System Config | NOT STARTED | Hybrid ENIP + Modbus for --sysconfig |
| 5 | Output and CLI | NOT STARTED | Formatting, argument parsing |
| 6 | Polish | NOT STARTED | Error handling, documentation |

---

## Phase 1: Foundation

### 1.1 Project Setup (NOT STARTED)
- [ ] Update claude.md with ENIP scope
- [ ] Update ARCHITECTURE.md with ENIP design
- [ ] Update PLAN.md (this file)
- [ ] Update RESUME.md for ENIP tracking
- [ ] Add cpppo>=5.0.0 to requirements.txt

### 1.2 CPPPO Testing (NOT STARTED)
- [ ] Install cpppo and verify import
- [ ] Test basic session registration with CLICK PLC (port 44818)
- [ ] Verify proxy_simple works for CLICK (simple CIP device)
- [ ] Test path syntax: @class/instance/attribute
- [ ] Document any CPPPO quirks or required options (-S flag?)
- [ ] Confirm data type handling for byte arrays

### 1.3 Script Skeleton (NOT STARTED)
- [ ] Create click_enip_scanner.py with section comments
- [ ] Implement CPPPO dependency check with graceful failure
- [ ] Implement basic argument parser (host, --port)
- [ ] Implement connect_enip() with session registration
- [ ] Verify script runs and shows help
- [ ] Test basic connection to real PLC

**Exit Criteria**: Script connects to CLICK via ENIP, session registered

---

## Phase 2: Device Info

### 2.1 Identity Object (NOT STARTED)
- [ ] Implement get_identity() - Class 0x01, Instance 1
- [ ] Read Attribute 1: Vendor ID (UINT)
- [ ] Read Attribute 2: Device Type (UINT)
- [ ] Read Attribute 3: Product Code (UINT)
- [ ] Read Attribute 4: Revision (Major.Minor)
- [ ] Read Attribute 5: Status (WORD)
- [ ] Read Attribute 6: Serial Number (UDINT)
- [ ] Read Attribute 7: Product Name (SHORT_STRING)
- [ ] Implement --info CLI option
- [ ] Test against real PLC

### 2.2 Network Objects (NOT STARTED)
- [ ] Implement get_tcp_ip_interface() - Class 0xF5, Instance 1
- [ ] Parse IP address, subnet mask, gateway from Attribute 5
- [ ] Implement get_ethernet_link() - Class 0xF6, Instance 1
- [ ] Parse MAC address, link speed
- [ ] Implement --network CLI option
- [ ] Test against real PLC

**Exit Criteria**: --info and --network return valid device data

---

## Phase 3: Data Retrieval

### 3.1 Assembly Reading (NOT STARTED)
- [ ] Implement get_assembly_data() - Class 0x04
- [ ] Support Instance 101 (Connection 1 Input) - default
- [ ] Support Instance 103 (Connection 2 Input) via --connection 2
- [ ] Read configurable byte count (--size, default 500)
- [ ] Handle size mismatch (requested vs actual)
- [ ] Add --connection CLI option (1 or 2)
- [ ] Test against real PLC with known config (432 bytes)

### 3.2 Multi-Format Interpretation (NOT STARTED)
- [ ] Implement interpret_as_int16() - little-endian signed
- [ ] Implement interpret_as_uint16() - little-endian unsigned
- [ ] Implement interpret_as_int32() - little-endian signed
- [ ] Implement interpret_as_float() - IEEE 754 single precision
- [ ] Implement interpret_as_hex() - raw bytes as hex string
- [ ] Implement interpret_as_ascii() - printable characters only
- [ ] Implement multi_format_display() - combined view with alignment

### 3.3 Console Output (NOT STARTED)
- [ ] Display header with target, connection, size
- [ ] Display offset column (hex)
- [ ] Display raw hex dump (16 bytes per row)
- [ ] Display INT16 interpretation
- [ ] Display INT32 interpretation
- [ ] Display ASCII interpretation (printable only)
- [ ] Align columns for readability

**Exit Criteria**: Default scan shows assembly data in multiple formats

---

## Phase 4: System Config

### 4.1 Modbus Integration (NOT STARTED)
- [ ] Import PyModbus (check as optional dependency)
- [ ] Implement connect_modbus() with separate port option
- [ ] Add --modbus-port CLI option (default 502)

### 4.2 Network Registers (NOT STARTED)
- [ ] Implement read_network_registers()
- [ ] Read SD80-SD83: IP Address octets (FC 04)
- [ ] Read SD84-SD87: Subnet Mask octets (FC 04)
- [ ] Read SD88-SD91: Gateway octets (FC 04)
- [ ] Read SD188-SD193: MAC Address octets (FC 04)
- [ ] Format IP as dotted decimal
- [ ] Format MAC as colon-separated hex

### 4.3 EtherNet/IP Status (NOT STARTED)
- [ ] Implement read_eip_status_coils()
- [ ] Read SC111-SC116: Connection status bits (FC 02)
- [ ] Implement read_eip_status_registers()
- [ ] Read SD101-SD105: Status registers (FC 04)
- [ ] Read SD106-SD108: Connection 1 counters (FC 03)
- [ ] Read SD109-SD111: Status registers (FC 04)
- [ ] Read SD112-SD114: Connection 2 counters (FC 03)

### 4.4 Sysconfig Option (NOT STARTED)
- [ ] Implement --sysconfig CLI option
- [ ] Combine ENIP identity + network + Modbus system data
- [ ] Handle case where Modbus port is blocked (graceful failure)
- [ ] Format combined output clearly

**Exit Criteria**: --sysconfig returns comprehensive system info

---

## Phase 5: Output and CLI

### 5.1 Markdown Output (NOT STARTED)
- [ ] Implement format_markdown()
- [ ] Include scan metadata (target, date, scanner version)
- [ ] Include device identity section
- [ ] Include network information section
- [ ] Include assembly data with hex dump
- [ ] Include interpreted data tables
- [ ] Add --output argument (.md extension required)
- [ ] Include timestamp in output filename

### 5.2 CLI Polish (NOT STARTED)
- [ ] Implement --full option (--info + --network + data)
- [ ] Verify --port works correctly (default 44818)
- [ ] Verify --modbus-port works correctly (default 502)
- [ ] Add --timeout for connection timeout
- [ ] Implement input validation (IP format, port range, size range)
- [ ] Add --help with clear usage examples

**Exit Criteria**: Full CLI working, Markdown output functional

---

## Phase 6: Polish

### 6.1 Error Handling (NOT STARTED)
- [ ] Handle CPPPO connection errors gracefully
- [ ] Parse CIP General Status codes with descriptions
- [ ] Parse CIP Extended Status codes with descriptions
- [ ] Reference CLICK EtherNet/IP Error Code documentation
- [ ] Handle Modbus errors for --sysconfig (continue with ENIP data)
- [ ] Add helpful error messages with troubleshooting hints

### 6.2 Documentation (NOT STARTED)
- [ ] Update README.md with ENIP scanner section
- [ ] Update USAGE.md with ENIP documentation
- [ ] Document CLI options with examples
- [ ] Document CIP addressing for CLICK
- [ ] Add troubleshooting section for common errors
- [ ] Document --sysconfig Modbus addresses

### 6.3 Testing (NOT STARTED)
- [ ] Test all CLI options against real PLC
- [ ] Test error conditions (wrong port, no connection, etc.)
- [ ] Verify Markdown output format
- [ ] Test --sysconfig with Modbus available
- [ ] Test --sysconfig with Modbus blocked
- [ ] Verify multi-format interpretation accuracy

**Exit Criteria**: Ready for student use

---

## Dependencies

| Dependency | Version | Purpose | Required |
|------------|---------|---------|----------|
| Python | 3.11+ | Runtime | Yes |
| cpppo | >=5.0.0 | EtherNet/IP CIP | Yes |
| pymodbus | >=3.6.0,<4.0.0 | Modbus for --sysconfig | Optional |

---

## Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| CPPPO API complexity | Medium | Start with proxy_simple, test incrementally |
| Unknown assembly size | Medium | Default to 500 bytes, handle size mismatch gracefully |
| CIP path syntax issues | Medium | Test @class/instance/attribute format early |
| CLICK as simple device | Medium | May need -S flag or special handling |
| Assembly not configured | High | Clear error message, suggest checking PLC config |
| Modbus blocked | Low | Make --sysconfig Modbus optional, graceful failure |
| CIP error codes | Low | Reference CLICK error code documentation |

---

## Test Environment

| Item | Value |
|------|-------|
| PLC Model | CLICK PLUS C2-03CPU-2 |
| EtherNet/IP Port | 44818 (default) |
| Modbus TCP Port | 502 (default) |
| Connection 1 Config | DS1-DS72 (144 bytes) + DD3-DD74 (288 bytes) |
| Total Assembly Size | 432 bytes |
| PyEnv | Development server with CPPPO installed |

---

## Milestones

| Milestone | Phase | Description |
|-----------|-------|-------------|
| M1 | 1 Complete | Script connects to CLICK via ENIP |
| M2 | 2 Complete | --info and --network return data |
| M3 | 3 Complete | Default scan shows multi-format data |
| M4 | 4 Complete | --sysconfig returns hybrid data |
| M5 | 5 Complete | Full CLI and Markdown output |
| M6 | 6 Complete | Ready for release |

---

## Notes

- Keep implementation simple - single script preferred
- Test against real hardware (CLICK PLUS C2-03CPU-2) when available
- Prioritize reliability over features
- Student-friendly error messages
- Multi-format interpretation is key for unknown configurations
- No CSV output for ENIP (data format not suitable)
- Console output must be readable in terminal
- Markdown output for reporting and documentation

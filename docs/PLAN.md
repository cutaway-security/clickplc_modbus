# PLAN.md - Project Roadmap

## Current Status

**Phase**: 5 - Polish (COMPLETE)
**Step**: All steps complete
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
| 1 | Foundation | COMPLETE | Project setup, library testing, basic connectivity |
| 2 | Device Info | COMPLETE | Identity and Network object reading |
| 3 | Data Retrieval | COMPLETE | Assembly data reading, multi-format interpretation |
| 4 | Output and CLI | COMPLETE | Formatting, --full option, Markdown output |
| 5 | Polish | COMPLETE | Error handling, documentation |

**Note**: Original Phase 4 (System Config) was removed. The hybrid ENIP+Modbus --sysconfig
feature is out of scope - this scanner uses EtherNet/IP CIP only. Network and device
information is already available via --info and --network options.

---

## Phase 1: Foundation

### 1.1 Project Setup (COMPLETE)
- [x] Update claude.md with ENIP scope
- [x] Update ARCHITECTURE.md with ENIP design
- [x] Update PLAN.md (this file)
- [x] Update RESUME.md for ENIP tracking
- [x] Add cpppo>=5.0.0 to requirements.txt

### 1.2 Library Testing (COMPLETE)
- [x] Install cpppo and verify import (v5.2.5)
- [x] Test basic session registration with CLICK PLC (port 44818)
- [x] Test proxy_simple for CLICK - ISSUE: read() returns "Service not supported"
- [x] Test path syntax: @class/instance/attribute - works in attribute_operations()
- [x] Document CPPPO quirks - see notes below
- [x] Test pycomm3 as alternative - SUCCESS: CIPDriver.generic_message() works
- [x] Confirm data type handling for byte arrays - raw bytes returned correctly

**Library Decision**: Use pycomm3.CIPDriver instead of CPPPO for CIP operations.
CPPPO list_identity() works but attribute reads fail with "Service not supported".
pycomm3 generic_message() works for all CIP services on CLICK.

**Verified Working:**
- Identity Object (0x01): All attributes 1-7
- TCP/IP Interface (0xF5): Attributes 1-6
- Ethernet Link (0xF6): Attributes 1-3
- Assembly Object (0x04): Instance 101, Attribute 3 (432 bytes)

### 1.3 Script Skeleton (COMPLETE)
- [x] Create click_enip_scanner.py with section comments
- [x] Implement pycomm3 dependency check with graceful failure
- [x] Implement basic argument parser (host, --port, --timeout)
- [x] Implement connect_enip() using CIPDriver
- [x] Verify script runs and shows help
- [x] Test basic connection to real PLC

**Exit Criteria**: Script connects to CLICK via ENIP, session registered - ACHIEVED

---

## Phase 2: Device Info

### 2.1 Identity Object (COMPLETE)
- [x] Implement get_identity() - Class 0x01, Instance 1
- [x] Read Attribute 1: Vendor ID (UINT)
- [x] Read Attribute 2: Device Type (UINT)
- [x] Read Attribute 3: Product Code (UINT)
- [x] Read Attribute 4: Revision (Major.Minor)
- [x] Read Attribute 5: Status (WORD)
- [x] Read Attribute 6: Serial Number (UDINT)
- [x] Read Attribute 7: Product Name (SHORT_STRING)
- [x] Implement --info CLI option
- [x] Test against real PLC

### 2.2 Network Objects (COMPLETE)
- [x] Implement get_tcp_ip_interface() - Class 0xF5, Instance 1
- [x] Parse IP address, subnet mask, gateway from Attribute 5
- [x] Implement get_ethernet_link() - Class 0xF6, Instance 1
- [x] Parse MAC address, link speed
- [x] Implement --network CLI option
- [x] Test against real PLC

**Exit Criteria**: --info and --network return valid device data - ACHIEVED

---

## Phase 3: Data Retrieval

### 3.1 Assembly Reading (COMPLETE)
- [x] Implement get_assembly_data() - Class 0x04
- [x] Support Instance 101 (Connection 1 Input) - default
- [x] Support Instance 103 (Connection 2 Input) via --connection 2
- [x] Read configurable byte count (--size, default 500)
- [x] Handle size mismatch (requested vs actual) - shows warning
- [x] Add --connection CLI option (1 or 2)
- [x] Test against real PLC with known config (432 bytes)

### 3.2 Multi-Format Interpretation (COMPLETE)
- [x] Implement interpret_as_int16() - little-endian signed
- [x] Implement interpret_as_uint16() - little-endian unsigned
- [x] Implement interpret_as_int32() - little-endian signed
- [x] Implement interpret_as_float() - IEEE 754 single precision
- [x] Implement interpret_as_hex() - raw bytes as hex string
- [x] Implement interpret_as_ascii() - printable characters only
- [x] Implement multi_format_display() - combined view with alignment

### 3.3 Console Output (COMPLETE)
- [x] Display header with target, connection, size
- [x] Display offset column (hex)
- [x] Display raw hex dump (16 bytes per row)
- [x] Display INT16 interpretation
- [x] Display INT32 interpretation
- [x] Display ASCII interpretation (printable only)
- [x] Align columns for readability
- [x] Add --hex flag for legacy hex-only output

**Exit Criteria**: Default scan shows assembly data in multiple formats - ACHIEVED

---

## Phase 4: Output and CLI

### 4.1 Markdown Output (COMPLETE)
- [x] Implement format_markdown() functions
- [x] Include scan metadata (target, date, scanner version)
- [x] Include device identity section
- [x] Include network information section
- [x] Include assembly data with hex dump
- [x] Include interpreted data tables (INT16, INT32, FLOAT)
- [x] Add --output argument (.md extension required)
- [x] Include timestamp in output filename

### 4.2 CLI Polish (COMPLETE)
- [x] Implement --full option (--info + --network + data)
- [x] Verify --port works correctly (default 44818)
- [x] Add --timeout for connection timeout
- [x] Implement input validation (IP format, port range, size range)
- [x] Add --help with clear usage examples
- [x] Add mutually exclusive group for --info/--network/--full

**Exit Criteria**: Full CLI working, Markdown output functional - ACHIEVED

---

## Phase 5: Polish

### 5.1 Error Handling (COMPLETE)
- [x] Handle pycomm3 connection errors gracefully
- [x] Parse CIP General Status codes with descriptions
- [x] Parse CIP Extended Status codes with descriptions
- [x] Reference CLICK EtherNet/IP Error Code documentation
- [x] Add helpful error messages with troubleshooting hints

### 5.2 Documentation (COMPLETE)
- [x] Update README.md with ENIP scanner section
- [x] Update USAGE.md with ENIP documentation
- [x] Document CLI options with examples
- [x] Document CIP addressing for CLICK
- [x] Add troubleshooting section for common errors

### 5.3 Testing (COMPLETE)
- [x] Test all CLI options against real PLC
- [x] Test error conditions (wrong port, no connection, etc.)
- [x] Verify Markdown output format
- [x] Verify multi-format interpretation accuracy

**Exit Criteria**: Ready for student use - ACHIEVED

---

## Dependencies

| Dependency | Version | Purpose | Required |
|------------|---------|---------|----------|
| Python | 3.11+ | Runtime | Yes |
| pycomm3 | >=1.0.0 | EtherNet/IP CIP (primary) | Yes |

**Note**: pycomm3 replaced CPPPO as primary library. CPPPO's read operations return
"Service not supported" for CLICK PLCs. pycomm3 CIPDriver.generic_message() works.
This scanner uses EtherNet/IP CIP only - no Modbus dependency.

---

## Risk Register

| Risk | Impact | Status | Mitigation |
|------|--------|--------|------------|
| CPPPO API complexity | Medium | RESOLVED | Switched to pycomm3 which has simpler API |
| CPPPO incompatible with CLICK | High | RESOLVED | pycomm3 CIPDriver works for all CIP operations |
| Unknown assembly size | Medium | MITIGATED | Tested: returns actual configured size (432 bytes) |
| CIP path syntax issues | Medium | RESOLVED | pycomm3 uses class_code/instance/attribute params |
| CLICK as simple device | Medium | RESOLVED | No special flags needed with pycomm3 |
| Assembly not configured | High | RESOLVED | Tested: Returns "Object does not exist" error, script handles gracefully |
| CIP error codes | Low | OPEN | Reference CLICK error code documentation |

---

## Test Environment

| Item | Value |
|------|-------|
| PLC Model | CLICK PLUS C2-03CPU-2 |
| EtherNet/IP Port | 44818 (default) |
| Connection 1 Config | DS1-DS72 (144 bytes) + DD3-DD74 (288 bytes) |
| Total Assembly Size | 432 bytes |
| pycomm3 | Installed and working |

---

## Milestones

| Milestone | Phase | Description |
|-----------|-------|-------------|
| M1 | 1 Complete | Script connects to CLICK via ENIP |
| M2 | 2 Complete | --info and --network return data |
| M3 | 3 Complete | Default scan shows multi-format data |
| M4 | 4 Complete | Full CLI (--full) and Markdown output |
| M5 | 5 Complete | Ready for release |

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

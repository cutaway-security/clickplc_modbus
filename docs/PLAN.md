# PLAN.md - Project Roadmap

## Current Status

**Phase**: 1 - Foundation
**Step**: 1.1 - Project Setup
**Last Updated**: 2025-01-05

---

## Phase Overview

| Phase | Name | Status | Description |
|-------|------|--------|-------------|
| 1 | Foundation | IN PROGRESS | Project structure, core data models, dependency handling |
| 2 | Core Scanner | NOT STARTED | Modbus communication, address scanning |
| 3 | Output and CLI | NOT STARTED | Formatting, argument parsing, user interface |
| 4 | Configuration | NOT STARTED | CSV import, filtered scanning |
| 5 | Polish | NOT STARTED | Error messages, documentation, packaging |

---

## Phase 1: Foundation

### 1.1 Project Setup (CURRENT)
- [x] Create claude.md with project rules
- [x] Create ARCHITECTURE.md with design
- [x] Create PLAN.md (this file)
- [ ] Create RESUME.md
- [ ] Create VIBE_HISTORY.md
- [ ] Create requirements.txt
- [ ] Update README.md with basic usage

### 1.2 Script Skeleton
- [ ] Create click_modbus_scanner.py with section comments
- [ ] Implement PyModbus dependency check
- [ ] Implement basic argument parser (IP address only)
- [ ] Verify script runs and shows help

### 1.3 Data Structures
- [ ] Define AddressType dataclass
- [ ] Define ScanResult dataclass
- [ ] Create CLICK_ADDRESS_TYPES constant dictionary
- [ ] Create COMMON_TYPES list for default scanning

**Exit Criteria**: Script runs, shows help, checks for PyModbus

---

## Phase 2: Core Scanner

### 2.1 Modbus Connection
- [ ] Implement connect_to_plc() with timeout handling
- [ ] Implement connection retry logic
- [ ] Test connection to real PLC
- [ ] Handle connection errors gracefully

### 2.2 Read Operations
- [ ] Implement read_coils() wrapper (FC 01)
- [ ] Implement read_discrete_inputs() wrapper (FC 02)
- [ ] Implement read_holding_registers() wrapper (FC 03)
- [ ] Implement read_input_registers() wrapper (FC 04)
- [ ] Add rate limiting between requests

### 2.3 Address Scanning
- [ ] Implement scan_address_range() for single type
- [ ] Handle multi-word registers (DD, DF, DH, CTD)
- [ ] Implement data conversion functions
- [ ] Test scanning each priority 1-3 type

**Exit Criteria**: Can scan DS, DF, C, X0, Y0 types and display raw results

---

## Phase 3: Output and CLI

### 3.1 Console Output
- [ ] Implement format_console() with tab separation
- [ ] Add header row
- [ ] Format values by data type (bool, int, float, hex)
- [ ] Handle long nicknames/descriptions

### 3.2 File Output
- [ ] Implement format_csv() with timestamp filename
- [ ] Implement format_markdown() with timestamp filename
- [ ] Add --output argument for file path

### 3.3 CLI Arguments
- [ ] Add --type for comma-separated type selection
- [ ] Add --full for complete scan
- [ ] Add --format for 984 vs HEX addressing
- [ ] Add --rate for timing control
- [ ] Add --port for non-standard port
- [ ] Add --verbose for detailed output
- [ ] Implement input validation

**Exit Criteria**: Full CLI working, all three output formats functional

---

## Phase 4: Configuration

### 4.1 CSV Parsing
- [ ] Implement parse_click_csv() for both 984 and HEX formats
- [ ] Handle CSV encoding variations
- [ ] Extract nickname information

### 4.2 Filtered Scanning
- [ ] Add --config argument for CSV path
- [ ] Implement extract_used_addresses() filter
- [ ] Merge nicknames into scan results
- [ ] Test with real CLICK project export

**Exit Criteria**: Can scan only addresses from CSV, nicknames appear in output

---

## Phase 5: Polish

### 5.1 Error Handling
- [ ] Review all error paths
- [ ] Add helpful error messages with troubleshooting steps
- [ ] Test common failure scenarios
- [ ] Add --quiet flag for minimal output

### 5.2 Documentation
- [ ] Update README.md with complete usage examples
- [ ] Add example output samples
- [ ] Document CSV export process from CLICK software
- [ ] Add troubleshooting section

### 5.3 Packaging
- [ ] Verify requirements.txt is complete
- [ ] Test fresh install process
- [ ] Create setup.py or pyproject.toml for pip install
- [ ] Tag release version

**Exit Criteria**: Ready for student use, installable via pip

---

## Milestones

| Milestone | Target | Description |
|-----------|--------|-------------|
| M1 | Phase 1 Complete | Script skeleton runs, shows help |
| M2 | Phase 2 Complete | Can scan PLC and show results |
| M3 | Phase 3 Complete | Full CLI and output formats |
| M4 | Phase 4 Complete | CSV configuration working |
| M5 | Phase 5 Complete | Ready for release |

---

## Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| PyModbus API changes | Medium | Pin version in requirements.txt |
| PLC unavailable for testing | High | Document expected behavior, test when available |
| Large scan timeouts | Medium | Implement chunked reading, progress indicator |
| CSV format variations | Low | Test with multiple CLICK project exports |

---

## Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| Python | 3.11+ | Runtime |
| pymodbus | 3.x | Modbus TCP communication |

---

## Notes

- Keep implementation simple - single script preferred
- Test against real hardware (CLICK PLUS C2-03CPU-2) when available
- Prioritize reliability over features
- Student-friendly error messages

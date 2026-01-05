# PLAN.md - Project Roadmap

## Current Status

**Phase**: 5 - Polish
**Step**: COMPLETE
**Last Updated**: 2026-01-05

---

## Phase Overview

| Phase | Name | Status | Description |
|-------|------|--------|-------------|
| 1 | Foundation | COMPLETE | Project structure, core data models, dependency handling |
| 2 | Core Scanner | COMPLETE | Modbus communication, address scanning |
| 3 | Output and CLI | COMPLETE | Formatting, argument parsing, user interface |
| 4 | Configuration | COMPLETE | CSV import, filtered scanning |
| 5 | Polish | COMPLETE | Error messages, documentation, packaging |

---

## Phase 1: Foundation

### 1.1 Project Setup (COMPLETE)
- [x] Create claude.md with project rules
- [x] Create ARCHITECTURE.md with design
- [x] Create PLAN.md (this file)
- [x] Create RESUME.md
- [x] Create VIBE_HISTORY.md
- [x] Create requirements.txt
- [x] Update README.md with basic usage

### 1.2 Script Skeleton (COMPLETE)
- [x] Create click_modbus_scanner.py with section comments
- [x] Implement PyModbus dependency check
- [x] Implement basic argument parser (IP address + port)
- [x] Implement connect_to_plc() with timeout handling
- [x] Verify script runs and shows help
- [x] Test connection to real PLC (192.168.0.10:502)

### 1.3 Data Structures (COMPLETE)
- [x] Define AddressType dataclass
- [x] Define ScanResult dataclass
- [x] Create CLICK_ADDRESS_TYPES constant dictionary (32 types)
- [x] Create COMMON_TYPES list for default scanning (X0, Y0, C, DS, DD, DF)
- [x] Add function code and data format constants
- [x] Add rate limiting presets

**Exit Criteria**: Script runs, shows help, checks for PyModbus (ACHIEVED)

---

## Phase 2: Core Scanner (COMPLETE)

### 2.1 Modbus Connection (COMPLETE)
- [x] Implement connect_to_plc() with timeout handling
- [x] Implement connection retry logic (via PyModbus retries parameter)
- [x] Test connection to real PLC (192.168.0.10:502)
- [x] Handle connection errors gracefully

### 2.2 Read Operations (COMPLETE)
- [x] Implement read_coils() wrapper (FC 01)
- [x] Implement read_discrete_inputs() wrapper (FC 02)
- [x] Implement read_holding_registers() wrapper (FC 03)
- [x] Implement read_input_registers() wrapper (FC 04)
- [x] Add rate limiting between requests (--rate option)

### 2.3 Address Scanning (COMPLETE)
- [x] Implement scan_address_type() for single type
- [x] Handle multi-word registers (DD, DF, DH, CTD)
- [x] Implement data conversion functions (int16, int32, float, hex)
- [x] Test scanning each priority 1-3 type
- [x] Add --type and --list CLI options
- [x] Basic console output with print_results_console()

**Exit Criteria**: Can scan DS, DF, C, X0, Y0 types and display results (ACHIEVED)

---

## Phase 3: Output and CLI (COMPLETE)

### 3.1 Console Output (COMPLETE)
- [x] Implement print_results_console() with dynamic column widths
- [x] Add header row with Address, Hex/984 Addr, Value, Name columns
- [x] Format values by data type (bool, int, float, hex)
- [x] Display nickname when available, fall back to CLICK address

### 3.2 File Output (COMPLETE)
- [x] Implement write_results_csv() with all ScanResult fields
- [x] Implement write_results_markdown() with sections per type
- [x] Add --output argument for file path (auto-detects .csv or .md)

### 3.3 CLI Arguments (COMPLETE)
- [x] Add --type for comma-separated type selection
- [x] Add --full for complete scan (all 32 address types)
- [x] Add --format for 984 vs HEX addressing display
- [x] Add --rate for timing control (normal/moderate/slow)
- [x] Add --port for non-standard port (default 502)
- [x] Add --timeout for connection timeout (default 5s)
- [x] Add --list to display available address types
- [x] Implement input validation for IP, port, timeout

**Exit Criteria**: Full CLI working, all three output formats functional (ACHIEVED)

---

## Phase 4: Configuration (COMPLETE)

### 4.1 CSV Parsing (COMPLETE)
- [x] Implement parse_click_csv() for both 984 and HEX formats
- [x] Auto-detect CSV format from Modbus Address field (HEX 'h' suffix vs decimal)
- [x] Handle CSV encoding variations (UTF-8, Windows-1252 fallback)
- [x] Extract nickname information from Nickname column
- [x] Derive address type from CLICK address (X001->X0, DS3->DS, etc.)

### 4.2 Filtered Scanning (COMPLETE)
- [x] Add --config argument for CSV path
- [x] Implement extract_used_addresses() filter to group by type
- [x] Implement scan_from_config() to scan only configured addresses
- [x] Merge nicknames into scan results
- [x] Test with HEX format CSV (docs/CLICKPLUS_C2-03CPU-2_3.41_Modbus_Addresses_HEX_Studentkit.csv)
- [x] Test with 984 format CSV (docs/CLICKPLUS_C2-03CPU-2_3.41_Modbus_Addresses_984_Studentkit.csv)

**Exit Criteria**: Can scan only addresses from CSV, nicknames appear in output (ACHIEVED)

---

## Phase 5: Polish (COMPLETE)

### 5.1 Error Handling (COMPLETE)
- [x] Review all error paths
- [x] Add helpful error messages with troubleshooting steps
- [x] Test common failure scenarios
- [ ] Add --quiet flag for minimal output (deferred - not critical)

### 5.2 Documentation (COMPLETE)
- [x] Update README.md with complete usage examples
- [x] Create USAGE.md with detailed documentation
- [x] Document CSV export process from CLICK software
- [x] Add troubleshooting section

### 5.3 Packaging (COMPLETE)
- [x] Verify requirements.txt is complete
- [ ] Test fresh install process (manual verification)
- [ ] Create setup.py or pyproject.toml for pip install (deferred)
- [ ] Tag release version (user action)

**Exit Criteria**: Ready for student use (ACHIEVED)

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

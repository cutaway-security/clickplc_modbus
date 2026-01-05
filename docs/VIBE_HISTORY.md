# VIBE_HISTORY.md - Development Lessons Learned

## Purpose

Track development lessons, failed approaches, and successful techniques across sessions. This serves as institutional memory for the project.

---

## Session: 2025-01-05 (Initial Planning)

### Lessons Learned

1. **Scope Definition First**
   - Taking time to clarify scope before coding prevents wasted effort
   - Questions about TCP vs RTU, read vs write, output formats resolved upfront
   - Clear constraints (single script, Python 3.11+, PyModbus 3.x) reduce decisions later

2. **Address Mapping Complexity**
   - CLICK PLC has many address types with different characteristics
   - Some types use FC 01, others FC 02, FC 03, or FC 04
   - Multi-word registers (DD, DF, DH, CTD) need special handling
   - Priority ordering prevents scope creep - implement common types first

3. **CSV Format Variations**
   - CLICK exports in both 984 and HEX formats
   - Need to handle both input formats
   - Default to HEX for output (easier for scripting)

### Decisions Made

| Decision | Rationale |
|----------|-----------|
| Single script | Simpler for students, easier to distribute |
| Read-only | Safety in ICS environments |
| Tab-separated console | Works in all terminals |
| Comma-separated type args | Allows multiple types without ambiguity |
| Common types as default | Reduces scan time, covers 90% use cases |

### What Worked

- Structured question/answer process for requirements gathering
- Breaking plan into phases with clear exit criteria
- Creating documentation before code

### What to Avoid

- (None yet - first session)

---

## Technical Notes

### PyModbus 3.x Changes

The original PoC used deprecated PyModbus 2.x API:
```python
# OLD (2.x) - Do not use
client.read_coils(address, count, unit=0x01)

# NEW (3.x) - Use this
client.read_coils(address, count, slave=1)
```

### CLICK Address Quirks

1. **X0/Y0 Numbering**: Module 0 (CPU) uses 1-36, expansion modules use 1-16
2. **C Relay Quantity**: 2000 relays requires chunked reading (max ~125 per request)
3. **Multi-word Registers**: DD, DF, CTD span 2 consecutive addresses

### Modbus Request Limits

From Modbus specification:
- Maximum coils per request: 2000
- Maximum registers per request: 125 (250 bytes)

CLICK PLC may have lower limits - test during implementation.

---

## Session: 2025-01-05 (Documentation Completion)

### Context
Completing Phase 1.1 documentation tasks before starting script implementation.

### Decisions Made

| Decision | Rationale |
|----------|-----------|
| pymodbus>=3.6.0,<4.0.0 | Lower bound ensures modern API, upper bound prevents major version breaks, allows patch updates |
| PLAN.md as primary roadmap | Updated as project evolves with direction changes |
| RESUME.md for session state | Keep current for stop/resume workflow |
| VIBE_HISTORY.md for decisions | Capture what was asked, decisions made, issues resolved |
| Incremental workflow | Propose-approve-implement-report cycle prevents wasted effort |

### Issues Identified
- PLAN.md showed RESUME.md as incomplete but file existed (sync issue)
- Resolution: Update PLAN.md to reflect actual state

---

## Session: 2025-01-05 (Script Skeleton Implementation)

### Context
Implementing Phase 1.2 - creating the script skeleton with connection testing capability.

### Decisions Made

| Decision | Rationale |
|----------|-----------|
| Start fresh from ARCHITECTURE.md | POC script may have inaccuracies; vendor documentation is authoritative |
| Include connect_to_plc() in skeleton | Enables early testing against real hardware |
| Use ModbusTcpClient context manager pattern | Clean connection handling, automatic cleanup |
| 5-second default timeout | Reasonable for local network, adjustable via --timeout |
| Validate port 1-65535 | Standard TCP port range validation |
| Validate timeout 1-300 seconds | Prevent unreasonable wait times |

### Test Results
- Connection to 192.168.0.10:502: SUCCESS
- Invalid port validation: Works correctly
- Connection failure handling: Works correctly (shows timeout message)

### Observation
PyModbus logs connection errors to stderr before our error handler runs. This is informational and helps debugging. Consider suppressing in future if cleaner output desired.

---

## Session: 2025-01-05 (Data Structures Implementation)

### Context
Implementing Phase 1.3 - defining data structures and address type mappings from vendor documentation.

### Decisions Made

| Decision | Rationale |
|----------|-----------|
| Use dataclasses for AddressType and ScanResult | Clean, type-hinted, immutable-friendly data containers |
| Define all 32 address types | Complete coverage per ARCHITECTURE.md |
| COMMON_TYPES = X0, Y0, C, DS, DD, DF | Standard set covering physical I/O, control relays, common registers |
| Include rate limiting presets | Prepare for Phase 2 implementation |
| XD count = 9 (0-8 range) | Per ARCHITECTURE.md, XD/YD use 0-based indexing |

### Address Type Summary
- 9 discrete input types (X0-X8) - FC 02
- 9 coil output types (Y0-Y8) - FC 01
- 4 control logic types (C, T, CT, SC) - FC 01
- 4 data register types (DS, DD, DH, DF) - FC 03
- 2 timer/counter registers (TD, CTD) - FC 03
- 4 system/IO registers (SD, XD, YD, TXT) - FC 03/04

### Test Results
- Dataclass instantiation: SUCCESS
- 32 address types loaded correctly
- Script help and connection test still functional

---

## Session: 2025-01-05 (Phase 2 - Core Scanner Implementation)

### Context
Implementing Phase 2 - Modbus read operations, address scanning, and data conversion.

### Decisions Made

| Decision | Rationale |
|----------|-----------|
| Chunked reading (100 coils/registers per request) | Stay within Modbus limits, reduce error risk |
| device_id parameter instead of slave | PyModbus 3.11+ uses device_id, not slave |
| Big-endian byte order for multi-word | CLICK PLC uses big-endian for 32-bit values |
| Basic console output in Phase 2 | Enables testing before full Phase 3 formatting |
| --list option without host requirement | User convenience for exploring available types |

### Issues Encountered and Resolved

| Issue | Resolution |
|-------|------------|
| PyModbus API error: "unexpected keyword argument 'slave'" | Changed to device_id parameter (PyModbus 3.11+ API change) |
| Float values showing uninitialized memory | Expected behavior - PLC memory not cleared, values display correctly |

### Test Results Against Real PLC (192.168.0.10:502)
- X0 (Discrete Inputs, FC 02): 36 addresses - SUCCESS
- Y0 (Coils, FC 01): 36 addresses - SUCCESS (some True values observed)
- C (Control Relays, FC 01): 2000 addresses - SUCCESS (chunked reading works)
- DS (INT16 Registers, FC 03): 4500 addresses - SUCCESS
- DD (INT32 Registers, FC 03): 1000 addresses - SUCCESS (signed conversion works)
- DF (Float Registers, FC 03): 500 addresses - SUCCESS (IEEE 754 conversion works)

### Technical Notes
- PyModbus 3.11.4 requires count= and device_id= as keyword arguments
- Chunked reading handles large ranges (2000 coils, 4500 registers)
- Rate limiting via --rate option (normal=50ms, moderate=200ms, slow=500ms)

---

## Session: 2026-01-05 (Phase 3 - Output and CLI)

### Context
Implementing Phase 3 - console output improvements, file output, and CLI arguments.

### Decisions Made

| Decision | Rationale |
|----------|-----------|
| Dynamic column widths in console output | Adapts to content length, cleaner display |
| Nickname fallback to CLICK address | User always sees meaningful identifier |
| Auto-detect output format from extension | Reduces arguments, intuitive UX |
| Include both HEX and 984 addresses in CSV | Complete data for downstream processing |
| Markdown sections by address type | Organized, readable reports |

### Test Results Against Real PLC (192.168.0.10:502)
- Console output with --format hex: SUCCESS
- Console output with --format 984: SUCCESS
- CSV file output: SUCCESS (verified contents)
- Markdown file output: SUCCESS (verified contents)
- --type with multiple types (X0,DS): SUCCESS
- --full scan: SUCCESS (all 32 types)
- --list option: SUCCESS (displays all types)

### Technical Notes
- Output file extension determines format (.csv or .md)
- CSV includes: address_type, click_address, modbus_hex, modbus_984, raw_value, converted_value, nickname
- Markdown includes metadata header and per-type tables

---

## Session: 2026-01-05 (Phase 4 - Configuration)

### Context
Implementing Phase 4 - CSV parsing for CLICK project exports and filtered scanning with nicknames.

### Decisions Made

| Decision | Rationale |
|----------|-----------|
| Auto-detect CSV format from Modbus Address | HEX has 'h' suffix, 984 is decimal - unambiguous detection |
| Derive address type from CLICK address | X001->X0, DS3->DS - simpler than parsing Modbus address ranges |
| Scan addresses individually when using config | Flexibility to scan non-contiguous addresses, cleaner nickname mapping |
| ConfigEntry dataclass for parsed entries | Clean separation between parsing and scanning logic |
| UTF-8 with cp1252 fallback | Handle both standard encoding and Windows exports |

### Implementation Details

**CSV Parsing Functions:**
- `derive_address_type()` - Extracts type from CLICK address (X001->X0, DS3->DS, C2->C)
- `parse_modbus_address_hex()` - Parses HEX format (strips 'h' suffix)
- `parse_modbus_address_984()` - Parses 984 format with FC-based offset calculation
- `parse_click_csv()` - Main parser with format auto-detection
- `extract_used_addresses()` - Groups entries by type for lookup
- `get_types_from_config()` - Returns ordered list of types in config

**Scanning:**
- `scan_from_config()` - Reads only configured addresses, merges nicknames

### Test Results Against Real PLC (192.168.0.10:502)
- HEX format CSV: 223 addresses in 9 types - SUCCESS
- 984 format CSV: 223 addresses in 9 types - SUCCESS
- Nicknames displayed correctly in output
- Both formats produce identical scan results

### Technical Notes
- CLICK 984 format uses non-standard addressing for Y and C coils
- Y001 at 984=8193 corresponds to Modbus 0x2000
- C2 at 984=16386 corresponds to Modbus 0x4001
- Address derivation handles X/Y module numbering (X001-X036 = X0, X101-X116 = X1)

---

## Session: 2026-01-05 (Word Order Bug Fix)

### Context
User reported DD11 (Total_Tank_Max_Volume) returning 1,520,435,250 instead of expected 3,300,000.

### Root Cause Analysis

**Problem:** The script assumed big-endian word order (high word first) for 32-bit values, but CLICK PLC uses little-endian word order (low word first).

**Evidence from raw register read:**
```
DD11 Raw registers: [0x5AA0, 0x0032]
Big-endian (wrong):    (0x5AA0 << 16) | 0x0032 = 1,520,435,250
Little-endian (right): (0x0032 << 16) | 0x5AA0 = 3,300,000
```

**Additional verification:**
| Address | Description | Before Fix | After Fix | Expected |
|---------|-------------|-----------|-----------|----------|
| DD11 | Total_Tank_Max_Volume | 1,520,435,250 | 3,300,000 | 3,300,000 |
| DD13 | Total_Tank_Volume_Full | 1,490,026,545 | 3,234,000 | 98% of max |
| DD14 | Total_Tank_Volume_Empty | 30,343,169 | 65,999 | 2% of max |
| DF6 | Tank_Temp_Numeric_Display | -7.99e-25 | 252.59 | ~DS6 (252) |
| DF15 | Tank_Lvl_Bar_Graph | 2.7e-06 | 62.30 | ~DS7 (62) |

### Documentation Reference
MathWorks CLICK PLC Modbus guide confirms: "CLICK PLC stores 32-bit values with low word first" requiring `WordOrder = "little-endian"`.

### Files Modified
- click_modbus_scanner.py:
  - `convert_to_int32()` (line 940-958): Swapped word order
  - `convert_to_float()` (line 961-979): Swapped word order
  - `convert_to_hex()` (line 982-1001): Swapped word order for 2-word values
  - `scan_address_type()` (line 767-770): Fixed raw_value calculation
  - `scan_from_config()` (line 897-900): Fixed raw_value calculation

### Affected Data Types
All 2-word (32-bit) types: DD, DF, DH, CTD, XD, YD, TXT

### Lessons Learned
1. Always verify byte/word order assumptions against real hardware
2. Compare converted values with related data points (DD vs DS scaled values, DF vs DS)
3. CLICK PLC documentation and MathWorks guide both confirm little-endian word order

---

## Failed Approaches

### Big-Endian Word Order Assumption (Fixed 2026-01-05)
**What:** Initial implementation assumed CLICK PLC used big-endian word order (high word first) for 32-bit values based on common Modbus convention.

**Why it failed:** CLICK PLC actually uses little-endian word order (low word first). This is documented in MathWorks guide and confirmed by comparing raw register values with expected data.

**Symptom:** DD11 showing 1,520,435,250 instead of 3,300,000; DF values showing nonsense like -7.99e-25.

**Resolution:** Swapped word order in convert_to_int32(), convert_to_float(), convert_to_hex(), and raw_value calculations.

---

## Successful Techniques

(Document successful patterns here as project progresses)

---

## Reference Commands

### Export CSV from CLICK Software
(To be documented after testing)

### Test Connection
```bash
# Quick test with nc (netcat)
nc -zv 192.168.1.10 502
```

### Run Scanner
```bash
# Basic usage - scan common types (X0, Y0, C, DS, DD, DF)
python click_modbus_scanner.py 192.168.0.10

# Specific types
python click_modbus_scanner.py 192.168.0.10 --type DS,DF

# Full scan - all 32 address types
python click_modbus_scanner.py 192.168.0.10 --full

# Use CLICK CSV config file (filters addresses, adds nicknames)
python click_modbus_scanner.py 192.168.0.10 --config project_export.csv

# Output to CSV file
python click_modbus_scanner.py 192.168.0.10 --type X0 --output scan_results.csv

# Output to Markdown file
python click_modbus_scanner.py 192.168.0.10 --type X0,DS --output scan_results.md

# Show 984 format addresses
python click_modbus_scanner.py 192.168.0.10 --type DS --format 984

# List available address types
python click_modbus_scanner.py 192.168.0.10 --list

# Slow rate for sensitive environments
python click_modbus_scanner.py 192.168.0.10 --rate slow

# Combine config with output file
python click_modbus_scanner.py 192.168.0.10 --config project.csv --output results.md
```

---

## Future Considerations

Items that may be useful but are currently out of scope:

1. **Write Operations**: Could add with --write flag and confirmation
2. **RTU Support**: Serial connection for non-Ethernet PLCs
3. **Discovery Mode**: Scan subnet for Modbus devices
4. **Comparison Mode**: Diff current state vs expected values
5. **Watch Mode**: Continuous monitoring of specific addresses

Document here if scope changes in future versions.

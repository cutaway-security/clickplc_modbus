# VIBE_HISTORY.md - Development Lessons Learned

## Purpose

Track development lessons, failed approaches, and successful techniques across sessions. This serves as institutional memory for the project.

---

## Session: 2026-01-06 (Project Rename)

### Context
Project renamed from `clickplc_modbus` to `click-plc-scanner` to better reflect the expanded scope (Modbus + EtherNet/IP + NSE script).

### Changes Made

**Repository:**
- Old: `https://github.com/cutaway-security/clickplc_modbus`
- New: `https://github.com/cutaway-security/click-plc-scanner`

**Script Naming Standardization:**
- Documentation updated to reference `click_modbus_scanner.py` (actual filename)
- Previous documentation incorrectly referenced `click_mb_scanner.py`

**Files Updated (11 files, 26 edits):**

Phase 1 - Claude Development Files:
- claude.md - Repository URL, file structure, script references
- docs/PLAN.md - Script table, status updates
- docs/RESUME.md - Status table, section headers, session log
- docs/ARCHITECTURE.md - Overview list, section headers, script organization
- docs/GIT_RELEASE_STEPS.md - Example paths and URLs (16 occurrences)
- docs/VIBE_HISTORY.md - Added rename session entry

Phase 2 - User Documentation:
- README.md - Script references (7 occurrences)
- USAGE.md - Script references and anchor link fix

Phase 3 - Configuration/Code Files:
- requirements.txt - Comment reference
- click_modbus_scanner.py - Repository URL in header
- click_enip_scanner.py - Repository URL in header

**Note:** Historical references in VIBE_HISTORY.md intentionally preserved to maintain accurate development history.

### Issues Encountered

**Broken Anchor Link:**
- After renaming `click_mb_scanner.py` references to `click_modbus_scanner.py`, the table of contents anchor link in USAGE.md was broken
- Link `#modbus-scanner-click_mb_scannerpy` needed to match new header anchor `#modbus-scanner-click_modbus_scannerpy`
- Lesson: When renaming items referenced in Markdown headers, also update corresponding anchor links

### Lessons Learned

1. **Project naming should anticipate scope expansion**
   - Original name `clickplc_modbus` became limiting when EtherNet/IP and NSE scripts were added
   - `click-plc-scanner` is protocol-agnostic and more descriptive

2. **Consistent file naming prevents documentation drift**
   - Actual file `click_modbus_scanner.py` was documented as `click_mb_scanner.py` in multiple places
   - Standardize naming early and enforce through review

3. **Phased rename approach reduces errors**
   - Breaking rename into phases (Claude files, user docs, code files) allows incremental review
   - Verify each phase before proceeding to catch issues early

4. **Use replace_all for systematic changes**
   - When a string appears multiple times, `replace_all` ensures consistency
   - Follow up with grep search to verify no occurrences were missed

5. **Anchor links are auto-generated from headers**
   - Markdown converts headers to lowercase, replaces spaces with hyphens, removes special characters
   - When updating header text, must also update any anchor links pointing to it

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

## Session: 2026-01-05 (EtherNet/IP Scanner - Planning)

### Context
Starting development of click_enip_scanner.py to read CLICK PLC data via EtherNet/IP CIP Explicit Messaging.

### Decisions Made

| Decision | Rationale |
|----------|-----------|
| Use pycomm3 instead of CPPPO | CPPPO read() fails with "Service not supported" on CLICK |
| CIP-only (no Modbus) | Keep scanner focused on single protocol |
| Multi-format data display | Assembly data configuration unknown at scan time |
| No CSV output for ENIP | Assembly data format not suitable for tabular CSV |
| Support connections 1 and 2 | CLICK supports 2 EtherNet/IP adapter connections |

### CLICK EtherNet/IP Limitations Discovered
- Maximum 2 concurrent connections
- Acts as Adapter only (responds, does not initiate)
- Does NOT support Tag-Based (Symbolic) messaging
- Does NOT support PCCC
- Minimum RPI: 10ms

### CIP Addressing for CLICK
```
Identity Object:     Class 0x01, Instance 1
Assembly Object:     Class 0x04, Instance 101/102 (Conn 1) or 103/104 (Conn 2)
TCP/IP Interface:    Class 0xF5, Instance 1
Ethernet Link:       Class 0xF6, Instance 1
```

---

## Session: 2026-01-05 (EtherNet/IP Scanner - Phase 1 Foundation)

### Context
Testing EtherNet/IP libraries and establishing basic connectivity to CLICK PLC.

### Library Evaluation

**CPPPO 5.2.5:**
- `list_identity()`: SUCCESS - Returns device info
- `read()` with `attribute_operations()`: FAIL - "Service not supported" (Status 0x08)
- Tested with `-S` flag for simple devices: Still fails
- Conclusion: CPPPO uses Read Tag service instead of Get Attribute Single

**pycomm3:**
- `CIPDriver.generic_message()`: SUCCESS for all operations
- Get Attribute Single (service 0x0E) works correctly
- No special flags needed for CLICK
- Clean context manager pattern

### Decisions Made

| Decision | Rationale |
|----------|-----------|
| Use pycomm3 CIPDriver | generic_message() works for all CIP objects |
| Service 0x0E (Get Attribute Single) | Standard CIP service that CLICK supports |
| Default port 44818 | Standard EtherNet/IP port |
| Default timeout 5 seconds | Consistent with Modbus scanner |

### Test Results Against Real PLC (192.168.0.10:44818)

| CIP Object | Result |
|------------|--------|
| Identity (0x01) attributes 1-7 | SUCCESS |
| TCP/IP Interface (0xF5) attribute 5 | SUCCESS |
| Ethernet Link (0xF6) attributes 1-3 | SUCCESS |
| Assembly (0x04) Instance 101 | SUCCESS - 432 bytes |
| Assembly (0x04) Instance 103 | "Object does not exist" (not configured) |

### Technical Notes
- IP addresses in TCP/IP Interface use little-endian byte order
- Assembly returns actual configured size, not requested size
- Unconfigured connections return graceful error message

---

## Session: 2026-01-05 (EtherNet/IP Scanner - Phase 2-3 Device Info and Data)

### Context
Implementing device identity, network info, and assembly data retrieval with multi-format interpretation.

### Decisions Made

| Decision | Rationale |
|----------|-----------|
| Multi-format display (INT16/INT32/FLOAT/HEX) | Configuration unknown at scan time |
| Show all interpretations | User can identify correct format from data patterns |
| Size mismatch as warning, not error | Expected behavior when --size differs from actual |
| --hex flag for legacy output | Some users prefer hex-only dump |

### Data Interpretation Functions
```python
interpret_as_int16()   # DS registers
interpret_as_uint16()  # Unsigned variant
interpret_as_int32()   # DD registers
interpret_as_float()   # DF registers (IEEE 754)
interpret_as_ascii()   # Text data
```

### Test Results
- Identity Object: All 7 attributes readable
- Network Info: IP, subnet, gateway, hostname, MAC, link speed
- Assembly Data: 432 bytes from Connection 1 (DS1-DS72 + DD3-DD74)
- Multi-format display: Correct alignment and formatting

### Lessons Learned
1. Always display size mismatch as informational, not error
2. Include data summary (total INT16/INT32/FLOAT values)
3. Note that DS registers are INT16, DD registers are INT32/FLOAT

---

## Session: 2026-01-05 (EtherNet/IP Scanner - Phase 4 Scope Change)

### Context
Original Phase 4 planned hybrid ENIP+Modbus --sysconfig feature. User clarified ENIP scanner should be CIP-only.

### Scope Change

**Removed:**
- --sysconfig option (required Modbus for SD/SC registers)
- pymodbus dependency for ENIP scanner
- Hybrid protocol mixing

**Added:**
- --full option (combines --info + --network + assembly data)

### Rationale
- ENIP scanner should use EtherNet/IP CIP protocol only
- SD/SC register data (EIP status) only accessible via Modbus
- Network/device info already available via CIP objects
- Keep each scanner focused on single protocol

### Decisions Made

| Decision | Rationale |
|----------|-----------|
| Remove Phase 4 (System Config) | Hybrid ENIP+Modbus out of scope |
| Add --full option | Comprehensive view via CIP only |
| Mutually exclusive --info/--network/--full | Cleaner CLI, prevents confusion |
| Renumber phases 5->4, 6->5 | Maintain sequential numbering |

---

## Session: 2026-01-05 (EtherNet/IP Scanner - Phase 4 Output and CLI)

### Context
Implementing Markdown output and CLI polish for ENIP scanner.

### Markdown Report Structure
```
# CLICK PLC EtherNet/IP Scan Report
| Parameter | Value |
| Target | host:port |
| Date | timestamp |
| Scanner | version |

## Device Identity (table)
## Network Information (table)
## Assembly Data - Connection N
### Hex Dump (code block)
### INT16 Interpretation (code block)
### INT32 Interpretation (code block)
### FLOAT Interpretation (code block)
### Data Summary
```

### Decisions Made

| Decision | Rationale |
|----------|-----------|
| .md extension required | Explicit format selection, avoid accidents |
| Scanner version in report | Traceability for support |
| All formats in Markdown | Same comprehensive view as console |
| argparse mutually exclusive group | Enforced at CLI level |

### Test Results
- --full --output report.md: SUCCESS
- Mutually exclusive group: Enforced correctly
- Extension validation: Rejects non-.md files

---

## Session: 2026-01-05 (EtherNet/IP Scanner - Phase 5 Polish)

### Context
Implementing error handling, documentation, and final testing.

### CIP Error Code Implementation

**General Status Codes (14 codes):**
```python
CIP_GENERAL_STATUS = {
    0x00: ("Success", "Operation completed successfully"),
    0x05: ("Path Destination Error", "Object Class, Instance, or Attribute not supported"),
    0x08: ("Service Not Supported", "Requested service not implemented"),
    0x16: ("Object Does Not Exist", "Specified object does not exist"),
    # ... etc
}
```

**Extended Status Codes (19 codes for status 0x01):**
```python
CIP_EXTENDED_STATUS_0x01 = {
    0x0100: ("Connection In Use", "Connection already established"),
    0x0106: ("Owner Conflict", "Exclusive owner already configured"),
    # ... etc
}
```

**Troubleshooting Hints:**
```python
CIP_TROUBLESHOOTING = {
    0x16: "The assembly instance may not be configured. Check EtherNet/IP setup in CLICK software.",
}
```

### Error Handler Functions
- `parse_cip_error()` - Parse error string, return (name, description, hint)
- `format_cip_error()` - Format for user display
- `handle_connection_error()` - Connection-specific messages with troubleshooting

### Documentation Updates
- README.md: Added ENIP scanner section with both scripts
- USAGE.md: Added comprehensive ENIP documentation
  - Basic usage and quick start
  - CLI options reference
  - Output modes
  - Examples
  - Troubleshooting section
  - CIP Protocol Reference

### Final Test Results

| Test | Result |
|------|--------|
| --info | SUCCESS |
| --network | SUCCESS |
| --hex | SUCCESS |
| --full | SUCCESS |
| --connection 2 (unconfigured) | "Object Does Not Exist" with hint |
| Non-existent host | Helpful troubleshooting message |
| Invalid port | Validation error |

### Lessons Learned
1. User-friendly error messages significantly improve usability
2. Include troubleshooting hints inline with errors
3. Document CIP error codes from vendor documentation

---

## Failed Approaches

### CPPPO for CLICK PLCs (2026-01-05)
**What:** Initial plan to use CPPPO library for EtherNet/IP CIP communication.

**Why it failed:** CPPPO's `read()` function returns "Service not supported" (Status 0x08) for CLICK PLCs. CPPPO appears to use Read Tag service instead of Get Attribute Single, which CLICK does not support.

**Symptom:** `list_identity()` works, but all attribute reads fail with status 0x08.

**Resolution:** Switched to pycomm3 CIPDriver with `generic_message()` using service 0x0E (Get Attribute Single).

### Hybrid ENIP+Modbus --sysconfig (2026-01-05)
**What:** Planned feature to read EIP status from SD/SC Modbus registers while using ENIP.

**Why it failed:** User clarified that ENIP scanner should use EtherNet/IP CIP only, no Modbus.

**Symptom:** Scope creep - mixing protocols defeats purpose of separate scanners.

**Resolution:** Removed --sysconfig, added --full option for comprehensive CIP-only view.

### Big-Endian Word Order Assumption (Fixed 2026-01-05)
**What:** Initial implementation assumed CLICK PLC used big-endian word order (high word first) for 32-bit values based on common Modbus convention.

**Why it failed:** CLICK PLC actually uses little-endian word order (low word first). This is documented in MathWorks guide and confirmed by comparing raw register values with expected data.

**Symptom:** DD11 showing 1,520,435,250 instead of 3,300,000; DF values showing nonsense like -7.99e-25.

**Resolution:** Swapped word order in convert_to_int32(), convert_to_float(), convert_to_hex(), and raw_value calculations.

---

## Successful Techniques

### pycomm3 generic_message() for CIP
Using `CIPDriver.generic_message()` with explicit service code provides maximum control:
```python
result = plc.generic_message(
    service=0x0E,           # Get Attribute Single
    class_code=0x04,        # Assembly Object
    instance=101,           # Connection 1 Input
    attribute=0x03,         # Data attribute
)
```
This works reliably for CLICK PLCs where higher-level APIs fail.

### Multi-Format Data Display
When assembly configuration is unknown, showing all interpretations (INT16, INT32, FLOAT, HEX) lets users identify correct format from data patterns. Values that make sense (e.g., 3,300,000 vs 1.5e9) indicate correct interpretation.

### Inline Troubleshooting Hints
Including hints with error messages reduces support burden:
```
Object Does Not Exist: The specified CIP object does not exist in the device
  Hint: The assembly instance may not be configured. Check EtherNet/IP setup in CLICK software.
```

### Mutually Exclusive argparse Groups
Using `add_mutually_exclusive_group()` enforces option conflicts at CLI level, preventing invalid combinations before code runs.

---

## Reference Commands

### Export CSV from CLICK Software
(To be documented after testing)

### Test Connection
```bash
# Quick test with nc (netcat) - Modbus
nc -zv 192.168.0.10 502

# Quick test with nc (netcat) - EtherNet/IP
nc -zv 192.168.0.10 44818
```

### Run Modbus Scanner
```bash
# Basic usage - scan common types (X0, Y0, C, DS, DD, DF)
python click_mb_scanner.py 192.168.0.10

# Specific types
python click_mb_scanner.py 192.168.0.10 --type DS,DF

# Full scan - all 32 address types
python click_mb_scanner.py 192.168.0.10 --full

# Use CLICK CSV config file (filters addresses, adds nicknames)
python click_mb_scanner.py 192.168.0.10 --config project_export.csv

# Output to CSV file
python click_mb_scanner.py 192.168.0.10 --type X0 --output scan_results.csv

# Output to Markdown file
python click_mb_scanner.py 192.168.0.10 --type X0,DS --output scan_results.md

# Show 984 format addresses
python click_mb_scanner.py 192.168.0.10 --type DS --format 984

# List available address types
python click_mb_scanner.py 192.168.0.10 --list

# Slow rate for sensitive environments
python click_mb_scanner.py 192.168.0.10 --rate slow

# Combine config with output file
python click_mb_scanner.py 192.168.0.10 --config project.csv --output results.md
```

### Run EtherNet/IP Scanner
```bash
# Read device identity
python click_enip_scanner.py 192.168.0.10 --info

# Read network configuration
python click_enip_scanner.py 192.168.0.10 --network

# Read assembly data (default - includes identity header)
python click_enip_scanner.py 192.168.0.10

# Full scan with all information
python click_enip_scanner.py 192.168.0.10 --full

# Hex-only output (no multi-format interpretation)
python click_enip_scanner.py 192.168.0.10 --hex

# Read Connection 2 assembly (if configured)
python click_enip_scanner.py 192.168.0.10 --connection 2

# Save to Markdown report
python click_enip_scanner.py 192.168.0.10 --full --output report.md

# Extended timeout for slow networks
python click_enip_scanner.py 192.168.0.10 --timeout 15 --full
```

---

## Session: 2026-01-06 (NSE Script - Phase 3 ENIP UDP)

### Context
Implementing EtherNet/IP List Identity over UDP and testing PLC RUN/STOP mode detection.

### Implementation Details

**Function Implemented:**
- `enip_scan_udp(host, port)` - UDP socket handling with try/catch pattern

**Key Differences from TCP:**
```lua
-- TCP socket creation
socket = nmap.new_socket()

-- UDP socket creation
socket = nmap.new_socket("udp")
```

**Action Function Update:**
- Added `is_udp` check: `use_udp or (port.protocol == "udp")`
- Routes to `enip_scan_udp()` when UDP flag set or port scanned via -sU

### Test Results

**UDP Scan (--script-args='click-plc-info.udp=true'):**
- Successfully sends/receives via UDP even when port scanned as TCP
- Response identical to TCP (80 bytes, same parsed values)
- Debug output confirms UDP code path execution

**RUN vs STOP Mode Testing:**

User switched PLC between RUN and STOP modes via hardware switch.

| Field | RUN Mode | STOP Mode | Changed? |
|-------|----------|-----------|----------|
| Vendor | 482 | 482 | No |
| Device Type | 43 | 43 | No |
| Product Name | CLICK C2-03CPU-2 | CLICK C2-03CPU-2 | No |
| Serial Number | 0x35bf2b44 | 0x35bf2b44 | No |
| Product Code | 634 | 634 | No |
| Revision | 1.1 | 1.1 | No |
| **Status** | **0x0030** | **0x0030** | **No** |
| **State** | **0xff** | **0xff** | **No** |
| Device IP | 192.168.0.10 | 192.168.0.10 | No |

### Key Finding: ENIP Does Not Expose PLC Mode

The EtherNet/IP List Identity response Status and State fields do **not** change when the CLICK PLC switches between RUN and STOP modes.

**Additional Testing: CIP Get_Attribute_Single**

Based on user research suggesting Identity Object Status (Class 0x01, Attribute 0x05) should expose RUN/STOP mode, tested with pycomm3:

```python
result = plc.generic_message(
    service=0x0E,       # Get Attribute Single
    class_code=0x01,    # Identity Object
    instance=0x01,
    attribute=0x05,     # Status attribute
)
```

| Mode | Status | Bits 4-7 | CIP Interpretation |
|------|--------|----------|-------------------|
| RUN | 0x0030 | 3 | "Operational" |
| STOP | 0x0030 | 3 | "Operational" |

**Result:** CIP explicit messaging to Identity Object Status also does NOT change between RUN/STOP modes. The "Operational" state (bits 4-7 = 3) refers to the EtherNet/IP adapter being operational, not PLC program execution.

**Implications:**
1. Cannot determine PLC operating mode via ENIP List Identity
2. Cannot determine PLC operating mode via CIP Get_Attribute_Single on Identity Object
3. Must use Modbus SD registers to read PLC mode (Phase 5)
4. Status 0x0030 indicates EtherNet/IP adapter is operational
5. State 0xff in List Identity appears to be CLICK-specific (typical CIP: 0x00-0x03)
6. Alternative (SC1/SC2 mapped to ENIP I/O) requires pre-configuration, not usable for scanner

### Decisions Made

| Decision | Rationale |
|----------|-----------|
| Check both use_udp flag and port.protocol | Handles both explicit flag and nmap -sU scans |
| Reuse parse_enip_response() for UDP | Same packet format regardless of transport |
| Document RUN/STOP finding | Important for users expecting mode detection |

### Lessons Learned

1. **ENIP List Identity is transport-agnostic**
   - Same 24-byte request works for TCP and UDP
   - Same response parsing for both transports

2. **CIP Status/State fields vary by vendor**
   - CLICK uses State 0xff (non-standard)
   - Status 0x0030 does not reflect operating mode
   - Vendor-specific behavior should be documented

3. **Hardware testing reveals protocol limitations**
   - Without RUN/STOP test, we might have assumed Status reflected mode
   - Real hardware testing is essential for accurate documentation

---

## Session: 2026-01-05 (NSE Script - Phase 2 ENIP TCP)

### Context
Implementing EtherNet/IP List Identity request/response over TCP for click-plc-info.nse.

### Implementation Details

**Functions Implemented:**
- `vendor_lookup(vennum)` - Returns vendor name from ID or "Unknown Vendor"
- `device_type_lookup(devtype)` - Returns device type from ID or "Unknown Device Type"
- `form_enip_list_identity()` - Returns 24-byte List Identity packet (hex: 63000000...)
- `parse_enip_response(response)` - Parses full response, returns output table
- `enip_scan_tcp(host, port)` - Socket handling with try/catch pattern

**Response Parsing (parse_enip_response):**
- Validates minimum length (27 bytes for header, 63+ for full parse)
- Validates command byte == 0x63 (List Identity)
- Validates type ID byte == 0x0C (Identity item)
- Parses fields using string.unpack() with little-endian format
- Uses ipOps.fromdword() for IP address conversion

**Field Offsets (1-indexed for Lua):**
| Field | Offset | Format | Size |
|-------|--------|--------|------|
| Command | 1 | B | 1 byte |
| Type ID | 27 | B | 1 byte |
| Device IP | 37 | >I4 (big-endian) | 4 bytes |
| Vendor ID | 49 | <I2 (little-endian) | 2 bytes |
| Device Type | 51 | <I2 | 2 bytes |
| Product Code | 53 | <I2 | 2 bytes |
| Revision | 55 | BB | 2 bytes |
| Status | 57 | <I2 | 2 bytes |
| Serial Number | 59 | <I4 | 4 bytes |
| Product Name | 63 | s1 (length-prefixed) | variable |
| State | after name | B | 1 byte |

### Test Results Against Real PLC (192.168.0.10:44818)

| Field | Value |
|-------|-------|
| Vendor | Koyo Electronics (AutomationDirect) (482) |
| Device Type | Generic Device (keyable) (43) |
| Product Name | CLICK C2-03CPU-2 |
| Serial Number | 0x35bf2b44 |
| Product Code | 634 |
| Revision | 1.1 |
| Status | 0x0030 |
| State | 0xff |
| Device IP | 192.168.0.10 |

### Decisions Made

| Decision | Rationale |
|----------|-----------|
| Use try/catch pattern from enip-info.nse | Ensures socket cleanup on errors |
| Set port.version.name on success | Updates nmap service detection |
| Return nil on parse failure | Standard NSE pattern for no results |
| Use stdnse.debug1() for debug output | Nmap standard for script debugging |

### Observations

1. **CLICK uses Vendor ID 482 (Koyo), not 898**
   - Koyo Electronics is AutomationDirect's PLC brand
   - Good decision to include both in vendor table

2. **Device Type is 43 (Generic Device keyable)**
   - Not 14 (PLC) as might be expected
   - Added type 43 to device_type table in Phase 1

3. **State value is 0xff**
   - Different from typical 0x03 seen in enip-info.nse examples
   - May be CLICK-specific

---

## Session: 2026-01-05 (NSE Script - Phase 1 Script Skeleton)

### Context
Creating the NSE script skeleton for click-plc-info.nse with standard headers, portrule, arguments, and action stub.

### Decisions Made

| Decision | Rationale |
|----------|-----------|
| Include both vendor IDs 898 and 482 | 898 = AutomationDirect official, 482 = Koyo Electronics (AutomationDirect brand) |
| Categories: discovery, version | Read-only script, not intrusive |
| Port-based routing in action() | Simple dispatch based on port 502 vs 44818 |
| Placeholder output during development | Allows testing script loading before protocol implementation |
| Minimal vendor/device tables | Only include common PLC vendors, not exhaustive list |

### Implementation Details

**Script Structure:**
- Headers: description, usage, output examples, author, license, categories
- Requirements: comm, nmap, shortport, stdnse, string, table
- Portrule: shortport.port_or_service({502, 44818}, {"modbus", "EtherNet-IP-2"}, {"tcp", "udp"})
- Lookup tables: vendor_id (7 entries), device_type (7 entries), modbus_exception (10 entries)
- Action: argument parsing, port-based routing, placeholder output

**Script Arguments (6 total):**
- modbus-only: Skip ENIP scan
- enip-only: Skip Modbus scan
- unit-id: Modbus Unit ID (default 0)
- coil-count: X/Y coil count (default 10)
- reg-count: DS/DD register count (default 10)
- udp: Use UDP for ENIP (default false)

### Reference Scripts Reviewed

**modbus-discover.nse:**
- Uses comm.exchange() for simple request/response
- form_rsid() builds MBAP + PDU frame
- modbus_exception_codes table for error messages
- Iterates through slave IDs (1-246)

**enip-info.nse:**
- Extensive vendor_id table (1500+ entries)
- List Identity query as hex string
- string.unpack() for response parsing
- nmap.new_socket() with explicit timeout

### Lessons Learned

1. **NSE Script Categories Matter**
   - "intrusive" category for scripts that may affect device state
   - "discovery, version" for read-only information gathering
   - CLICK script is read-only, so "discovery, version" is appropriate

2. **Vendor ID Tables Can Vary**
   - enip-info.nse lists 482 as "Koyo Electronics"
   - Koyo is AutomationDirect's PLC brand
   - Include both 898 (official) and 482 (Koyo) for compatibility

3. **Placeholder Pattern for Incremental Development**
   - Return stdnse.output_table() with status message
   - Allows testing script loading before full implementation
   - Clear TODO markers for unimplemented sections

---

## Session: 2026-01-06 (NSE Script - Phase 5 Modbus Device Info)

### Context
Implementing the modbus_scan() function to read device information from SD registers and basic I/O data from X/Y coils and DS/DD registers.

### Implementation Details

**Main Function:**
```lua
local function modbus_scan(host, port, unit_id, coil_count, reg_count)
    -- SD Register addresses (base 0xF000)
    local SD_FIRMWARE = 0xF004   -- SD5-SD8
    local SD_IP = 0xF04F         -- SD80-SD83
    local SD_SUBNET = 0xF053     -- SD84-SD87
    local SD_GATEWAY = 0xF057    -- SD88-SD91
    local SD_EIP_STATUS = 0xF064 -- SD101-SD102
    local SD_MAC = 0xF0BB        -- SD188-SD193

    -- I/O addresses
    local X_BASE = 0x0000        -- X inputs (FC 02)
    local Y_BASE = 0x2000        -- Y outputs (FC 01)
    local DS_BASE = 0x0000       -- DS registers (FC 03)
    local DD_BASE = 0x4000       -- DD registers (FC 03)
    ...
end
```

**Key Code Changes:**
1. Moved data conversion functions (bytes_to_int16, bytes_to_int32, format_ip, format_mac, format_firmware) BEFORE modbus_scan() - Lua requires functions to be declared before use
2. Added got_data and got_device_info flags to track success - stdnse.output_table() doesn't work with next() for iteration
3. IP/Subnet/Gateway stored as 4 registers, one byte per register's low byte
4. MAC stored as 6 registers, one byte per register's low byte

### Test Results Against Real PLC (192.168.0.10)

**Port 502 (Modbus):**
| Field | Value |
|-------|-------|
| Firmware | 3.41 |
| IP Address | 192.168.0.10 |
| Subnet Mask | 255.255.255.0 |
| Gateway | 0.0.0.0 |
| MAC Address | 00:D0:7C:1A:42:44 |
| EIP Enabled | No (Status: 0x0000) |
| X Inputs | 0 0 0 0 0 0 0 0 0 0 |
| Y Outputs | 0 1 1 1 0 0 0 0 0 0 |
| DS Registers | 0, 0, 422, 0, 5, 252, 30, 0, 0, 0 |
| DD Registers | 0, 0, 422400000, 117333, 0, 0, 0, 0, 0, 0 |

**Port 44818 (ENIP):**
| Field | Value |
|-------|-------|
| Vendor | Koyo Electronics (AutomationDirect) (482) |
| Product Name | CLICK C2-03CPU-2 |
| Revision | 1.1 |

### Firmware Version Format (Corrected)

**Observation:** SD5-SD6 returns raw bytes `00 29 00 03`:
- SD5 = 0x0029 = 41 (minor version)
- SD6 = 0x0003 = 3 (major version)

**Correct Interpretation:**
- Firmware version = major.minor = SD6.SD5 = 3.41
- CLICK stores minor version in SD5, major version in SD6
- Only 2 registers needed (SD5-SD6), not 4

**ENIP Revision Clarification:**
- ENIP List Identity "Revision: 1.1" is the ENIP protocol version
- This is NOT the PLC firmware version
- PLC firmware must be read via Modbus SD registers

### Decisions Made

| Decision | Rationale |
|----------|-----------|
| Use explicit flags instead of next() | stdnse.output_table() doesn't iterate with next() |
| Move conversion functions before scan | Lua requires declaration before use |
| IP/MAC as separate registers | CLICK stores network info as individual bytes in register low bytes |
| Keep firmware display despite uncertainty | Better to show something than nothing; can be refined |

### Lessons Learned

1. **stdnse.output_table() is not a regular table**
   - Cannot use `next(output_table)` to check for content
   - Must track success with explicit boolean flags

2. **Lua function ordering matters**
   - Local functions must be declared before they're called
   - Reorganize code to ensure dependencies are met

3. **SD Register format may vary by model**
   - Documentation may not match actual register layout
   - Compare with ENIP data when possible
   - Raw hex dump useful for debugging

4. **CLICK stores network info unusually**
   - IP/Subnet/Gateway use 4 registers with one byte each in low position
   - MAC uses 6 registers similarly
   - Extract with string.byte(data, offset) for low byte

5. **CLICK firmware version format**
   - SD5 = minor version, SD6 = major version
   - Display as major.minor (e.g., 3.41)
   - ENIP Revision field is ENIP protocol version, not PLC firmware

---

## Session: 2026-01-06 (NSE Script - Phase 4 Modbus Helpers)

### Context
Implementing Modbus TCP helper functions for the NSE script to enable communication with CLICK PLCs.

### Implementation Details

**Core Functions Implemented:**

1. **form_modbus_request(uid, fc, addr, qty)**
   - Builds MBAP header (7 bytes) + PDU
   - Uses string.pack() with big-endian format (>I2)
   - Maintains transaction_id counter for request tracking

```lua
local function form_modbus_request(uid, fc, addr, qty)
    transaction_id = (transaction_id + 1) % 65536
    local pdu_length = 6
    local packet = string.pack(">I2 >I2 >I2 B B >I2 >I2",
        transaction_id, 0x0000, pdu_length, uid, fc, addr, qty)
    return packet
end
```

2. **parse_modbus_response(response, expected_fc)**
   - Validates response length (minimum 9 bytes)
   - Detects exception responses (FC + 0x80)
   - Returns data bytes or nil + error message

3. **Read Wrapper Functions**
   - read_coils(socket, uid, addr, qty) - FC 01
   - read_discrete_inputs(socket, uid, addr, qty) - FC 02
   - read_holding_registers(socket, uid, addr, qty) - FC 03
   - read_input_registers(socket, uid, addr, qty) - FC 04

4. **Data Conversion Functions**
   - bytes_to_int16(b1, b2) - Signed 16-bit with overflow handling
   - bytes_to_int32(b1, b2, b3, b4) - Signed 32-bit, little-endian word order
   - format_ip(b1, b2, b3, b4) - IP address string formatting
   - format_mac(b1, b2, b3, b4, b5, b6) - MAC address string formatting
   - format_firmware(b1, b2, b3, b4) - Version string from 4 bytes

### Test Results Against Real PLC (192.168.0.10:502)

| Function Code | Target | Result |
|---------------|--------|--------|
| FC 01 (Read Coils) | Y001-Y010 | 0 1 1 1 0 0 0 0 0 0 |
| FC 02 (Read Discrete Inputs) | X001-X010 | 0 0 0 0 0 0 0 0 0 0 |
| FC 03 (Read Holding Registers) | DS1-DS10 | 0, 0, 422, 0, 6, 252, 30, 0, 0, 0 |
| FC 04 (Read Input Registers) | - | Functional |

### Technical Notes

1. **MBAP Header Format**
   ```
   Transaction ID: 2 bytes (big-endian, incremented per request)
   Protocol ID: 2 bytes (0x0000 for Modbus)
   Length: 2 bytes (remaining bytes including Unit ID)
   Unit ID: 1 byte
   ```

2. **Exception Detection**
   - Exception response: Function Code = expected_fc + 0x80
   - Exception code in byte 9 of response
   - Lookup via modbus_exception table

3. **Signed Integer Conversion**
   - INT16: Values >= 32768 become negative (val - 65536)
   - INT32: Values >= 2147483648 become negative (val - 4294967296)

4. **Word Order for 32-bit Values**
   - CLICK uses little-endian word order: low word at lower address
   - Reassemble: (high_word * 65536) + low_word

### Decisions Made

| Decision | Rationale |
|----------|-----------|
| Global transaction_id counter | Simple, sufficient for single-threaded NSE execution |
| Return nil + error on parse failure | Standard Lua pattern for error handling |
| Separate read functions per FC | Cleaner API, matches Modbus specification |
| Validate response length first | Prevents string.unpack errors on truncated responses |

### Lessons Learned

1. **string.pack/unpack Format Specifiers**
   - `>I2` = big-endian unsigned 16-bit
   - `<I2` = little-endian unsigned 16-bit
   - `B` = unsigned byte
   - Spacing optional but improves readability

2. **Modbus Exception Handling**
   - Exception code 0x02 (Illegal Data Address) common for invalid ranges
   - Exception code 0x03 (Illegal Data Value) for out-of-bounds counts
   - Always check FC in response matches expected before parsing data

3. **Testing with Temporary action() Code**
   - Temporary test code in action() useful for validation
   - Remove before production release
   - Keep test output informative but concise

---

## Session: 2026-01-06 (NSE Script - Phase 6 Integration and Polish)

### Context
Final phase of NSE script development: argument validation, documentation updates, and final testing.

### Implementation Details

**Argument Validation Added:**
```lua
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
```

**Documentation Updates:**
- README.md: Added NSE Script section with features, quick start, arguments, and example output
- USAGE.md: Added comprehensive NSE section with installation, arguments, output format, examples, and troubleshooting

### Final Test Results

**Dual-Port Scan (502 + 44818):**
```
PORT      STATE SERVICE
502/tcp   open  modbus
| click-plc-info:
|   Device Information:
|     Firmware: 3.41
|     IP Address: 192.168.0.10
|     MAC Address: 00:D0:7C:1A:42:44
|   Inputs (X001-X010): 0 0 0 0 0 0 0 0 0 0
|   Outputs (Y001-Y010): 0 1 1 1 0 0 0 0 0 0
|   DS Registers (DS1-DS10): 0, 0, 422, 0, 5, 252, 30, 0, 0, 0
|_  DD Registers (DD1-DD10): 0, 0, 422400000, 117333, 0, 0, 0, 0, 0, 0
44818/tcp open  EtherNet-IP-2
| click-plc-info:
|   Vendor: Koyo Electronics (AutomationDirect) (482)
|   Product Name: CLICK C2-03CPU-2
|_  Device IP: 192.168.0.10
```

**Custom Arguments Test:**
- `--script-args='click-plc-info.coil-count=20,click-plc-info.reg-count=5'`: Correctly shows X001-X020, Y001-Y020, DS1-DS5, DD1-DD5
- `--script-args='click-plc-info.modbus-only=true'`: Skips ENIP output
- `--script-args='click-plc-info.coil-count=200,click-plc-info.unit-id=255'`: Validated and clamped with debug messages

### Decisions Made

| Decision | Rationale |
|----------|-----------|
| Clamp values instead of rejecting | User-friendly, script continues to work |
| Log validation issues to debug | Visible with -d flag, doesn't clutter normal output |
| Comprehensive USAGE.md | Single reference for all scanner tools |

### Lessons Learned

1. **Argument validation prevents unexpected behavior**
   - Invalid coil-count could cause Modbus exceptions
   - Invalid unit-id could prevent communication
   - Clamping with debug logging is user-friendly

2. **Documentation should be comprehensive**
   - Include installation instructions
   - Document all arguments with defaults and ranges
   - Provide troubleshooting section for common issues

3. **Test all argument combinations**
   - Valid arguments
   - Invalid arguments (out of range)
   - Combined arguments
   - Protocol-specific flags (modbus-only, enip-only)

### Project Completion

All three scanning tools are now complete:

| Tool | Protocol | Status |
|------|----------|--------|
| click_mb_scanner.py | Modbus TCP | COMPLETE |
| click_enip_scanner.py | EtherNet/IP CIP | COMPLETE |
| click-plc-info.nse | Modbus + ENIP | COMPLETE |

---

## Session: 2026-01-08 (Metasploit Modules - Phase 9.1 modbus_click.rb)

### Context
Developing custom Metasploit Framework auxiliary scanner module for CLICK PLC Modbus scanning.

### Decisions Made

| Decision | Rationale |
|----------|-----------|
| Read-only operations only | Safety in ICS environments |
| CLICK-specific address mappings | X0, Y0, C, DS, DD, DF, SD address types |
| Little-endian word order for 32-bit | Matches CLICK PLC behavior (confirmed in Python scanner) |
| Actions-based design | READ_INPUTS, READ_OUTPUTS, READ_DEVICE_INFO, etc. |
| Database reporting with report_note() | Consistent with MSF modbus_banner_grabbing.rb pattern |

### Issues Encountered and Resolved

| Issue | Resolution |
|-------|------------|
| Firmware version displayed as 41.3 instead of 3.41 | SD5=minor, SD6=major; swapped in format_firmware_from_registers() |
| FLOAT conversion byte order concern | Verified Ruby pack('L').unpack('F') works (symmetric native byte order), but updated to explicit big-endian pack('nn').unpack('g') for clarity and consistency with Python |

### Technical Notes

**CLICK Address Type Mappings:**
```ruby
CLICK_ADDRESSES = {
  'X0' => { fc: 2, start: 0x0000, count: 36, type: :bool },
  'Y0' => { fc: 1, start: 0x2000, count: 36, type: :bool },
  'DS' => { fc: 3, start: 0x0000, count: 100, type: :int16 },
  'DD' => { fc: 3, start: 0x4000, count: 50, type: :int32 },
  'DF' => { fc: 3, start: 0x6000, count: 50, type: :float },
  # ... etc
}
```

**SD Device Info Registers:**
- SD5-SD6 (0xF004): Firmware version (minor.major)
- SD80-SD83 (0xF04F): IP Address
- SD84-SD87 (0xF053): Subnet Mask
- SD88-SD91 (0xF057): Gateway
- SD188-SD193 (0xF0BB): MAC Address

### Lessons Learned

1. **Byte order documentation is critical**
   - CLICK uses little-endian word order for 32-bit values
   - Firmware version bytes are swapped (minor first, then major)
   - Document in module description for troubleshooting

2. **MSF module patterns from existing SCADA modules**
   - modbus_banner_grabbing.rb for database reporting
   - modbusclient.rb for Modbus frame building
   - Use Actions array for multiple operations

3. **Test with real hardware early**
   - Firmware version issue only discovered during testing
   - Compare output with Python scanner for validation

---

## Session: 2026-01-08 (Metasploit Modules - Phase 9.2 enip_scanner.rb)

### Context
Developing generic EtherNet/IP scanner module for device identity enumeration.

### Decisions Made

| Decision | Rationale |
|----------|-----------|
| Generic scanner (not CLICK-specific) | Works with any ENIP device |
| Vendor ID table from Nmap enip-info.nse | 1500+ vendors, authoritative source |
| TCP and UDP transport support | UDP faster for discovery |
| List Identity command (0x0063) | No session required, widely supported |
| Device type lookup table | Meaningful device categorization |

### Implementation Details

**ENIP List Identity Packet (24 bytes):**
```ruby
def build_list_identity_request
  # Command (2) + Length (2) + Session (4) + Status (4) + Context (8) + Options (4)
  header = [0x0063, 0, 0, 0].pack('vvVV')
  header += "\x00" * 8  # Sender Context
  header += [0].pack('V')  # Options
  header
end
```

**Identity Response Parsing:**
- CPF Item Type 0x000C = Identity Item
- Vendor ID at offset 18 (little-endian)
- Device Type at offset 20
- Product Name at offset 33 (length-prefixed string)
- Device IP from socket address at offset 6

### Technical Notes

**Vendor ID Table Size:**
- 1500+ vendors imported from Nmap
- Includes Koyo Electronics (482) = AutomationDirect
- Fallback: "Unknown Vendor (ID)"

**Device Type Table:**
- 40+ device types from ODVA specification
- Type 14 = PLC, Type 43 = Generic Device (CLICK uses 43)
- Fallback: "Unknown Device Type (ID)"

### Lessons Learned

1. **Nmap scripts are authoritative source for ICS protocol data**
   - enip-info.nse has most comprehensive vendor list
   - Device type table from Wireshark dissector

2. **ENIP List Identity is session-less**
   - No Register Session required
   - Same packet works for TCP and UDP
   - Simplest ENIP operation for device discovery

3. **Socket address in response contains device IP**
   - Useful for devices behind NAT
   - sin_addr at offset 6 of identity item

---

## Session: 2026-01-08 (Metasploit Modules - Phase 9.3 enip_bruteforce.rb)

### Context
Developing CIP object enumeration module for discovering supported classes, instances, and attributes on EtherNet/IP devices.

### Decisions Made

| Decision | Rationale |
|----------|-----------|
| Prominent safety warning | Module can impact device performance |
| KNOWN_OBJECTS as default action | Safest option, only scans documented classes |
| Configurable rate limiting | DELAY option (default 100ms) prevents overload |
| CIP session management | Required for Send RR Data command |
| 40+ CIP status codes | Comprehensive error handling |

### Implementation Details

**CIP Session Management:**
```ruby
def register_session
  # Register Session: command 0x0065, protocol version 1
  data = [1, 0].pack('vv')
  packet = build_enip_header(ENIP_CMD_REGISTER_SESSION, data.length, 0) + data
  # Parse session handle from response
end
```

**CIP Path Building:**
```ruby
def build_cip_path(class_id, instance_id, attribute_id = nil)
  path = ''
  # Class segment: 0x20 (8-bit) or 0x21 (16-bit)
  # Instance segment: 0x24 (8-bit) or 0x25 (16-bit)
  # Attribute segment: 0x30 (8-bit) or 0x31 (16-bit)
end
```

**Known CIP Classes:**
| Class | Name | Instances | Key Attributes |
|-------|------|-----------|----------------|
| 0x01 | Identity | 1 | Vendor ID, Device Type, Serial |
| 0x02 | Message Router | 1 | Object List |
| 0x04 | Assembly | 100-105, 150-151 | Data |
| 0x06 | Connection Manager | 1 | Open Requests |
| 0xF4 | Port | 1-4 | Port Type, Number |
| 0xF5 | TCP/IP Interface | 1 | Config, Hostname |
| 0xF6 | Ethernet Link | 1-4 | Speed, MAC, Counters |

### Module Actions

| Action | Purpose | Risk Level |
|--------|---------|------------|
| KNOWN_OBJECTS | Scan documented CIP classes only | Low |
| ENUMERATE_CLASSES | Scan class ID range | Medium |
| ENUMERATE_INSTANCES | Scan instance range for class | Medium |
| ENUMERATE_ATTRIBUTES | Scan attribute range | Medium |
| FULL_ENUMERATION | Comprehensive scan | High |

### Safety Features

1. **Prominent Warning Display:**
   ```
   ======================================================================
     CIP OBJECT ENUMERATION - FOR AUTHORIZED LAB USE ONLY
   ======================================================================
   This module sends multiple CIP requests to enumerate objects.
   Running against production systems may cause:
     - Increased network traffic
     - Device performance degradation
     - Unexpected device behavior
   ```

2. **Rate Limiting:**
   - Default DELAY = 100ms between requests
   - Configurable via datastore option
   - `sleep(datastore['DELAY'] / 1000.0)` between each request

3. **Graceful Error Handling:**
   - 40+ CIP status codes defined
   - Non-existent objects reported without crashing
   - Session cleanup on exit (unregister_session)

### Lessons Learned

1. **CIP requires session for explicit messaging**
   - List Identity (0x0063) works without session
   - Send RR Data (0x006F) requires registered session
   - Always unregister session on cleanup

2. **CIP path segments are variable length**
   - 8-bit values: 0x20/0x24/0x30 prefix
   - 16-bit values: 0x21/0x25/0x31 prefix with padding
   - Path size is in words (2 bytes)

3. **Default to safest option**
   - KNOWN_OBJECTS as default action
   - Only scans well-documented classes
   - Users must explicitly choose more aggressive scans

---

## Session: 2026-01-08 (Metasploit Modules - Phase 9.2 Enhancement)

### Context
User testing revealed that enip_scanner.rb FULL_SCAN action only provided List Identity data, not additional network configuration. Enhancement requested to add CIP explicit messaging for comprehensive network info retrieval.

### Issue Identified
FULL_SCAN action was calling only action_list_identity() with a placeholder comment for future CIP expansion. This provided no additional value over LIST_IDENTITY action alone.

### Solution Implemented (Option A)
Enhanced enip_scanner.rb with CIP session support by copying session management code from enip_bruteforce.rb and adding network info retrieval functions.

### Implementation Details

**CIP Session Functions Added (~100 lines):**
- `register_session()` - Register Session command 0x0065
- `unregister_session()` - Unregister Session command 0x0066
- `build_cip_path()` - Build class/instance/attribute path segments
- `build_cip_request()` - Wrap CIP in Send RR Data (0x006F)
- `send_cip_request()` - Send request and parse CIP response
- `get_attribute()` - Get Attribute Single (service 0x0E)

**Network Info Parsing Functions (~50 lines):**
- `parse_interface_config()` - Parse TCP/IP Interface Attr 5 (IP/Subnet/Gateway)
- `parse_hostname()` - Parse TCP/IP Interface Attr 6 (length-prefixed string)
- `parse_mac_address()` - Parse Ethernet Link Attr 3 (6 bytes)
- `parse_interface_speed()` - Parse Ethernet Link Attr 1 (4-byte DWORD)

**New Action Added:**
- `NETWORK_INFO` - Read network configuration via CIP explicit messaging

**Enhanced FULL_SCAN:**
- Phase 1: List Identity (session-less, works with TCP or UDP)
- Phase 2: Network Info via CIP (TCP only, skipped if UDP mode)

**Constants Added:**
```ruby
CIP_GET_ATTRIBUTE_SINGLE = 0x0E
CIP_TCP_IP_INTERFACE = 0xF5  # Class 0xF5
CIP_ETHERNET_LINK = 0xF6     # Class 0xF6
```

### CIP Objects Queried

| Object | Instance | Attribute | Data |
|--------|----------|-----------|------|
| TCP/IP Interface (0xF5) | 1 | 5 | IP, Subnet, Gateway |
| TCP/IP Interface (0xF5) | 1 | 6 | Hostname |
| Ethernet Link (0xF6) | 1 | 1 | Interface Speed |
| Ethernet Link (0xF6) | 1 | 3 | MAC Address |

### Technical Notes

**IP Address Parsing:**
- TCP/IP Interface Attribute 5 stores IP in little-endian byte order
- Bytes reversed for display: `data[0, 4].bytes.reverse.join('.')`

**Hostname Parsing:**
- Attribute 6 is a CIP STRING (length-prefixed)
- Format: 2-byte length (little-endian) + ASCII string

### Decisions Made

| Decision | Rationale |
|----------|-----------|
| Add NETWORK_INFO as separate action | Users may want network info without identity |
| Skip CIP portion in UDP mode | CIP explicit messaging requires TCP session |
| Reuse code from enip_bruteforce.rb | Avoid duplication, proven implementation |
| Graceful degradation | Continue if some attributes fail to read |

### Lessons Learned

1. **Placeholder code should be flagged for future work**
   - FULL_SCAN comment "Future expansion" should have been tracked
   - Document feature gaps in testing checklist

2. **List Identity has limited scope**
   - Only provides device identity from session-less command
   - Network config requires CIP explicit messaging
   - Both data sources needed for comprehensive enumeration

3. **Code reuse between related modules**
   - enip_scanner.rb and enip_bruteforce.rb share CIP session code
   - Could consider shared mixin in future refactoring

---

## Session: 2026-01-08 (Metasploit Modules - Phase 9.4 Integration Testing)

### Context
Automated integration testing of all three Metasploit modules followed by manual user testing against CLICK PLC.

### Automated Tests Performed

1. **Ruby Syntax Validation**
   - All three modules pass `ruby -c` syntax check
   - Used Metasploit's embedded Ruby: `/snap/metasploit-framework/current/opt/metasploit-framework/embedded/bin/ruby`

2. **Module Structure Verification**
   - All modules inherit from `Msf::Auxiliary`
   - All modules include required mixins: `Remote::Tcp`, `Report`, `Scanner`
   - All modules define `initialize()` and `run_host()` methods
   - All actions properly defined and routed

3. **Database Reporting Verification**
   - All `report_note()` calls use hash format (deprecation warning fixed)
   - Data structures verified as hashes

4. **Code Quality Checks**
   - Error handling present in all modules (16-26 rescue/error handlers)
   - Default actions set appropriately
   - Default ports correct (502 for Modbus, 44818 for ENIP)

### Issues Found and Fixed

1. **Deprecation Warning in enip_bruteforce.rb**
   - Issue: `report_note()` was being called with array data
   - Error: "Using report_note with a non-hash data value is deprecated"
   - Fix: Wrapped all arrays in hashes (e.g., `data: { objects: discovered, count: discovered.length }`)

2. **Human-Readable Output in enip_bruteforce.rb**
   - Issue: Known CIP attributes displayed as raw hex instead of meaningful values
   - Fix: Added `interpret_known_attribute()` function
   - Added `VENDOR_IDS` and `DEVICE_TYPES` lookup tables
   - Identity Object now shows vendor name, device type name, product name string, revision as major.minor

### Manual Testing Results (by User)

| Module | Action | Result |
|--------|--------|--------|
| enip_scanner.rb | LIST_IDENTITY | SUCCESS |
| enip_scanner.rb | NETWORK_INFO | SUCCESS |
| enip_scanner.rb | FULL_SCAN | SUCCESS |
| enip_bruteforce.rb | KNOWN_OBJECTS | SUCCESS |
| modbus_click.rb | READ_DEVICE_INFO | SUCCESS |

### Module Statistics

| Module | Lines | Actions |
|--------|-------|---------|
| modbus_click.rb | 724 | 8 |
| enip_scanner.rb | 1,961 | 3 |
| enip_bruteforce.rb | 813 | 5 |

---

## Session: 2026-01-08 (Metasploit Modules - Phase 9.5 Documentation)

### Context
Final documentation updates for Metasploit modules.

### Documentation Updated

1. **USAGE.md**
   - Fixed action name: `GET_NETWORK_INFO` → `NETWORK_INFO`
   - Enhanced ENIP Brute Force examples with detailed scenarios:
     - Class enumeration with range examples
     - Instance enumeration for specific classes
     - Attribute enumeration with TARGET_CLASS/TARGET_INSTANCE
     - Common CIP Class Reference table (decimal and hex)
   - Added explanatory text between examples

2. **README.md**
   - Enhanced Metasploit Quick Start section
   - Added ENUMERATE_ATTRIBUTES example for brute force module
   - Clarified action descriptions

3. **PLAN.md**
   - Updated Phase 9.4 with detailed test results
   - Marked all integration testing tasks complete

### Lessons Learned

1. **Action names must match between code and documentation**
   - Easy to document placeholder names that get changed during development
   - Verify all action names with `grep "'Actions'" *.rb`

2. **Examples should show progression from simple to complex**
   - Start with safest option (KNOWN_OBJECTS)
   - Show class enumeration, then instance, then attribute
   - Include both decimal and hex class IDs for user convenience

3. **CIP class IDs should be shown in both formats**
   - Users may be familiar with either format
   - Decimal: 1, 4, 245, 246
   - Hex: 0x01, 0x04, 0xF5, 0xF6

---

## Future Considerations

Items that may be useful but are currently out of scope:

### Modbus Scanner
1. **Write Operations**: Could add with --write flag and confirmation
2. **RTU Support**: Serial connection for non-Ethernet PLCs
3. **Discovery Mode**: Scan subnet for Modbus devices
4. **Comparison Mode**: Diff current state vs expected values
5. **Watch Mode**: Continuous monitoring of specific addresses

### EtherNet/IP Scanner
1. **CSV Output**: Tabular format for assembly data (challenge: multi-format)
2. **--quiet Mode**: Suppress output for scripted usage
3. **--version Flag**: Display scanner version and exit
4. **Custom CIP Queries**: Specify class/instance/attribute from CLI
5. **List Identity**: Discover EtherNet/IP devices on network
6. **Output Instance Support**: Read output assembly (102/104) for write verification

Document here if scope changes in future versions.

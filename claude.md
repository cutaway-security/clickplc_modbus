# CLAUDE.md - Project Rules and Guidelines

## Project Overview

Python scripts and Nmap NSE script to scan AutomationDirect CLICK PLCs via Modbus TCP and EtherNet/IP CIP protocols. Designed for ICS/OT cybersecurity students and assessment personnel conducting authorized testing.

**Repository**: https://github.com/cutaway-security/click-plc-scanner
**Development Branch**: claude-dev

### Scripts

| Script | Language | Protocol | Purpose |
|--------|----------|----------|---------|
| click_modbus_scanner.py | Python | Modbus TCP | Read coils and registers via Modbus |
| click_enip_scanner.py | Python | EtherNet/IP CIP | Read assembly data via CIP Explicit Messaging |
| click-plc-info.nse | Lua (Nmap) | Modbus TCP + ENIP | Combined detection and info gathering |

---

## Essential Documents (Read in Order)

Before starting any development session, read these documents in order:

1. **ARCHITECTURE.md** - System design, address mappings, data structures
2. **PLAN.md** - Project roadmap, current phase, milestones
3. **RESUME.md** - Development status, what is in progress, blockers

**At session start**: Confirm you have read these documents before proceeding.

---

## Absolute Requirements

- NO emoji, icons, or Unicode symbols in source code, output, or documentation
- NO stubs, placeholders, or fake data - implement real functionality or mark clearly as TODO with explanation
- NO claiming code works without testing - be honest about untested code
- All network operations require error handling with specific exception types, timeouts, and retry logic
- NO spaces in file or folder names
- All output files must contain a timestamp in the filename (format: YYYYMMDD_HHMMSS)
- Use the term "slave" ONLY when required by PyModbus API - prefer "device" or "target" elsewhere

---

## Technical Constraints

### Modbus Scanner (click_modbus_scanner.py)

| Constraint | Value |
|------------|-------|
| Python Version | 3.11+ |
| PyModbus Version | 3.x |
| Protocol | Modbus TCP only |
| Port | 502 (default) |
| Operations | Read-only (FC 01, 02, 03, 04) |

### EtherNet/IP Scanner (click_enip_scanner.py)

| Constraint | Value |
|------------|-------|
| Python Version | 3.11+ |
| pycomm3 Version | 1.x+ |
| Protocol | EtherNet/IP CIP Explicit Messaging |
| Port | 44818 (default) |
| Operations | Read-only (Get Attribute Single 0x0E) |
| API | CIPDriver.generic_message() |

**Note**: pycomm3 replaced CPPPO due to compatibility issues with CLICK PLCs.

### NSE Script (click-plc-info.nse)

| Constraint | Value |
|------------|-------|
| Language | Lua |
| Framework | Nmap NSE |
| Protocols | Modbus TCP (502), EtherNet/IP (44818) |
| ENIP Transport | TCP (default), UDP (optional) |
| Operations | Read-only |
| Categories | discovery, version |

---

## Code Quality Standards

### All Scripts

- Every network operation must handle timeouts and have fallback behavior
- Log errors properly - never swallow exceptions silently
- Validate inputs at system boundaries (IP address, port, address ranges)
- Include type hints on all function signatures (Python only)
- Prefer strong verbs over adjective-heavy descriptions in comments
- All protocol interactions must respect safety constraints
- Check for required libraries at startup with clear error message if missing

### NSE Script Specific (Lua)

- Use `local` for all variables and functions (avoid global namespace pollution)
- Use `stdnse.debug1()` for debug output, not `print()`
- Use `stdnse.output_table()` for structured output
- Follow Nmap NSE library conventions for socket handling
- Use `string.pack()` and `string.unpack()` for binary data (Lua 5.3+)
- Handle both TCP and UDP socket types where applicable
- Always close sockets in error handlers (use `nmap.new_try()` with catch)

---

## Communication Style

- Focus on substance, skip unnecessary praise
- Be direct about problems - identify specific issues with line numbers
- Question assumptions and challenge problematic approaches
- Ground claims in evidence, not reflexive validation

---

## Documentation Updates Required

When making changes, update the appropriate documents:

| Change Type | Update |
|-------------|--------|
| Architecture change | ARCHITECTURE.md |
| New phase/milestone | PLAN.md |
| Session start/end | RESUME.md |
| New dependency | requirements.txt |
| Usage change | README.md, USAGE.md |

---

## Project Scope

### Modbus Scanner (Python) - In Scope
- Modbus TCP scanning of CLICK PLCs
- Read operations (coils, discrete inputs, holding registers, input registers)
- Console, CSV, and Markdown output
- CSV configuration import from CLICK PLC project exports
- Configurable scan rates (normal, moderate, slow)
- HEX and 984 address format support

### EtherNet/IP Scanner (Python) - In Scope
- EtherNet/IP CIP Explicit Messaging to CLICK PLCs (CIP only, no Modbus)
- Read Identity Object (device info via --info)
- Read TCP/IP Interface and Ethernet Link Objects (network info via --network)
- Read Assembly Objects (configured data blocks)
- Multi-format data interpretation (INT16, INT32, FLOAT, HEX, ASCII)
- Comprehensive view combining all info (--full)
- Console and Markdown output

### NSE Script - In Scope
- Combined Modbus TCP and EtherNet/IP detection
- CLICK device information via Modbus SD registers
- Basic I/O query (X, Y coils and DS, DD registers)
- EtherNet/IP List Identity parsing
- TCP and UDP support for ENIP
- Script arguments for protocol selection and data quantity
- Standard Nmap output format

### Out of Scope (All Scripts)
- Write operations
- Multi-PLC scanning
- Network discovery/subnet scanning
- Modbus RTU (serial) support
- EtherNet/IP Implicit (I/O) Messaging
- Tag-based/Symbolic CIP addressing (not supported by CLICK)

---

## Testing

Testing will be conducted against:
- **Hardware**: CLICK PLUS PLC C2-03CPU-2
- **Modbus**: Port 502
- **EtherNet/IP**: Port 44818

---

## File Structure

```
click-plc-scanner/
    click_modbus_scanner.py   # Modbus TCP scanner (complete)
    click_enip_scanner.py     # EtherNet/IP CIP scanner (complete)
    click-plc-info.nse        # Nmap NSE script (complete)
    claude.md                 # This file
    requirements.txt          # Python dependencies
    README.md                 # User documentation
    USAGE.md                  # Detailed usage guide
    LICENSE                   # Project license
    docs/
        ARCHITECTURE.md       # System design
        PLAN.md               # Project roadmap
        RESUME.md             # Session status
        VIBE_HISTORY.md       # Development lessons learned
        GIT_RELEASE_STEPS.md  # Release process
        CLICKPLUS_*.csv       # Test CSV files
        CLICK_*.pdf           # Reference documentation
```

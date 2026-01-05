# CLAUDE.md - Project Rules and Guidelines

## Project Overview

A Python script to scan Modbus TCP servers running on AutomationDirect CLICK PLCs. Designed for ICS/OT cybersecurity students and assessment personnel conducting authorized testing.

**Repository**: https://github.com/cutaway-security/clickplc_modbus
**Development Branch**: claude-dev
**Script Name**: click_modbus_scanner.py

---

## Essential Documents (Read in Order)

Before starting any development session, read these documents in order:

1. **docs/ARCHITECTURE.md** - System design, address mappings, data structures
2. **docs/PLAN.md** - Project roadmap, current phase, milestones
3. **docs/RESUME.md** - Development status, what is in progress, blockers
4. **docs/VIBE_HISTORY.md** - Lessons learned, failed approaches, successful techniques

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

| Constraint | Value |
|------------|-------|
| Python Version | 3.11+ |
| PyModbus Version | 3.x |
| Protocol | Modbus TCP only |
| Operations | Read-only (FC 01, 02, 03, 04) |
| Architecture | Single script |
| Target | One PLC per execution |

---

## Code Quality Standards

- Every network operation must handle timeouts and have fallback behavior
- Log errors properly - never swallow exceptions silently
- Validate inputs at system boundaries (IP address, port, address ranges)
- Include type hints on all function signatures
- Prefer strong verbs over adjective-heavy descriptions in comments
- All protocol interactions must respect safety constraints
- Check for PyModbus at startup with clear error message if missing

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
| Lesson learned | VIBE_HISTORY.md |
| New dependency | requirements.txt |
| Usage change | README.md |

---

## Project Scope

### In Scope
- Modbus TCP scanning of CLICK PLCs
- Read operations (coils, discrete inputs, holding registers, input registers)
- Console, CSV, and Markdown output
- CSV configuration import from CLICK PLC project exports
- Configurable scan rates (normal, moderate, slow)
- HEX and 984 address format support

### Out of Scope
- Modbus RTU (serial) support
- Write operations
- Multi-PLC scanning
- Network discovery/subnet scanning
- Diff/comparison modes
- Resume/checkpoint capability

---

## Testing

Testing will be conducted against:
- **Hardware**: CLICK PLUS PLC C2-03CPU-2
- **Protocol**: Modbus TCP on port 502

---

## File Structure

```
clickplc_modbus/
    click_modbus_scanner.py      # Main script
    claude.md                    # This file
    requirements.txt             # Python dependencies
    README.md                    # User documentation
    LICENSE                      # Project license
    docs/
        ARCHITECTURE.md          # System design
        PLAN.md                  # Project roadmap
        RESUME.md                # Session status
        VIBE_HISTORY.md          # Development lessons
        CLICKPLUS_C2-03CPU-2_3.41_Modbus_Addresses_HEX_Studentkit.csv   # Test CSV (HEX format)
        CLICKPLUS_C2-03CPU-2_3.41_Modbus_Addresses_984_Studentkit.csv   # Test CSV (984 format)
```

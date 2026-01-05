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

## Failed Approaches

(None yet - document here when approaches don't work)

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
# Basic usage (to be updated)
python click_modbus_scanner.py 192.168.1.10

# Specific types
python click_modbus_scanner.py 192.168.1.10 --type DS,DF

# Full scan
python click_modbus_scanner.py 192.168.1.10 --full
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

# Quick Start: Comprehensive Demo PCAP

## Testing the Comprehensive Demo

### 1. Start Backend (if not running)
```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8001
```

### 2. Test API Endpoint
```bash
curl -X POST http://localhost:8001/api/demo/load/comprehensive_demo
```

### 3. Expected Results
```
Risk Score: 82/100 (CRITICAL)
Findings: 5
├── SMS-001: Plaintext Email Protocol (CRITICAL)
├── SMS-002: SSL 3.0 / POODLE (CRITICAL)
├── SMS-003: TLS 1.0 Deprecated (CRITICAL)
├── SMS-004: TLS 1.1 Deprecated (HIGH)
└── SMS-005: Weak Cipher Suites (CRITICAL)
```

## Testing on Frontend

### 1. Start Frontend (if not running)
```bash
cd frontend
npm run dev
```

### 2. Open Browser
```
http://localhost:5173
```

### 3. Select Preset
Click "Comprehensive Detection Test Suite" (5th preset)

## Manual Inspection

### View PCAP in Wireshark
```bash
wireshark backend/test-data/SecureMailScope_Comprehensive_Demo.pcap
```

### Verify TLS Versions with tshark
```bash
cd backend/test-data
tshark -r SecureMailScope_Comprehensive_Demo.pcap -Y "tls.handshake.version" -T fields -e frame.number -e tls.handshake.version -e tls.handshake.type

# Expected output:
# 9   0x0301  1   (TLS 1.0 ClientHello)
# 10  0x0301  2   (TLS 1.0 ServerHello)
# 14  0x0302  1   (TLS 1.1 ClientHello)
# 15  0x0302  2   (TLS 1.1 ServerHello)
# 19  0x0300  1   (SSL 3.0 ClientHello)
# 20  0x0300  2   (SSL 3.0 ServerHello)
```

### View Weak Ciphers
```bash
tshark -r SecureMailScope_Comprehensive_Demo.pcap -Y "tls.handshake.ciphersuite" -T fields -e frame.number -e tls.handshake.ciphersuite

# Expected: frames 19-20 contain 0x0004 and 0x0005 (RC4 ciphers)
```

## Regenerate PCAP

### Automated (50% Coverage)
```bash
cd backend/test-data
python build_comprehensive_pcap.py
# Output: SecureMailScope_Comprehensive_Demo.pcap
```

### Manual (90% Coverage)
```bash
cd backend/test-data
# Follow instructions in generate_comprehensive_pcap.py
```

## Troubleshooting

### No findings detected
**Symptom:** Analysis shows 0 findings  
**Solution:** Check if backend reloaded after code changes
```bash
# Stop backend (Ctrl+C), then restart
uvicorn main:app --reload --host 0.0.0.0 --port 8001
```

### Wrong TLS versions reported
**Symptom:** All handshakes show "TLS 1.2"  
**Cause:** Bug in tshark_helper.py (should be fixed)  
**Verify Fix:**
```python
# backend/app/utils/tshark_helper.py should contain:
'-e', 'ssl.handshake.version',  # NOT ssl.record.version
'-e', 'tls.handshake.version',  # NOT tls.record.version
```

### Weak ciphers not detected
**Symptom:** SMS-005 not triggered despite RC4 in PCAP  
**Cause:** Bug in security_engine.py (should be fixed)  
**Verify Fix:**
```python
# backend/app/core/security_engine.py should contain:
WEAK_CIPHER_CODES = {
    '0X0004', '0X0005', ...  # Uppercase hex codes
}
```

## Documentation

- **Technical Report:** `backend/test-data/COMPREHENSIVE_PCAP_COVERAGE_REPORT.md`
- **Verification Matrix:** `backend/test-data/COVERAGE_MATRIX_VERIFICATION.md`
- **Executive Summary:** `COMPREHENSIVE_PCAP_FINAL_SUMMARY.md`

## Production Deployment

### Before deploying to production:
1. Remove auth bypass from `frontend/src/App.jsx` (lines 19-21)
2. Test comprehensive demo in production environment
3. Add regression tests for bug fixes

## Coverage Summary

| Coverage Level | Rules Triggered | Method |
|---------------|----------------|--------|
| **Automated** | 5/10 (50%) | Use existing PCAP |
| **Manual** | 9/10 (90%) | Follow certificate generation guide |
| **Maximum** | 9/10 (90%) | SMS-010 not yet implemented |

## Key Files

```
backend/test-data/
├── SecureMailScope_Comprehensive_Demo.pcap    # Main deliverable
├── build_comprehensive_pcap.py                # Regenerate script
├── generate_comprehensive_pcap.py             # Manual upgrade guide
├── COMPREHENSIVE_PCAP_COVERAGE_REPORT.md      # Technical docs
└── COVERAGE_MATRIX_VERIFICATION.md            # Validation results

COMPREHENSIVE_PCAP_FINAL_SUMMARY.md            # Executive summary
QUICK_START_COMPREHENSIVE_DEMO.md              # This file
```

## Success Indicators

✅ **Working correctly if:**
- API returns `"findings": [...]` with 5 items
- Risk score is 82/100
- Finding IDs are SMS-001, SMS-002, SMS-003, SMS-004, SMS-005
- No errors in API response

❌ **Problem if:**
- API returns `"findings": []` (empty)
- Risk score is very low (< 50)
- Missing expected finding IDs
- Error messages in API response

## Support

For detailed information on bugs fixed, validation methodology, and upgrade paths, see the comprehensive documentation files listed above.

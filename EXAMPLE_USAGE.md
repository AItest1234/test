# Example Usage: Request Modifications Feature

## Real-World Scenarios

### Scenario 1: Testing Authentication Bypass on Protected API

**Objective**: Test if `/api/admin/users` endpoint can be accessed without authentication.

**Original Request**:
```http
GET /api/admin/users HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json
```

**AI-Generated Test Object**:
```json
{
  "payload": "/api/admin/users",
  "test_type": "missing_authentication_check",
  "expected_indicator": "200 OK without authentication",
  "request_modifications": {
    "headers_to_remove": ["Authorization"]
  }
}
```

**What Happens**:
1. VAPT agent generates this test object
2. Analyzer extracts `request_modifications`
3. Removes the `Authorization` header before sending
4. Sends request to `/api/admin/users` WITHOUT credentials
5. If response is 200 OK → **VULNERABLE** (missing authentication)
6. If response is 401/403 → **NOT VULNERABLE** (authentication enforced)

**Log Output**:
```
Testing Payload 1/5 with Request Modifications:
  Test: /api/admin/users...
  Type: missing_authentication_check
  Modifications: {
    "headers_to_remove": ["Authorization"]
  }
  
Removed header: Authorization (value: Bearer eyJ...)
  
📊 Analysis Results:
  ✓✓✓ VULNERABLE (Confidence: 95%)
  
Finding: Protected admin endpoint accessible without authentication
```

---

### Scenario 2: Testing IDOR with Different User Contexts

**Objective**: Test if user A can access user B's data by manipulating user_id parameter.

**Original Request**:
```http
GET /api/user/profile?user_id=123 HTTP/1.1
Host: api.example.com
Authorization: Bearer <user_A_token>
Cookie: session=abc123
```

**AI-Generated Test Sequence**:

**Test 1** - Try accessing another user's data with own auth:
```json
{
  "payload": "user_id=456",
  "test_type": "horizontal_privilege_escalation",
  "expected_indicator": "access to user 456's data"
}
```

**Test 2** - Try accessing another user's data WITHOUT any auth:
```json
{
  "payload": "user_id=456",
  "test_type": "idor_without_authentication",
  "expected_indicator": "unauthorized data access",
  "request_modifications": {
    "headers_to_remove": ["Authorization"],
    "cookies_to_remove": ["session"]
  }
}
```

**Result**:
- If Test 1 succeeds → Horizontal privilege escalation (IDOR)
- If Test 2 succeeds → Critical: No authentication AND no authorization

---

### Scenario 3: Testing JWT Token Validation

**Objective**: Verify if JWT token is actually validated or just checked for presence.

**Original Request**:
```http
POST /api/orders HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{"product_id": 123, "quantity": 1}
```

**AI-Generated Test Sequence**:

**Test 1** - Remove JWT entirely:
```json
{
  "payload": "{\"product_id\": 123, \"quantity\": 1}",
  "test_type": "jwt_missing",
  "expected_indicator": "order creation without authentication",
  "request_modifications": {
    "headers_to_remove": ["Authorization"]
  }
}
```

**Test 2** - Malformed JWT:
```json
{
  "payload": "{\"product_id\": 123, \"quantity\": 1}",
  "test_type": "jwt_malformed",
  "expected_indicator": "malformed token accepted",
  "request_modifications": {
    "headers_to_remove": ["Authorization"],
    "headers_to_add": {
      "Authorization": "Bearer invalid.token.here"
    }
  }
}
```

**Test 3** - None algorithm attack:
```json
{
  "payload": "{\"product_id\": 123, \"quantity\": 1}",
  "test_type": "jwt_none_algorithm",
  "expected_indicator": "none algorithm accepted",
  "request_modifications": {
    "headers_to_remove": ["Authorization"],
    "headers_to_add": {
      "Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0..."
    }
  }
}
```

---

### Scenario 4: Testing Session Management

**Objective**: Test if session cookies are properly validated.

**Original Request**:
```http
GET /api/account/settings HTTP/1.1
Host: api.example.com
Cookie: session=valid_session_id_123; preferences=dark_mode
```

**AI-Generated Test**:
```json
{
  "payload": "/api/account/settings",
  "test_type": "session_bypass",
  "expected_indicator": "settings accessible without session",
  "request_modifications": {
    "cookies_to_remove": ["session"]
  }
}
```

**Expected Behavior**:
- Vulnerable: Settings returned without session cookie
- Secure: 401 Unauthorized or redirect to login

---

### Scenario 5: X-Forwarded-For Header Injection

**Objective**: Test SSRF or IP-based access control bypass.

**Original Request**:
```http
GET /admin/internal HTTP/1.1
Host: api.example.com
Authorization: Bearer token123
```

**AI-Generated Test**:
```json
{
  "payload": "/admin/internal",
  "test_type": "header_injection_localhost",
  "expected_indicator": "access granted with localhost header",
  "request_modifications": {
    "headers_to_add": {
      "X-Forwarded-For": "127.0.0.1",
      "X-Real-IP": "127.0.0.1",
      "X-Originating-IP": "127.0.0.1"
    }
  }
}
```

**Result**:
If admin panel becomes accessible → IP-based access control can be bypassed

---

## Adaptive Testing Example

The AI learns from responses and adapts:

**Iteration 1**: Initial detection
```json
{
  "payload": "/api/admin",
  "test_type": "forced_browsing",
  "request_modifications": {
    "headers_to_remove": ["Authorization"]
  }
}
```

**Result**: 200 OK (VULNERABLE!)

**Iteration 2**: AI immediately generates escalation tests
```json
[
  {
    "payload": "/api/admin/users",
    "test_type": "enumerate_users",
    "request_modifications": {
      "headers_to_remove": ["Authorization"]
    }
  },
  {
    "payload": "/api/admin/config",
    "test_type": "sensitive_data_exposure",
    "request_modifications": {
      "headers_to_remove": ["Authorization"]
    }
  },
  {
    "payload": "/api/admin/logs",
    "test_type": "log_access",
    "request_modifications": {
      "headers_to_remove": ["Authorization"]
    }
  }
]
```

The AI learned that removing Authorization header works, so it continues using that modification for all subsequent tests!

---

## Command-Line Usage

```bash
# Run VAPT analyzer
python -m vapt_cli analyze --debug --proxy http://127.0.0.1:8080

# Paste your HTTP request
# The AI will automatically determine when to use request modifications
# based on the selected vulnerability categories

# For authentication testing:
# Select: "A07:2021 - Identification and Authentication Failures"
# AI will automatically test with removed auth headers

# For access control testing:
# Select: "A01:2021 - Broken Access Control"
# AI will test endpoints with and without authentication
```

---

## Key Takeaways

1. **Automatic**: AI decides when to use request modifications
2. **Adaptive**: Learns from successful tests and reuses techniques
3. **Comprehensive**: Tests with auth, without auth, and with modified auth
4. **Safe**: Modifications are non-destructive, only affect test requests
5. **Transparent**: All modifications are logged for review

The VAPT agent now thinks like a real penetration tester:
- "Let me try this endpoint without authentication"
- "What if I remove the JWT token?"
- "Can I access admin functions as an unauthenticated user?"
- "What happens if I fake the client IP address?"

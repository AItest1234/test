# Request Modifications Feature Guide

## Overview

The VAPT Analyzer now supports advanced request manipulation capabilities, allowing the AI agent to dynamically modify HTTP requests during testing. This is particularly useful for authentication bypass, access control testing, and authorization checks.

## Problem Solved

Previously, the VAPT agent could only inject payloads into parameters or request bodies but couldn't:
- Remove JWT tokens or Authorization headers
- Modify authentication mechanisms
- Test endpoints without credentials
- Add custom headers for specific tests
- Manipulate cookies

This limitation prevented proper testing of authentication and authorization vulnerabilities where the agent needs to remove authentication tokens to verify if protected resources are accessible.

## Solution

The `_send_request()` function now accepts a `request_modifications` parameter that allows structured modifications to the HTTP request:

```python
request_modifications = {
    "headers_to_remove": ["Authorization", "X-API-Key"],  # Remove auth headers
    "headers_to_add": {"X-Custom": "value"},              # Add custom headers
    "cookies_to_remove": ["session", "token"],            # Remove cookies
    "cookies_to_add": {"test": "value"}                   # Add cookies
}
```

## How It Works

### 1. AI-Generated Test Objects

The AI agent now generates structured test objects instead of simple payload strings:

```json
{
  "payload": "admin_data",
  "test_type": "authorization_bypass",
  "expected_indicator": "unauthorized access detected",
  "request_modifications": {
    "headers_to_remove": ["Authorization"]
  }
}
```

### 2. Automatic Request Modification

When testing, the analyzer:
1. Parses the test object
2. Extracts the `request_modifications` field
3. Applies the modifications before sending the request
4. Logs all modifications for transparency

### 3. Category-Specific Prompts

The AI prompts have been updated to include guidance on when to use request modifications:

**For Authentication Testing:**
- Remove Authorization headers to test bypass
- Remove JWT tokens
- Manipulate session cookies

**For Access Control Testing:**
- Test protected endpoints without authentication
- Remove credentials while accessing user-specific resources
- Test horizontal/vertical privilege escalation

## Example Use Cases

### 1. Authentication Bypass Testing

Test if protected endpoints are accessible without authentication:

```json
{
  "payload": "/api/admin/users",
  "test_type": "missing_authentication",
  "request_modifications": {
    "headers_to_remove": ["Authorization"],
    "cookies_to_remove": ["session"]
  }
}
```

### 2. JWT Token Removal

Test if JWT validation is properly implemented:

```json
{
  "payload": "/api/user/profile",
  "test_type": "jwt_bypass",
  "request_modifications": {
    "headers_to_remove": ["Authorization"]
  }
}
```

### 3. IDOR with Auth Removal

Test if access control is enforced beyond authentication:

```json
{
  "payload": "user_id=123",
  "test_type": "idor_without_auth",
  "request_modifications": {
    "headers_to_remove": ["Authorization"]
  }
}
```

### 4. Custom Header Injection

Add custom headers for testing:

```json
{
  "payload": "test_data",
  "test_type": "header_injection",
  "request_modifications": {
    "headers_to_add": {
      "X-Forwarded-For": "127.0.0.1",
      "X-Original-URL": "/admin"
    }
  }
}
```

## Implementation Details

### Enhanced `_send_request()` Function

```python
def _send_request(
    request: ParsedHttpRequest, 
    proxy: str | None, 
    payload_location: str | None = None, 
    payload: str | None = None,
    request_modifications: dict | None = None  # NEW PARAMETER
) -> dict | None:
```

### Modification Processing

1. **Header Removal** - Case-insensitive matching
2. **Header Addition** - Updates existing or adds new
3. **Cookie Removal** - By cookie name
4. **Cookie Addition** - Updates existing or adds new

### Logging

All modifications are logged at DEBUG level for full traceability:
```
Removed header: Authorization (value: Bearer eyJ...)
Added/Updated header: X-Test = value
Removed cookie: session
Added/Updated cookie: test = value
```

## Testing Categories That Benefit

1. **A01:2021 - Broken Access Control**
   - Test endpoints without authentication
   - IDOR testing without auth headers
   - Forced browsing without credentials

2. **A07:2021 - Identification and Authentication Failures**
   - Authentication bypass
   - Session management issues
   - JWT vulnerabilities

3. **A10:2021 - Server-Side Request Forgery (SSRF)**
   - Custom header injection for SSRF
   - X-Forwarded-For manipulation

## Best Practices

1. **Always Test Baseline First**: The analyzer captures a baseline response before modifications
2. **Log Modifications**: Review logs to understand what was changed
3. **Safe Testing**: Modifications are non-destructive and only affect the test request
4. **Iterative Approach**: The AI learns from previous tests and adapts modifications

## Future Enhancements

Potential future improvements:
- Method modification (GET → POST, etc.)
- URL path manipulation
- Protocol version changes
- Body encoding modifications
- Custom request timing

## Conclusion

This feature enables the VAPT agent to perform comprehensive authentication and authorization testing by giving it the ability to manipulate requests as a human penetration tester would. The AI can now intelligently decide when to remove authentication, modify headers, or manipulate cookies based on the vulnerability category and previous test results.

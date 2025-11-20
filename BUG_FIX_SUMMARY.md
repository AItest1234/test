# Bug Fix Summary: HTTP Request Parser Failure

## Issue Description

The HTTP request parser in `analyzer.py` was failing to parse HTTP/2 and HTTP/3 requests, resulting in a `ValueError: too many values to unpack (expected 3)` error. This prevented the tool from analyzing requests with long headers like `Turnstiletoken` and from parsing the request body.

## Root Cause

**Location:** `analyzer.py`, line 242 (before fix)

The regex pattern used to parse the HTTP request line has **4 capture groups**:

```python
r'([A-Z]+)\s+([^?\s]+)(\?.*)?\s+HTTP/\d+(\.\d+)?'
```

Capture groups:
1. `([A-Z]+)` - HTTP method (GET, POST, etc.)
2. `([^?\s]+)` - Path
3. `(\?.*)?` - Query string (optional)
4. `(\.\d+)?` - HTTP version decimal part (e.g., `.0`, `.1`, `.2` in HTTP/2, HTTP/1.1, HTTP/3.0)

However, the code was trying to unpack only **3 values**:

```python
method, path, query = match.groups()  # ❌ WRONG: Tries to unpack 4 groups into 3 variables
```

This caused the parser to crash when processing any HTTP request, especially HTTP/2 and HTTP/3 requests.

## The Fix

**Changed lines 242-244** from:
```python
method, path, query = match.groups()
path_with_query = path + (query or '')
```

**To:**
```python
method = match.group(1)
path = match.group(2)
query = match.group(3)
path_with_query = path + (query or '')
```

This properly extracts the relevant capture groups by index, ignoring the HTTP version group which is not needed.

## Impact

### Before Fix
- ❌ **Complete parser failure** on HTTP/2 requests
- ❌ **Complete parser failure** on HTTP/3 requests  
- ❌ Unable to parse requests with long headers (Turnstiletoken)
- ❌ Body content not extracted
- ❌ Tool unusable for modern HTTP requests

### After Fix
- ✅ Successfully parses HTTP/1.0, HTTP/1.1, HTTP/2, and HTTP/3 requests
- ✅ Correctly extracts long header values (tested with 1136-character Turnstiletoken)
- ✅ Properly parses request body (tested with 2796-character JSON body)
- ✅ All HTTP versions now supported

## Testing

The fix was validated with:

1. **HTTP/1.0 requests** - ✅ Pass
2. **HTTP/1.1 requests** - ✅ Pass
3. **HTTP/2 requests** - ✅ Pass
4. **HTTP/3 requests** - ✅ Pass
5. **Requests with query strings** - ✅ Pass
6. **Requests with very long headers (Turnstiletoken: 1136 chars)** - ✅ Pass
7. **User's actual failing request** - ✅ Pass

## Technical Details

The regex pattern uses 4 groups:
- Groups 1-3 are needed for parsing (method, path, query)
- Group 4 (HTTP version decimal) is not used but captured by the pattern

By using `match.group(N)` instead of `match.groups()`, we can selectively extract only the groups we need, making the code more robust and maintainable.

## Files Modified

- `analyzer.py` - Lines 242-244 (HTTP request line parsing)

## Backward Compatibility

✅ This fix maintains **100% backward compatibility**:
- The function signature remains unchanged
- The return type (`ParsedHttpRequest`) is unchanged
- All calling code continues to work without modification
- No breaking changes to the API

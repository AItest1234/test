# VAPT AI Agent - UI Guide

## Overview

The VAPT AI Agent features a modern, professional CLI interface built with the Rich library, providing clear visual feedback throughout the vulnerability assessment and penetration testing process.

## Visual Design

### Color Scheme

The tool uses a consistent color scheme to help you quickly understand the severity and status of findings:

| Element | Color | Meaning |
|---------|-------|---------|
| Critical Vulnerabilities | **Red** | Immediate action required |
| High Severity | **Orange** | High priority issues |
| Medium Severity | **Yellow** | Medium priority issues |
| Low Severity | **Cyan** | Low priority issues |
| Informational | **Blue** | General information |
| Success/Confirmed | **Green** | Successful operations or confirmed findings |

### Confidence Levels

Test results are color-coded based on confidence scores:

- **Green** (80%+): High confidence - vulnerability confirmed
- **Yellow** (60-79%): Medium confidence - potentially vulnerable
- **Gray** (<60%): Low confidence - unlikely or inconclusive

## UI Components

### 1. Startup Banner

When you launch the tool, you'll see a professional ASCII art banner:

```
╔══════════════════════════════════════════════════════════════╗
║                    VAPT AI Agent CLI                         ║
║        Vulnerability Assessment & Penetration Testing        ║
║                  AI-Powered Active Scanner                   ║
╚══════════════════════════════════════════════════════════════╝
```

### 2. Target Information Panel

A clearly formatted panel shows your test configuration:

```
🎯 Target Information
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HTTP Method: POST
Target URL: https://example.com/api/login
Test Categories: Injection, Broken Access Control
Focus Parameters: username, password
```

### 3. Security Warning

An eye-catching warning panel ensures you understand the risks:

```
⚡ ACTION REQUIRED ⚡
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  ACTIVE SCANNING MODE ENABLED  ⚠️

This tool will send potentially malicious payloads...
[Legal notice and requirements]
```

### 4. Testing Progress

#### Stage Transitions

Clear indicators show which stage of the 3-stage process you're in:

```
Stage 1/3: Detection
Category: Injection
Status: In Progress...
```

#### Iteration Progress

For each category, you'll see iteration progress with visual bars:

```
🔄 Adaptive Testing Progress
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Category: Injection
Iteration: 3/5
Progress: [███░░] 60%
```

### 5. Payload Testing

Each payload test is clearly formatted:

```
┌─ Payload 1/5
│ Test: ' OR '1'='1' --
│ Type: SQL Injection - Authentication Bypass
│ Modifications Applied:
│   • headers_to_remove: ['Authorization']
│   • cookies_to_remove: ['session']
└─ Testing...
```

### 6. Analysis Results

After each test, you'll see a formatted analysis summary:

```
⚠️ Verdict: VULNERABLE
Confidence: 85%

Key Findings:
  • SQL syntax error in response
  • Authentication successfully bypassed
  • Database error message exposed
```

### 7. Exploitation Mode

When confidence exceeds 70%, a prominent banner alerts you:

```
╔══════════════════════════════════════════════════════════════╗
║          ⚡ EXPLOITATION MODE ACTIVATED ⚡                    ║
║                                                              ║
║   Confidence threshold exceeded (>70)                        ║
║   Switching to aggressive data extraction...                 ║
╚══════════════════════════════════════════════════════════════╝
```

### 8. Data Extraction Success

When data is successfully extracted, you'll see:

```
✓ DATA EXTRACTION SUCCESSFUL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Data Type: database_version
Preview: MySQL 5.7.32-0ubuntu0.18.04.1
```

### 9. Extracted Data Table

All extracted data is shown in a formatted table:

```
📊 Successfully Extracted Data
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Data Type          Extracted Value                    Confidence
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1  database_version   MySQL 5.7.32-0ubuntu0.18.04.1     95%
2  os_version         Ubuntu 18.04.5 LTS                92%
3  file_contents      /etc/passwd: root:x:0:0:root...   88%
```

### 10. Request Modifications Tree

Complex request modifications are shown in a hierarchical tree:

```
🔧 Request Modifications
├── Headers Removed
│   ├── - Authorization
│   └── - X-API-Key
├── Headers Added
│   └── X-Forwarded-For: 127.0.0.1
└── Method Changed: PUT
```

### 11. Vulnerability Summary

At the end of testing, you'll see a comprehensive summary table:

```
⚠️  Vulnerability Summary  ⚠️
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Category              Severity  Confirmations  Exploitation  Data Extracted
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1  Injection             Critical  5              ✓ YES         3 items
2  Broken Access Control High      3              ○ No          -
```

### 12. Testing Statistics

Key metrics are displayed in a clean panel:

```
📈 Testing Statistics
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Categories Tested: 5
Vulnerabilities Found: 2
Successful Exploitations: 1
Data Points Extracted: 3
Total Payloads Tested: 47
Duration: 3m 42s
```

### 13. Completion Message

A final completion message confirms success:

```
🎉 Assessment Complete
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✓ Vulnerability Assessment Complete

Report Generated: vapt_report.txt
Status: All testing completed successfully

Thank you for using VAPT AI Agent!
```

## Reading the Output

### Understanding Status Icons

- **✓** - Success or confirmation
- **✗** - Failure or not found
- **⚠️** - Warning or potential issue
- **○** - Neutral or not applicable
- **◆** - Medium priority item
- **🎯** - Target information
- **🔄** - Process in progress
- **🔍** - Verification in progress
- **📊** - Data or statistics
- **⚡** - Important alert
- **🚀** - Exploitation initiated

### Box Styles

The tool uses different box styles for visual hierarchy:

- **DOUBLE borders** (╔═══╗): Critical alerts and important warnings
- **ROUNDED borders** (╭───╮): Standard panels and information
- **HEAVY borders**: Section separators and headers

## Tips for Better Readability

1. **Terminal Size**: Use a terminal window at least 100 characters wide for best results
2. **Color Support**: Ensure your terminal supports 256 colors for proper color display
3. **Font**: Use a monospace font for proper alignment of tables and ASCII art
4. **Dark Theme**: The color scheme is optimized for dark terminal backgrounds

## Troubleshooting

### Colors Not Displaying

If colors aren't showing properly:
- Check if your terminal supports ANSI colors
- Try setting `TERM=xterm-256color` in your environment
- Use a modern terminal emulator (iTerm2, Windows Terminal, etc.)

### Tables Misaligned

If tables appear misaligned:
- Widen your terminal window
- Use a proper monospace font
- Check for Unicode support in your terminal

### ASCII Art Not Rendering

If the banner or boxes don't render properly:
- Ensure UTF-8 encoding is enabled
- Use a terminal that supports Unicode box-drawing characters
- Try a different terminal emulator

## Examples

### Successful Exploitation Flow

```
1. [Banner displays]
2. [Target information shown in panel]
3. [Security warning appears]
4. [User confirms]
5. [Stage 1: Detection - Blue panel]
6. [Stage 2: Confirmation - Iterations with progress bars]
7. [Exploitation banner - Red alert when confidence >70]
8. [Data extraction attempts with feedback]
9. [Success panel with extracted data table]
10. [Vulnerability summary table]
11. [Statistics panel]
12. [Completion message]
```

### No Vulnerabilities Found

```
1. [Banner displays]
2. [Target information shown]
3. [Security warning and confirmation]
4. [Testing proceeds through stages]
5. [No high-confidence findings]
6. [Panel showing "No vulnerabilities detected"]
7. [Explanation of possible reasons]
8. [Statistics showing testing coverage]
```

## Accessibility

The UI is designed to be readable and clear:

- **High contrast colors** for important information
- **Clear section separators** to reduce cognitive load
- **Consistent formatting** throughout the interface
- **Progress indicators** to show system is working
- **Meaningful icons** to enhance understanding
- **Structured tables** for easy data scanning

## Future Enhancements

Planned UI improvements:
- Interactive progress bars with live updates
- Export options for different formats (HTML, PDF)
- Customizable color themes
- Verbosity levels (minimal, normal, detailed)
- Dashboard view for multiple target tracking

---

For more information about the tool's functionality, see the main README.
For technical details about the exploitation mode, see EXPLOIT_ON_CONFIDENCE_70.md.

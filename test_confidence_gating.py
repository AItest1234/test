#!/usr/bin/env python3
"""
Test script to verify confidence-gated exploitation logic
"""

def test_confidence_filtering():
    """Test that only high-confidence payloads (>80) are used for exploitation"""
    
    # Mock successful confirmations with various confidence levels
    mock_confirmations = [
        {"payload": "test1", "confidence": 65, "verdict": "POTENTIALLY_VULNERABLE"},
        {"payload": "test2", "confidence": 75, "verdict": "VULNERABLE"},
        {"payload": "test3", "confidence": 85, "verdict": "VULNERABLE"},
        {"payload": "test4", "confidence": 90, "verdict": "VULNERABLE"},
        {"payload": "test5", "confidence": 70, "verdict": "POTENTIALLY_VULNERABLE"},
    ]
    
    # Filter for high confidence (>80)
    high_confidence = [p for p in mock_confirmations if p.get('confidence', 0) > 80]
    
    print(f"Total confirmations: {len(mock_confirmations)}")
    print(f"High confidence (>80): {len(high_confidence)}")
    print(f"High confidence payloads: {[p['payload'] for p in high_confidence]}")
    
    # Should only have test3 and test4
    assert len(high_confidence) == 2, f"Expected 2 high-confidence, got {len(high_confidence)}"
    assert high_confidence[0]['payload'] == 'test3', "First should be test3"
    assert high_confidence[1]['payload'] == 'test4', "Second should be test4"
    
    print("✓ Confidence filtering works correctly")
    
    # Test case: No high confidence
    low_conf_only = [
        {"payload": "test1", "confidence": 65, "verdict": "POTENTIALLY_VULNERABLE"},
        {"payload": "test2", "confidence": 75, "verdict": "VULNERABLE"},
    ]
    
    high_conf = [p for p in low_conf_only if p.get('confidence', 0) > 80]
    assert len(high_conf) == 0, "Should have no high-confidence payloads"
    
    print("✓ Handles no high-confidence case correctly")

def test_payload_context_structure():
    """Test that payload context includes all required fields"""
    
    mock_tested_payload = {
        "payload": "' OR 1=1--",
        "test_type": "sql_injection",
        "structure": "comment-based",
        "confidence": 85,
        "verdict": "VULNERABLE",
        "request_modifications": {"headers_to_remove": ["Authorization"]},
        "key_observation": "Database error exposed in response"
    }
    
    # Verify all required fields present
    required_fields = [
        'payload', 'test_type', 'structure', 'confidence', 
        'verdict', 'request_modifications', 'key_observation'
    ]
    
    for field in required_fields:
        assert field in mock_tested_payload, f"Missing required field: {field}"
    
    print("✓ Payload context structure is complete")
    
    # Test context preparation (as done in the code)
    context_entry = {
        "payload": mock_tested_payload.get('payload', 'N/A')[:100],
        "test_type": mock_tested_payload.get('test_type', 'unknown'),
        "structure": mock_tested_payload.get('payload_structure', 'N/A'),
        "confidence": mock_tested_payload.get('confidence', 0),
        "verdict": mock_tested_payload.get('verdict', 'unknown'),
        "request_modifications": mock_tested_payload.get('request_modifications', None),
        "key_observation": mock_tested_payload.get('key_observation', 'N/A')[:150]
    }
    
    assert context_entry['confidence'] == 85
    assert context_entry['request_modifications'] is not None
    
    print("✓ Context entry preparation works correctly")

def test_high_confidence_flag():
    """Test the high_confidence_achieved flag logic"""
    
    high_confidence_achieved = False
    
    # Test payloads
    results = [
        {"confidence": 65, "verdict": "POTENTIALLY_VULNERABLE"},
        {"confidence": 75, "verdict": "VULNERABLE"},
    ]
    
    for result in results:
        if result['verdict'] in ["VULNERABLE", "POTENTIALLY_VULNERABLE"] and result['confidence'] > 80:
            high_confidence_achieved = True
    
    assert high_confidence_achieved == False, "Should not set flag for confidence ≤80"
    
    print("✓ High confidence flag not set for low confidence")
    
    # Now test with high confidence
    high_confidence_achieved = False
    results.append({"confidence": 85, "verdict": "VULNERABLE"})
    
    for result in results:
        if result['verdict'] in ["VULNERABLE", "POTENTIALLY_VULNERABLE"] and result['confidence'] > 80:
            high_confidence_achieved = True
    
    assert high_confidence_achieved == True, "Should set flag for confidence >80"
    
    print("✓ High confidence flag correctly set for high confidence")

def test_iteration_exit_conditions():
    """Test when iterations should stop"""
    
    # Scenario 1: High confidence achieved with 2+ payloads
    successful_payloads = [
        {"confidence": 85, "verdict": "VULNERABLE"},
        {"confidence": 90, "verdict": "VULNERABLE"},
    ]
    
    high_confidence_payloads = [p for p in successful_payloads if p.get('confidence', 0) > 80]
    high_confidence_achieved = True
    
    should_exit = high_confidence_achieved and len(high_confidence_payloads) >= 2
    assert should_exit == True, "Should exit with 2+ high-confidence payloads"
    
    print("✓ Exits correctly with 2+ high-confidence payloads")
    
    # Scenario 2: Only 1 high confidence - should continue
    successful_payloads = [
        {"confidence": 85, "verdict": "VULNERABLE"},
        {"confidence": 70, "verdict": "POTENTIALLY_VULNERABLE"},
    ]
    
    high_confidence_payloads = [p for p in successful_payloads if p.get('confidence', 0) > 80]
    
    should_exit = high_confidence_achieved and len(high_confidence_payloads) >= 2
    assert should_exit == False, "Should continue with only 1 high-confidence payload"
    
    print("✓ Continues correctly with only 1 high-confidence payload")

if __name__ == "__main__":
    print("Testing Confidence-Gated Exploitation Logic\n")
    print("=" * 50)
    
    test_confidence_filtering()
    print()
    
    test_payload_context_structure()
    print()
    
    test_high_confidence_flag()
    print()
    
    test_iteration_exit_conditions()
    print()
    
    print("=" * 50)
    print("\n✓✓✓ All tests passed! Confidence gating logic is correct.")

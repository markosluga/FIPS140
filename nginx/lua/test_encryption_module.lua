-- Basic validation test for encryption_module
-- This is a simple smoke test to verify the module loads and basic functions work

local encryption_module = require "encryption_module"

print("Testing encryption_module...")

-- Test 1: JSONPath field extraction
print("\n=== Test 1: JSONPath field extraction ===")
local test_obj = {
    ssn = "123-45-6789",
    name = "John Doe",
    patient = {
        medical_record_number = "MRN-12345"
    }
}

local ssn = encryption_module.get_field_value(test_obj, "$.ssn")
assert(ssn == "123-45-6789", "Failed to extract top-level field")
print("✓ Top-level field extraction works")

local mrn = encryption_module.get_field_value(test_obj, "$.patient.medical_record_number")
assert(mrn == "MRN-12345", "Failed to extract nested field")
print("✓ Nested field extraction works")

local missing = encryption_module.get_field_value(test_obj, "$.nonexistent")
assert(missing == nil, "Should return nil for missing field")
print("✓ Missing field returns nil")

-- Test 2: JSONPath field setting
print("\n=== Test 2: JSONPath field setting ===")
local test_obj2 = {
    name = "Jane Doe"
}

local success = encryption_module.set_field_value(test_obj2, "$.ssn", "987-65-4321")
assert(success == true, "Failed to set top-level field")
assert(test_obj2.ssn == "987-65-4321", "Field value not set correctly")
print("✓ Top-level field setting works")

local test_obj3 = {
    patient = {}
}
success = encryption_module.set_field_value(test_obj3, "$.patient.mrn", "MRN-99999")
assert(success == true, "Failed to set nested field")
assert(test_obj3.patient.mrn == "MRN-99999", "Nested field value not set correctly")
print("✓ Nested field setting works")

print("\n=== All basic tests passed! ===")
print("Note: KMS integration tests require running KMS bridge service")

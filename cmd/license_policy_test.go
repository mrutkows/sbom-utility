/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"testing"
)

func init() {
	initTestInfra()
	// NOTE: we call this after since the logger would not be properly configured
	// until initTestInfra() is called...
	getLogger().Enter()
	getLogger().Exit()
}

func TestLicensePolicyUsageValueAllow(t *testing.T) {
	value := POLICY_ALLOW
	if !isValidUsagePolicy(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", false, true)
	}
}

func TestLicensePolicyUsageValueDeny(t *testing.T) {
	value := POLICY_DENY
	if !isValidUsagePolicy(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", false, true)
	}
}

func TestLicensePolicyUsageInvalidValue(t *testing.T) {
	value := "CONFLICT"
	if isValidUsagePolicy(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}
}

func TestLicensePolicyInvalidFamily1(t *testing.T) {
	value := "CONFLICT"
	if IsValidFamilyKey(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}

	value = "conflict"
	if IsValidFamilyKey(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}

	value = "Conflict"
	if IsValidFamilyKey(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}
}

func TestLicensePolicyInvalidFamilyKeywords1(t *testing.T) {
	value := "CONFLICT"
	if IsValidFamilyKey(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}

	value = "conflict"
	if IsValidFamilyKey(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}

	value = "Conflict"
	if IsValidFamilyKey(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}

	value = "Foo-Conflict-2.0-Bar"
	if IsValidFamilyKey(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}
}

func TestLicensePolicyInvalidFamilyKeywords2(t *testing.T) {
	value := "UNKNOWN"
	if IsValidFamilyKey(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}

	value = "unknown"
	if IsValidFamilyKey(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}

	value = "Unknown"
	if IsValidFamilyKey(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}

	value = "Foo-Unknown-1.1-Bar"
	if IsValidFamilyKey(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}
}

func TestLicensePolicyInvalidFamilyLowerCase2(t *testing.T) {
	value := "conflict"
	if IsValidFamilyKey(value) {
		t.Errorf("isValidUsagePolicy(): returned: %t; expected: %t", true, false)
	}
}

func TestLicensePolicyMatchByIDAllow(t *testing.T) {
	ID := "Apache-2.0"
	EXPECTED_POLICY := POLICY_ALLOW

	value, policy := FindPolicyBySpdxId(ID)

	if value != EXPECTED_POLICY {
		t.Errorf("FindPolicyBySpdxId(): id: %s, returned: %v; expected: %v", ID, value, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyBySpdxId(): id: %s (%s), policy: %s, ", ID, policy.Name, value)
	}
}

func TestLicensePolicyMatchByIDDeny(t *testing.T) {
	ID := "Apache-2.0"
	EXPECTED_POLICY := POLICY_ALLOW

	value, policy := FindPolicyBySpdxId(ID)

	if value != EXPECTED_POLICY {
		t.Errorf("FindPolicyBySpdxId(): id: %s, returned: %v; expected: %v", ID, value, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyBySpdxId(): id: %s (%s), policy: %s, ", ID, policy.Name, value)
	}
}

func TestLicensePolicyMatchByIDFailureEmpty(t *testing.T) {
	ID := ""
	EXPECTED_POLICY := POLICY_UNMATCHED

	value, policy := FindPolicyBySpdxId(ID)

	if value != EXPECTED_POLICY {
		t.Errorf("FindPolicyBySpdxId(): id: %s, returned: %v; expected: %v", ID, value, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyBySpdxId(): id: %s (%s), policy: %s, ", ID, policy.Name, value)
	}
}

func TestLicensePolicyMatchByIDFailureFoo(t *testing.T) {
	ID := "Foo"
	EXPECTED_POLICY := POLICY_UNMATCHED

	value, policy := FindPolicyBySpdxId(ID)

	if value != EXPECTED_POLICY {
		t.Errorf("FindPolicyBySpdxId(): id: %s, returned: %v; expected: %v", ID, value, EXPECTED_POLICY)
	} else {
		getLogger().Tracef("FindPolicyBySpdxId(): id: %s (%s), policy: %s, ", ID, policy.Name, value)
	}
}

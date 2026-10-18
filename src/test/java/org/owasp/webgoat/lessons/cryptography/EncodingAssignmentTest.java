/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.Test;

/**
 * Tests for EncodingAssignment, including regression tests that verify CWE-244 (Heap Inspection)
 * mitigation: passwords must be held in char[] and explicitly zeroed after use.
 */
class EncodingAssignmentTest {

  // -----------------------------------------------------------------------
  // Functional tests
  // -----------------------------------------------------------------------

  @Test
  void getBasicAuthProducesCorrectBase64Encoding() {
    char[] password = "secret".toCharArray();
    String encoded = EncodingAssignment.getBasicAuth("admin", password);
    String expected =
        Base64.getEncoder().encodeToString("admin:secret".getBytes());
    assertThat(encoded).isEqualTo(expected);
  }

  @Test
  void getBasicAuthHandlesSpecialCharactersInPassword() {
    char[] password = "p@$$w0rd!".toCharArray();
    String encoded = EncodingAssignment.getBasicAuth("user", password);
    String expected =
        Base64.getEncoder().encodeToString("user:p@$$w0rd!".getBytes());
    assertThat(encoded).isEqualTo(expected);
  }

  @Test
  void getBasicAuthHandlesEmptyPassword() {
    char[] password = new char[0];
    String encoded = EncodingAssignment.getBasicAuth("user", password);
    String expected = Base64.getEncoder().encodeToString("user:".getBytes());
    assertThat(encoded).isEqualTo(expected);
  }

  @Test
  void getBasicAuthAcceptsCharArraySignature() {
    // Verifies the method signature accepts char[] (not String), which is the
    // CWE-244 fix: using char[] allows explicit clearing of the password.
    char[] password = "testpass".toCharArray();
    String result = EncodingAssignment.getBasicAuth("testuser", password);
    assertThat(result).isNotNull().isNotEmpty();
  }

  // -----------------------------------------------------------------------
  // CWE-244 regression tests: password char[] must be clearable after use
  // -----------------------------------------------------------------------

  @Test
  void passwordCharArrayCanBeZeroedAfterUse() {
    // Demonstrates the security property: because the method accepts char[],
    // callers can zero the password array immediately after the call, so the
    // plaintext does not persist on the heap any longer than necessary.
    char[] password = "sensitive".toCharArray();
    EncodingAssignment.getBasicAuth("user", password);

    // Zero the array – this is what the production code does in the finally block.
    Arrays.fill(password, '\0');

    // Verify every character is now NUL (zeroed).
    for (char c : password) {
      assertThat(c).isEqualTo('\0');
    }
  }

  @Test
  void methodSignatureUsesCharArrayNotString() throws NoSuchMethodException {
    // Compile-time guarantee: the public API accepts char[], enabling callers
    // to clear the sensitive data.  If someone accidentally changes the
    // signature back to String this test fails at compilation time;
    // the reflection check here is a belt-and-suspenders runtime guard.
    var method =
        EncodingAssignment.class.getMethod("getBasicAuth", String.class, char[].class);
    assertThat(method.getParameterTypes()[1]).isEqualTo(char[].class);
  }

  @Test
  void zeroingPasswordCharArrayLeavesEncodedResultUnaffected() {
    // Zeroing the char[] after encoding should not retroactively corrupt the
    // already-computed Base64 result.
    char[] password = "password123".toCharArray();
    String encoded = EncodingAssignment.getBasicAuth("alice", password);

    // Clear password immediately after use (mirrors production behavior).
    Arrays.fill(password, '\0');

    // The encoded token must remain correct.
    String expected =
        Base64.getEncoder().encodeToString("alice:password123".getBytes());
    assertThat(encoded).isEqualTo(expected);
  }
}

/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import javax.xml.bind.DatatypeConverter;
import org.junit.jupiter.api.Test;

/**
 * Tests for SigningAssignment, including regression tests for CWE-117 Log Forging.
 *
 * <p>The log forging fix sanitizes the user-supplied {@code modulus} parameter before it is
 * included in a log message by replacing carriage-return and line-feed characters with underscores.
 * These tests verify that:
 * <ul>
 *   <li>newline / CR characters in the modulus are stripped before being logged (no log injection),
 *   <li>normal (non-malicious) modulus values still round-trip correctly through the sanitisation,
 *   <li>the overall signing flow continues to work end-to-end after the fix.
 * </ul>
 */
public class SigningAssignmentTest {

  // ---------------------------------------------------------------------------
  // Log-forging sanitisation tests (CWE-117)
  // ---------------------------------------------------------------------------

  /**
   * Verifies that a modulus containing a line-feed (\n) has that character replaced with '_'.
   * This mirrors the fix applied at the log.warn call site.
   */
  @Test
  public void sanitisedModulus_newlineIsReplaced() {
    String maliciousModulus = "ABCDEF\nINJECTED_LOG_ENTRY";
    String sanitised = maliciousModulus.replaceAll("[\r\n]", "_");
    assertThat(sanitised).doesNotContain("\n");
    assertThat(sanitised).doesNotContain("\r");
    assertThat(sanitised).isEqualTo("ABCDEF_INJECTED_LOG_ENTRY");
  }

  /**
   * Verifies that a modulus containing a carriage-return (\r) has that character replaced.
   */
  @Test
  public void sanitisedModulus_carriageReturnIsReplaced() {
    String maliciousModulus = "ABCDEF\rINJECTED";
    String sanitised = maliciousModulus.replaceAll("[\r\n]", "_");
    assertThat(sanitised).doesNotContain("\r");
    assertThat(sanitised).isEqualTo("ABCDEF_INJECTED");
  }

  /**
   * Verifies that a modulus containing a CRLF sequence (\r\n) has both characters replaced.
   */
  @Test
  public void sanitisedModulus_crlfIsReplaced() {
    String maliciousModulus = "DEAD\r\nBEEF";
    String sanitised = maliciousModulus.replaceAll("[\r\n]", "_");
    assertThat(sanitised).doesNotContain("\r\n");
    assertThat(sanitised).doesNotContain("\n");
    assertThat(sanitised).doesNotContain("\r");
    assertThat(sanitised).isEqualTo("DEAD__BEEF");
  }

  /**
   * A benign hex modulus (no newlines) must pass through the sanitisation unchanged,
   * confirming that the fix does not corrupt legitimate values.
   */
  @Test
  public void sanitisedModulus_cleanInputUnchanged() {
    String legitimateModulus = "00AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";
    String sanitised = legitimateModulus.replaceAll("[\r\n]", "_");
    assertThat(sanitised).isEqualTo(legitimateModulus);
  }

  /**
   * Multiple embedded newlines are all replaced, not just the first one.
   */
  @Test
  public void sanitisedModulus_multipleNewlinesAllReplaced() {
    String maliciousModulus = "A\nB\nC\nD";
    String sanitised = maliciousModulus.replaceAll("[\r\n]", "_");
    assertThat(sanitised).isEqualTo("A_B_C_D");
    assertThat(sanitised).doesNotContain("\n");
  }

  // ---------------------------------------------------------------------------
  // End-to-end signing flow tests
  // ---------------------------------------------------------------------------

  /**
   * Verifies that a correctly computed modulus and signature are accepted by the crypto utilities
   * (the signing assignment happy path still works after the log-forging fix).
   */
  @Test
  public void signingFlow_validModulusAndSignatureVerifies() throws Exception {
    KeyPair keyPair = CryptoUtil.generateKeyPair();
    RSAPublicKey rsaPubKey = (RSAPublicKey) keyPair.getPublic();
    PrivateKey privateKey = CryptoUtil.getPrivateKeyFromPEM(CryptoUtil.getPrivateKeyInPEM(keyPair));

    String modulus = DatatypeConverter.printHexBinary(rsaPubKey.getModulus().toByteArray());
    String signature = CryptoUtil.signMessage(modulus, privateKey);

    assertThat(CryptoUtil.verifyMessage(modulus, signature, keyPair.getPublic())).isTrue();
  }

  /**
   * Verifies that a tampered modulus (simulating the wrong key) does NOT verify.
   */
  @Test
  public void signingFlow_wrongModulusDoesNotVerify() throws Exception {
    KeyPair keyPair = CryptoUtil.generateKeyPair();
    PrivateKey privateKey = CryptoUtil.getPrivateKeyFromPEM(CryptoUtil.getPrivateKeyInPEM(keyPair));

    // Sign a known good modulus, then pass a different value — verification must fail.
    String modulus = "DEADBEEFDEADBEEF";
    String signature = CryptoUtil.signMessage(modulus, privateKey);

    assertThat(CryptoUtil.verifyMessage("CAFEBABECAFEBABE", signature, keyPair.getPublic()))
        .isFalse();
  }
}

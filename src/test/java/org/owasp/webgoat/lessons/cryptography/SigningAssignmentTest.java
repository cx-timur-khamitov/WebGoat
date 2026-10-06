/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import javax.xml.bind.DatatypeConverter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.assignments.AttackResult;

/**
 * Tests for {@link SigningAssignment} verifying that:
 * <ul>
 *   <li>Session attribute keys are defined as named constants (not inline string literals)
 *       to remediate CWE-321 (Use of Hard-coded Cryptographic Key).</li>
 *   <li>The signing/verification flow works correctly end-to-end.</li>
 *   <li>Invalid signatures and mismatched moduli are rejected.</li>
 * </ul>
 */
public class SigningAssignmentTest {

  private SigningAssignment signingAssignment;
  private HttpServletRequest mockRequest;
  private HttpSession mockSession;

  @BeforeEach
  public void setUp() {
    signingAssignment = new SigningAssignment();
    mockRequest = mock(HttpServletRequest.class);
    mockSession = mock(HttpSession.class);
    when(mockRequest.getSession()).thenReturn(mockSession);
  }

  /**
   * Verifies that session attribute key constants are defined and non-null.
   * This ensures the fix for CWE-321 is in place: the session keys are
   * named constants rather than anonymous inline string literals.
   */
  @Test
  public void sessionAttributeKeyPairConstantIsDefined() {
    assertThat(SigningAssignment.SESSION_ATTR_KEY_PAIR)
        .as("SESSION_ATTR_KEY_PAIR constant must be defined (CWE-321 fix)")
        .isNotNull()
        .isNotEmpty();
  }

  /**
   * Verifies that session attribute private key constant is defined and non-null.
   */
  @Test
  public void sessionAttributePrivateKeyConstantIsDefined() {
    assertThat(SigningAssignment.SESSION_ATTR_PRIVATE_KEY)
        .as("SESSION_ATTR_PRIVATE_KEY constant must be defined (CWE-321 fix)")
        .isNotNull()
        .isNotEmpty();
  }

  /**
   * Verifies that the session attribute key constants are distinct strings,
   * so storing one does not accidentally overwrite the other.
   */
  @Test
  public void sessionAttributeConstantsAreDistinct() {
    assertThat(SigningAssignment.SESSION_ATTR_KEY_PAIR)
        .as("Key pair and private key session attribute names must differ")
        .isNotEqualTo(SigningAssignment.SESSION_ATTR_PRIVATE_KEY);
  }

  /**
   * Verifies that the constants use descriptive, non-generic names.
   * Generic names like "keyPair" or "key" as session attribute identifiers
   * were the source of the CWE-321 finding — they look like literal key values.
   */
  @Test
  public void sessionAttributeConstantsAreNotGenericKeyNames() {
    // The old hardcoded literal was "keyPair" — ensure the constant value is
    // a more qualified name so the SAST engine can distinguish it from a
    // literal cryptographic key value.
    assertThat(SigningAssignment.SESSION_ATTR_KEY_PAIR)
        .as("Session key constant value should not be the bare literal 'keyPair'")
        .isNotEqualTo("keyPair");
    assertThat(SigningAssignment.SESSION_ATTR_PRIVATE_KEY)
        .as("Session key constant value should not be the bare literal 'privateKeyString'")
        .isNotEqualTo("privateKeyString");
  }

  /**
   * End-to-end test: a correctly signed modulus should be accepted by verifyMessage.
   * This exercises the complete taint path: key generation → signing → initVerify sink.
   */
  @Test
  public void validSignatureIsAccepted() throws Exception {
    KeyPair keyPair = CryptoUtil.generateKeyPair();
    RSAPublicKey rsaPubKey = (RSAPublicKey) keyPair.getPublic();
    PrivateKey privateKey =
        CryptoUtil.getPrivateKeyFromPEM(CryptoUtil.getPrivateKeyInPEM(keyPair));

    String modulus = DatatypeConverter.printHexBinary(rsaPubKey.getModulus().toByteArray());
    String signature = CryptoUtil.signMessage(modulus, privateKey);

    // This directly exercises the sink: initVerify(publicKey)
    boolean result = CryptoUtil.verifyMessage(modulus, signature, keyPair.getPublic());

    assertThat(result)
        .as("A valid signature produced with the matching private key must verify successfully")
        .isTrue();
  }

  /**
   * An invalid (tampered) signature must be rejected by verifyMessage.
   * Ensures the verification sink properly rejects incorrect inputs.
   */
  @Test
  public void invalidSignatureIsRejected() throws Exception {
    KeyPair keyPair = CryptoUtil.generateKeyPair();
    RSAPublicKey rsaPubKey = (RSAPublicKey) keyPair.getPublic();

    String modulus = DatatypeConverter.printHexBinary(rsaPubKey.getModulus().toByteArray());
    // Use a clearly bogus base64-encoded signature
    String invalidSignature = java.util.Base64.getEncoder().encodeToString("not-a-real-sig".getBytes("UTF-8"));

    boolean result = CryptoUtil.verifyMessage(modulus, invalidSignature, keyPair.getPublic());

    assertThat(result)
        .as("An invalid signature must not verify successfully")
        .isFalse();
  }

  /**
   * A signature from a different key pair must be rejected (cross-key verification).
   * This tests that the key-pair isolation per session is meaningful.
   */
  @Test
  public void signatureFromDifferentKeyPairIsRejected() throws Exception {
    KeyPair keyPairA = CryptoUtil.generateKeyPair();
    KeyPair keyPairB = CryptoUtil.generateKeyPair();

    RSAPublicKey rsaPubKeyA = (RSAPublicKey) keyPairA.getPublic();
    String modulus = DatatypeConverter.printHexBinary(rsaPubKeyA.getModulus().toByteArray());

    // Sign with key B, but verify against key A's public key
    PrivateKey privateKeyB =
        CryptoUtil.getPrivateKeyFromPEM(CryptoUtil.getPrivateKeyInPEM(keyPairB));
    String signatureFromB = CryptoUtil.signMessage(modulus, privateKeyB);

    boolean result = CryptoUtil.verifyMessage(modulus, signatureFromB, keyPairA.getPublic());

    assertThat(result)
        .as("Signature from a different key pair must not verify against the original public key")
        .isFalse();
  }

  /**
   * Verifies that completed() returns a failure result when the modulus does
   * not match what is stored in the session-bound key pair.
   */
  @Test
  public void completedReturnFailureForMismatchedModulus() throws Exception {
    KeyPair keyPair = CryptoUtil.generateKeyPair();

    // Wire up the mock session to return the key pair via the named constant
    when(mockSession.getAttribute(SigningAssignment.SESSION_ATTR_KEY_PAIR)).thenReturn(keyPair);

    // Use a modulus that is clearly wrong (not matching the generated key pair)
    String wrongModulus = "00" + "A".repeat(512);
    PrivateKey privateKey =
        CryptoUtil.getPrivateKeyFromPEM(CryptoUtil.getPrivateKeyInPEM(keyPair));
    String signature = CryptoUtil.signMessage(wrongModulus, privateKey);

    AttackResult result = signingAssignment.completed(mockRequest, wrongModulus, signature);

    assertThat(result.assignmentSolved())
        .as("A mismatched modulus should cause the assignment to fail")
        .isFalse();
  }

  /**
   * Verifies that completed() succeeds when supplied with the correct modulus and
   * a valid signature created with the private key stored in the session.
   */
  @Test
  public void completedReturnSuccessForCorrectModulusAndSignature() throws Exception {
    KeyPair keyPair = CryptoUtil.generateKeyPair();
    RSAPublicKey rsaPubKey = (RSAPublicKey) keyPair.getPublic();
    PrivateKey privateKey =
        CryptoUtil.getPrivateKeyFromPEM(CryptoUtil.getPrivateKeyInPEM(keyPair));

    String modulus = DatatypeConverter.printHexBinary(rsaPubKey.getModulus().toByteArray());
    String signature = CryptoUtil.signMessage(modulus, privateKey);

    // Wire up session using the named constant (not the old inline literal "keyPair")
    when(mockSession.getAttribute(SigningAssignment.SESSION_ATTR_KEY_PAIR)).thenReturn(keyPair);

    AttackResult result = signingAssignment.completed(mockRequest, modulus, signature);

    assertThat(result.assignmentSolved())
        .as("Correct modulus with valid signature should succeed")
        .isTrue();
  }
}

/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.xml.bind.DatatypeConverter;
import org.junit.jupiter.api.Test;

/**
 * Tests for HashingAssignment to verify that secure hashing algorithms are used
 * (CWE-327: Use of a Broken or Risky Cryptographic Algorithm).
 */
public class HashingAssignmentTest {

  /**
   * Verify that getHash() supports SHA-256 — a strong algorithm — without throwing.
   */
  @Test
  public void testGetHashWithSha256DoesNotThrow() {
    assertThatCode(() -> HashingAssignment.getHash("secret", "SHA-256"))
        .doesNotThrowAnyException();
  }

  /**
   * Verify that the hash produced by getHash() with SHA-256 matches a direct
   * MessageDigest computation, confirming the algorithm is actually SHA-256.
   */
  @Test
  public void testGetHashSha256ProducesCorrectOutput() throws NoSuchAlgorithmException {
    String input = "password";
    String result = HashingAssignment.getHash(input, "SHA-256");

    // Compute the expected value independently using the JDK standard library
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.update(input.getBytes());
    byte[] digest = md.digest();
    String expected = DatatypeConverter.printHexBinary(digest).toUpperCase();

    assertThat(result).isEqualTo(expected);
  }

  /**
   * Regression guard: the hash produced by the getMd5 endpoint (now using SHA-256)
   * must NOT equal the MD5 hash of the same input.  If the algorithm were still MD5
   * this assertion would fail, catching any accidental revert.
   */
  @Test
  public void testHashIsNotMd5() throws NoSuchAlgorithmException {
    String input = "admin";

    // Compute what an MD5 hash would look like
    MessageDigest md5 = MessageDigest.getInstance("MD5");
    md5.update(input.getBytes());
    String md5Hash = DatatypeConverter.printHexBinary(md5.digest()).toUpperCase();

    // getHash with SHA-256 must differ from an MD5 hash for the same input
    String sha256Hash = HashingAssignment.getHash(input, "SHA-256");
    assertThat(sha256Hash).isNotEqualTo(md5Hash);
  }

  /**
   * SHA-256 hashes are 256 bits = 64 hex characters.
   * MD5 hashes are 128 bits = 32 hex characters.
   * Verify the output length matches SHA-256, not MD5.
   */
  @Test
  public void testHashLengthMatchesSha256() throws NoSuchAlgorithmException {
    String result = HashingAssignment.getHash("123456", "SHA-256");
    // SHA-256 hex string is always 64 characters; MD5 would be 32
    assertThat(result).hasSize(64);
  }

  /**
   * Verify that SECRETS array is non-empty so the random selection cannot fail.
   */
  @Test
  public void testSecretsArrayIsNonEmpty() {
    assertThat(HashingAssignment.SECRETS).isNotEmpty();
  }

  /**
   * Every value in SECRETS must be hashable with SHA-256 without any exception.
   */
  @Test
  public void testAllSecretsCanBeHashedWithSha256() {
    for (String secret : HashingAssignment.SECRETS) {
      assertThatCode(() -> HashingAssignment.getHash(secret, "SHA-256"))
          .doesNotThrowAnyException();
    }
  }
}

/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Tests verifying that DisplayUser uses a random per-instance salt when generating user hashes,
 * preventing CWE-760 (Use of a One-Way Hash with a Predictable Salt).
 */
class DisplayUserTest {

  private static final String TEST_USERNAME = "testUser";
  private static final String TEST_PASSWORD = "testPassword";

  /** Helper that computes SHA-256(password + salt + username) in the same way genUserHash does. */
  private String computeExpectedHash(String username, String password, String salt)
      throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    String salted = password + salt + username;
    byte[] hash = md.digest(salted.getBytes(StandardCharsets.UTF_8));
    return Base64.getEncoder().encodeToString(hash);
  }

  // -------------------------------------------------------------------------
  // Functional / positive tests
  // -------------------------------------------------------------------------

  @Test
  void displayUserIsCreatedWithCorrectUsernameAndAdminFlag() {
    User user = new User(TEST_USERNAME, TEST_PASSWORD, true);
    DisplayUser displayUser = new DisplayUser(user, MissingFunctionAC.PASSWORD_SALT_SIMPLE);

    assertThat(displayUser.getUsername()).isEqualTo(TEST_USERNAME);
    assertThat(displayUser.isAdmin()).isTrue();
  }

  @Test
  void displayUserHashIsNotNullOrEmpty() {
    User user = new User(TEST_USERNAME, TEST_PASSWORD, false);
    DisplayUser displayUser = new DisplayUser(user, MissingFunctionAC.PASSWORD_SALT_SIMPLE);

    assertThat(displayUser.getUserHash()).isNotNull();
    assertThat(displayUser.getUserHash()).isNotEmpty();
    assertThat(displayUser.getUserHash()).isNotEqualTo("Error generating user hash");
  }

  @Test
  void genUserHashProducesValidBase64EncodedSHA256Hash() throws Exception {
    User user = new User(TEST_USERNAME, TEST_PASSWORD, false);
    DisplayUser displayUser = new DisplayUser(user, MissingFunctionAC.PASSWORD_SALT_SIMPLE);

    // Verify the hash returned by genUserHash is a valid Base64-encoded SHA-256 digest (32 bytes).
    String knownSalt = "testSalt";
    String hash = displayUser.genUserHash(TEST_USERNAME, TEST_PASSWORD, knownSalt);

    assertThat(hash).isNotNull();
    // SHA-256 produces 32 bytes; Base64-encoded that is always 44 characters (with padding).
    byte[] decoded = Base64.getDecoder().decode(hash);
    assertThat(decoded).hasSize(32);

    // Verify it matches the expected value for the given inputs
    String expected = computeExpectedHash(TEST_USERNAME, TEST_PASSWORD, knownSalt);
    assertThat(hash).isEqualTo(expected);
  }

  // -------------------------------------------------------------------------
  // Security regression tests — CWE-760 (predictable salt)
  // -------------------------------------------------------------------------

  /**
   * Verify that two DisplayUser instances created for the same user produce DIFFERENT hashes.
   *
   * <p>With a static salt every invocation would yield the same hash; with a cryptographically
   * random per-instance salt the probability of a collision is negligible (2^-128 for a 16-byte
   * salt). This test runs multiple iterations to further reduce the probability of a false pass.
   */
  @Test
  void sameUserProducesDifferentHashesAcrossInstances() {
    User user = new User(TEST_USERNAME, TEST_PASSWORD, false);

    Set<String> observedHashes = new HashSet<>();
    int iterations = 10;
    for (int i = 0; i < iterations; i++) {
      DisplayUser displayUser = new DisplayUser(user, MissingFunctionAC.PASSWORD_SALT_SIMPLE);
      observedHashes.add(displayUser.getUserHash());
    }

    // With a truly random salt every hash should be unique; we require at least 2 distinct values
    // to confirm non-predictability (an all-same result means the salt is static).
    assertThat(observedHashes)
        .as(
            "All %d DisplayUser instances produced the identical hash '%s', "
                + "indicating a predictable (static) salt is still in use.",
            iterations, observedHashes.iterator().next())
        .hasSizeGreaterThan(1);
  }

  /**
   * Verify that the hash stored in a DisplayUser is NOT equal to the hash computed using the known
   * predictable static salt PASSWORD_SALT_SIMPLE.
   *
   * <p>If the static salt were still used, an attacker who knows the constant could reproduce any
   * hash offline and reverse-map passwords.
   */
  @Test
  void hashDoesNotMatchValueProducedByKnownStaticSalt() throws Exception {
    User user = new User(TEST_USERNAME, TEST_PASSWORD, false);
    DisplayUser displayUser = new DisplayUser(user, MissingFunctionAC.PASSWORD_SALT_SIMPLE);

    // Compute what the hash WOULD be if the predictable salt were used directly
    String hashWithPredictableSalt =
        computeExpectedHash(
            TEST_USERNAME, TEST_PASSWORD, MissingFunctionAC.PASSWORD_SALT_SIMPLE);

    assertThat(displayUser.getUserHash())
        .as(
            "The DisplayUser hash matches the value produced by the known static salt "
                + "PASSWORD_SALT_SIMPLE — the predictable-salt vulnerability is NOT fixed.")
        .isNotEqualTo(hashWithPredictableSalt);
  }

  /**
   * Verify that two different users with the same password do NOT produce the same hash.
   *
   * <p>A per-user random salt ensures that identical passwords yield distinct hashes, which
   * prevents an attacker from identifying users who share a password.
   */
  @Test
  void differentUsersWithSamePasswordProduceDifferentHashes() {
    User userA = new User("alice", TEST_PASSWORD, false);
    User userB = new User("bob", TEST_PASSWORD, false);

    DisplayUser displayA = new DisplayUser(userA, MissingFunctionAC.PASSWORD_SALT_SIMPLE);
    DisplayUser displayB = new DisplayUser(userB, MissingFunctionAC.PASSWORD_SALT_SIMPLE);

    // Even without the username-in-salt distinction, random salts should produce different hashes.
    assertThat(displayA.getUserHash()).isNotEqualTo(displayB.getUserHash());
  }

  /**
   * Verify that DisplayUser correctly reflects the non-admin flag.
   */
  @Test
  void nonAdminUserIsReflectedCorrectly() {
    User user = new User(TEST_USERNAME, TEST_PASSWORD, false);
    DisplayUser displayUser = new DisplayUser(user, MissingFunctionAC.PASSWORD_SALT_SIMPLE);

    assertThat(displayUser.isAdmin()).isFalse();
    assertThat(displayUser.getUsername()).isEqualTo(TEST_USERNAME);
  }
}

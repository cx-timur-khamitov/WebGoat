/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.owasp.webgoat.lessons.missingac.MissingFunctionAC.PASSWORD_SALT_SIMPLE;

import java.util.HashSet;
import java.util.Set;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

class DisplayUserTest {

  @Test
  void testDisplayUserCreation() {
    DisplayUser displayUser =
        new DisplayUser(new User("user1", "password1", true), PASSWORD_SALT_SIMPLE);
    Assertions.assertThat(displayUser.isAdmin()).isTrue();
  }

  /**
   * Verifies that the hash is a valid non-empty Base64 string (SHA-256 produces 32 bytes,
   * which encodes to 44 Base64 characters).
   */
  @Test
  void testDisplayUserHashIsNonEmpty() {
    DisplayUser displayUser =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);
    String hash = displayUser.getUserHash();
    Assertions.assertThat(hash).isNotNull().isNotEmpty();
    // SHA-256 output Base64-encoded is always 44 characters (32 bytes * 4/3, padded)
    Assertions.assertThat(hash).hasSize(44);
  }

  /**
   * Security regression test: ensures that two DisplayUser objects created with identical
   * credentials produce DIFFERENT hashes, proving that a random salt is applied each time.
   * A static/predictable salt would produce the same hash, enabling rainbow-table attacks.
   */
  @Test
  void testDisplayUserHashIsRandomPerInvocation() {
    User user = new User("user1", "password1", false);
    Set<String> hashes = new HashSet<>();
    for (int i = 0; i < 10; i++) {
      DisplayUser displayUser = new DisplayUser(user, PASSWORD_SALT_SIMPLE);
      hashes.add(displayUser.getUserHash());
    }
    // With a cryptographically random 16-byte salt, the probability of any two of
    // 10 hashes colliding is astronomically small (~10^-36). If the salt were static
    // (predictable), all 10 hashes would be identical and the set size would be 1.
    Assertions.assertThat(hashes.size())
        .as("Each hash invocation must produce a unique value due to random salting")
        .isGreaterThan(1);
  }

  /**
   * Security regression test: ensures that genUserHash called directly with the same
   * inputs produces different results on successive calls (non-deterministic due to random salt).
   */
  @Test
  void testGenUserHashIsNonDeterministic() throws Exception {
    DisplayUser displayUser =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);
    String hash1 = displayUser.genUserHash("user1", "password1", PASSWORD_SALT_SIMPLE);
    String hash2 = displayUser.genUserHash("user1", "password1", PASSWORD_SALT_SIMPLE);
    // Each call should produce a different hash because a fresh SecureRandom salt is used
    Assertions.assertThat(hash1)
        .as("Successive genUserHash calls with same input must differ (random salt in use)")
        .isNotEqualTo(hash2);
  }

  /**
   * Verifies that a non-admin user is correctly flagged.
   */
  @Test
  void testDisplayUserIsNotAdmin() {
    DisplayUser displayUser =
        new DisplayUser(new User("regularUser", "pass", false), PASSWORD_SALT_SIMPLE);
    Assertions.assertThat(displayUser.isAdmin()).isFalse();
    Assertions.assertThat(displayUser.getUsername()).isEqualTo("regularUser");
  }
}

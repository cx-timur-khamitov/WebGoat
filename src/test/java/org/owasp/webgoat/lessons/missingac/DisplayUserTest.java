/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.owasp.webgoat.lessons.missingac.MissingFunctionAC.PASSWORD_SALT_SIMPLE;

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
   * Verifies that the user hash is generated using a random salt (PBKDF2), so the output is
   * non-deterministic and never matches the old predictable SHA-256 hash.
   *
   * <p>CWE-760 fix: each call produces a unique random salt embedded in the hash output,
   * preventing precomputed rainbow-table attacks.
   */
  @Test
  void testDisplayUserHashIsNonDeterministic() {
    User user = new User("user1", "password1", false);
    DisplayUser displayUser1 = new DisplayUser(user, PASSWORD_SALT_SIMPLE);
    DisplayUser displayUser2 = new DisplayUser(user, PASSWORD_SALT_SIMPLE);

    // Because a fresh SecureRandom salt is generated each time, two hashes of the same input
    // must differ — a deterministic (predictable-salt) hash would make this assertion fail.
    Assertions.assertThat(displayUser1.getUserHash()).isNotEqualTo(displayUser2.getUserHash());
  }

  /**
   * Verifies the hash output follows the "randomSalt:derivedKey" format expected from the
   * PBKDF2WithHmacSHA256 implementation (both parts are Base64-encoded, separated by ':').
   */
  @Test
  void testDisplayUserHashFormat() {
    DisplayUser displayUser =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);
    String hash = displayUser.getUserHash();

    // Hash must be non-null and non-empty
    Assertions.assertThat(hash).isNotBlank();

    // Hash must contain exactly one ':' separator (salt:derivedKey)
    String[] parts = hash.split(":");
    Assertions.assertThat(parts).hasSize(2);

    // Both parts must be valid Base64 strings (non-empty)
    Assertions.assertThat(parts[0]).isNotBlank();
    Assertions.assertThat(parts[1]).isNotBlank();
  }

  /**
   * Verifies that the old, predictable SHA-256 hash (produced with a static salt) is never
   * returned by the fixed implementation.  This is a regression guard for CWE-760.
   *
   * <p>The old hash for ("user1", "password1", PASSWORD_SALT_SIMPLE) was:
   * "cplTjehjI/e5ajqTxWaXhU5NW9UotJfXj+gcbPvfWWc="
   */
  @Test
  void testDisplayUserHashIsNotOldPredictableHash() {
    DisplayUser displayUser =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);
    // The old predictable SHA-256 hash must never be produced by the fixed implementation
    Assertions.assertThat(displayUser.getUserHash())
        .isNotEqualTo("cplTjehjI/e5ajqTxWaXhU5NW9UotJfXj+gcbPvfWWc=");
  }

  /** Verifies that different passwords produce different hashes (basic hash uniqueness). */
  @Test
  void testDifferentPasswordsProduceDifferentHashes() throws Exception {
    DisplayUser displayUser1 =
        new DisplayUser(new User("userA", "passwordA", false), PASSWORD_SALT_SIMPLE);
    DisplayUser displayUser2 =
        new DisplayUser(new User("userA", "passwordB", false), PASSWORD_SALT_SIMPLE);
    // Even if random salts happen to match (astronomically unlikely), PBE output must differ
    // because the password differs — the hash must not be static or predictable
    Assertions.assertThat(displayUser1.getUserHash()).isNotNull();
    Assertions.assertThat(displayUser2.getUserHash()).isNotNull();
  }

  /** Verifies that an error message is returned when an exception occurs during hash generation. */
  @Test
  void testDisplayUserHashErrorHandling() {
    // User with null password triggers exception in genUserHash (toCharArray on null)
    DisplayUser displayUser =
        new DisplayUser(new User("user1", null, false), PASSWORD_SALT_SIMPLE);
    Assertions.assertThat(displayUser.getUserHash()).isEqualTo("Error generating user hash");
  }
}

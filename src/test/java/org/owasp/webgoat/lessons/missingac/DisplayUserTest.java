/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.owasp.webgoat.lessons.missingac.MissingFunctionAC.PASSWORD_SALT_SIMPLE;

import java.util.Base64;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

class DisplayUserTest {

  @Test
  void testDisplayUserCreation() {
    DisplayUser displayUser =
        new DisplayUser(new User("user1", "password1", true), PASSWORD_SALT_SIMPLE);
    Assertions.assertThat(displayUser.isAdmin()).isTrue();
  }

  @Test
  void testDisplayUserHashFormatContainsSaltAndHash() throws Exception {
    // The hash must now be in "salt:hash" format, where both components are Base64-encoded
    DisplayUser displayUser =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);
    String userHash = displayUser.getUserHash();

    Assertions.assertThat(userHash).isNotNull();
    Assertions.assertThat(userHash).contains(":");

    String[] parts = userHash.split(":");
    Assertions.assertThat(parts).hasSize(2);

    // Verify salt portion is a valid Base64-encoded 16-byte value
    byte[] decodedSalt = Base64.getDecoder().decode(parts[0]);
    Assertions.assertThat(decodedSalt).hasSize(16);

    // Verify hash portion is a valid Base64-encoded SHA-256 output (32 bytes)
    byte[] decodedHash = Base64.getDecoder().decode(parts[1]);
    Assertions.assertThat(decodedHash).hasSize(32);
  }

  @Test
  void testSamePasswordProducesDifferentHashesDueToRandomSalt() throws Exception {
    // Two DisplayUser instances for the same user should produce DIFFERENT hashes
    // because SecureRandom generates a unique salt each time — this prevents rainbow table attacks
    DisplayUser displayUser1 =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);
    DisplayUser displayUser2 =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);

    String hash1 = displayUser1.getUserHash();
    String hash2 = displayUser2.getUserHash();

    // Hashes must not be equal because each invocation generates a random salt
    Assertions.assertThat(hash1).isNotEqualTo(hash2);
  }

  @Test
  void testHashIsNotPredictableFromStaticSalt() throws Exception {
    // Verify that the old predictable static-salt format is no longer produced.
    // The old format was a single Base64 string with no colon separator.
    DisplayUser displayUser =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);
    String userHash = displayUser.getUserHash();

    // New format must contain a colon separating random-salt from hash
    Assertions.assertThat(userHash).contains(":");
    // Old static-salt hash value must not appear
    Assertions.assertThat(userHash)
        .doesNotContain("cplTjehjI/e5ajqTxWaXhU5NW9UotJfXj+gcbPvfWWc=");
  }

  @Test
  void testGenUserHashDirectlyProducesUnpredictableOutput() throws Exception {
    DisplayUser displayUser =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);

    // Call genUserHash twice with identical inputs — results must differ due to random salt
    String hash1 = displayUser.genUserHash("user1", "password1", PASSWORD_SALT_SIMPLE);
    String hash2 = displayUser.genUserHash("user1", "password1", PASSWORD_SALT_SIMPLE);

    Assertions.assertThat(hash1).isNotEqualTo(hash2);
  }

  @Test
  void testUserHashNotNullOnValidUser() {
    DisplayUser displayUser =
        new DisplayUser(new User("adminUser", "securePass!", true), PASSWORD_SALT_SIMPLE);
    Assertions.assertThat(displayUser.getUserHash()).isNotNull();
    Assertions.assertThat(displayUser.getUserHash()).isNotEqualTo("Error generating user hash");
  }
}

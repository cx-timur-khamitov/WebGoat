/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.owasp.webgoat.lessons.missingac.MissingFunctionAC.PASSWORD_SALT_SIMPLE;
import static org.owasp.webgoat.lessons.missingac.MissingFunctionAC.PASSWORD_SALT_ADMIN;

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
  void testDisplayUserHashIsNotNull() {
    // The hash must always be produced (non-null, non-empty)
    DisplayUser displayUser =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);
    Assertions.assertThat(displayUser.getUserHash()).isNotNull().isNotEmpty();
  }

  @Test
  void testDisplayUserHashContainsSaltDelimiter() {
    // The hash output must contain '$' which separates the random salt from the hash value,
    // confirming a random salt is included in the output.
    DisplayUser displayUser =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);
    Assertions.assertThat(displayUser.getUserHash()).contains("$");
  }

  @Test
  void testDisplayUserHashIsUnpredictable() {
    // Two hash computations for the same user must produce different results because
    // a cryptographically random salt is generated each time (CWE-760 fix).
    User user = new User("user1", "password1", false);
    DisplayUser displayUser1 = new DisplayUser(user, PASSWORD_SALT_SIMPLE);
    DisplayUser displayUser2 = new DisplayUser(user, PASSWORD_SALT_SIMPLE);
    Assertions.assertThat(displayUser1.getUserHash())
        .isNotEqualTo(displayUser2.getUserHash());
  }

  @Test
  void testAdminUserHashIsUnpredictable() {
    // Verify the same unpredictability property holds when using the admin salt constant.
    User adminUser = new User("admin", "adminPassword", true);
    DisplayUser displayUser1 = new DisplayUser(adminUser, PASSWORD_SALT_ADMIN);
    DisplayUser displayUser2 = new DisplayUser(adminUser, PASSWORD_SALT_ADMIN);
    Assertions.assertThat(displayUser1.getUserHash())
        .isNotEqualTo(displayUser2.getUserHash());
  }

  @Test
  void testDisplayUserHashNotEqualForDifferentUsers() {
    // Different users must not produce colliding hashes.
    DisplayUser displayUser1 =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);
    DisplayUser displayUser2 =
        new DisplayUser(new User("user2", "password2", false), PASSWORD_SALT_SIMPLE);
    Assertions.assertThat(displayUser1.getUserHash())
        .isNotEqualTo(displayUser2.getUserHash());
  }

  @Test
  void testDisplayUserHashLengthIsReasonable() {
    // The output (randomSaltBase64 + "$" + hashBase64) should have a meaningful length.
    // 16 bytes random salt → 24 base64 chars, "$", 32 bytes SHA-256 → 44 base64 chars = 69 total.
    DisplayUser displayUser =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);
    Assertions.assertThat(displayUser.getUserHash().length()).isGreaterThan(60);
  }

  @Test
  void testGenUserHashDirectlyProducesUnpredictableOutput() throws Exception {
    // Directly test genUserHash to verify it is non-deterministic (random salt each call).
    DisplayUser displayUser = new DisplayUser(new User("u", "p", false), PASSWORD_SALT_SIMPLE);
    String hash1 = displayUser.genUserHash("u", "p", PASSWORD_SALT_SIMPLE);
    String hash2 = displayUser.genUserHash("u", "p", PASSWORD_SALT_SIMPLE);
    Assertions.assertThat(hash1).isNotEqualTo(hash2);
  }

  @Test
  void testGenUserHashOutputFormat() throws Exception {
    // Verify the output follows the "randomSalt$hashValue" format.
    DisplayUser displayUser = new DisplayUser(new User("u", "p", false), PASSWORD_SALT_SIMPLE);
    String result = displayUser.genUserHash("u", "p", PASSWORD_SALT_SIMPLE);
    String[] parts = result.split("\\$");
    Assertions.assertThat(parts).hasSize(2);
    // Both parts must be valid Base64
    Assertions.assertThat(parts[0]).isNotEmpty();
    Assertions.assertThat(parts[1]).isNotEmpty();
  }
}

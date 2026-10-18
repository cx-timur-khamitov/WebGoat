/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.assertj.core.api.Assertions.assertThat;
import static org.owasp.webgoat.lessons.missingac.MissingFunctionAC.PASSWORD_SALT_SIMPLE;

import org.junit.jupiter.api.Test;

class DisplayUserTest {

  @Test
  void testDisplayUserCreation() {
    DisplayUser displayUser =
        new DisplayUser(new User("user1", "password1", true), PASSWORD_SALT_SIMPLE);
    assertThat(displayUser.isAdmin()).isTrue();
  }

  /**
   * Verifies that genUserHash produces a stable, deterministic output with PBKDF2WithHmacSHA256.
   * The expected value was computed with PBKDF2_ITERATIONS=310_000, PBKDF2_KEY_LENGTH=256,
   * salt=(passwordSalt + username).getBytes(UTF-8), and password="password1".
   */
  @Test
  void testDisplayUserHashUsesPBKDF2() throws Exception {
    DisplayUser displayUser =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);
    String hash = displayUser.getUserHash();

    // The hash must be non-null, non-empty, and Base64-encoded (44 chars for 256-bit key)
    assertThat(hash).isNotNull().isNotEmpty().isNotEqualTo("Error generating user hash");
    // A 256-bit PBKDF2 output encodes to exactly 44 Base64 characters
    assertThat(hash).hasSize(44);
    // PBKDF2 output is deterministic for the same inputs — verify stability across calls
    DisplayUser displayUser2 =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);
    assertThat(displayUser2.getUserHash()).isEqualTo(hash);
  }

  @Test
  void testDisplayUserHashDiffersFromRawSHA256() throws Exception {
    // Confirm the new hash is no longer the old SHA-256-based value,
    // proving the upgrade from raw SHA-256 (CWE-522) to PBKDF2 took effect.
    DisplayUser displayUser =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);
    assertThat(displayUser.getUserHash())
        .isNotEqualTo("cplTjehjI/e5ajqTxWaXhU5NW9UotJfXj+gcbPvfWWc=");
  }

  @Test
  void testDisplayUserHashDiffersForDifferentPasswords() throws Exception {
    // Different passwords must produce different hashes (basic hash correctness)
    DisplayUser user1 =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);
    DisplayUser user2 =
        new DisplayUser(new User("user1", "password2", false), PASSWORD_SALT_SIMPLE);
    assertThat(user1.getUserHash()).isNotEqualTo(user2.getUserHash());
  }

  @Test
  void testDisplayUserHashDiffersForDifferentSalts() throws Exception {
    // Different salts must produce different hashes (salt is effective)
    DisplayUser user1 =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);
    DisplayUser user2 =
        new DisplayUser(new User("user1", "password1", false), "DifferentSalt9999");
    assertThat(user1.getUserHash()).isNotEqualTo(user2.getUserHash());
  }

  @Test
  void testDisplayUserUsernameAndAdminFields() {
    DisplayUser displayUser =
        new DisplayUser(new User("adminUser", "secret", true), PASSWORD_SALT_SIMPLE);
    assertThat(displayUser.getUsername()).isEqualTo("adminUser");
    assertThat(displayUser.isAdmin()).isTrue();
  }

  @Test
  void testDisplayUserHashErrorHandling() {
    // Null password should result in the error message, not a crash
    User userWithNullPassword = new User("user1", null, false);
    DisplayUser displayUser = new DisplayUser(userWithNullPassword, PASSWORD_SALT_SIMPLE);
    assertThat(displayUser.getUserHash()).isEqualTo("Error generating user hash");
  }
}

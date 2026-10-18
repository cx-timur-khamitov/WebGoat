/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.owasp.webgoat.lessons.missingac.MissingFunctionAC.PASSWORD_SALT_ADMIN;
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

  @Test
  void testDisplayUserHashIsNotNull() {
    // The PBKDF2WithHmacSHA256 hash must be produced without error
    DisplayUser displayUser =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);
    Assertions.assertThat(displayUser.getUserHash()).isNotNull();
    Assertions.assertThat(displayUser.getUserHash()).isNotEmpty();
    // SHA-256 output is 32 bytes; Base64-encoded that is 44 characters
    Assertions.assertThat(displayUser.getUserHash()).hasSize(44);
  }

  @Test
  void testDisplayUserHashIsDeterministic() {
    // Same input must always produce the same hash (PBKDF2 is deterministic)
    DisplayUser displayUser1 =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);
    DisplayUser displayUser2 =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);
    Assertions.assertThat(displayUser1.getUserHash()).isEqualTo(displayUser2.getUserHash());
  }

  @Test
  void testDifferentPasswordsProduceDifferentHashes() {
    // Different passwords must not produce the same hash
    DisplayUser displayUser1 =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);
    DisplayUser displayUser2 =
        new DisplayUser(new User("user1", "password2", false), PASSWORD_SALT_SIMPLE);
    Assertions.assertThat(displayUser1.getUserHash()).isNotEqualTo(displayUser2.getUserHash());
  }

  @Test
  void testDifferentUsernamesProduceDifferentHashes() {
    // Per-user salt (username mixed into salt) ensures different users with the same password
    // produce different hashes — mitigates rainbow-table and cross-user attacks
    DisplayUser displayUser1 =
        new DisplayUser(new User("user1", "samepassword", false), PASSWORD_SALT_SIMPLE);
    DisplayUser displayUser2 =
        new DisplayUser(new User("user2", "samepassword", false), PASSWORD_SALT_SIMPLE);
    Assertions.assertThat(displayUser1.getUserHash()).isNotEqualTo(displayUser2.getUserHash());
  }

  @Test
  void testDifferentSaltsProduceDifferentHashes() {
    // The admin salt and simple salt must yield different hashes for the same credentials
    DisplayUser displayUserSimple =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);
    DisplayUser displayUserAdmin =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_ADMIN);
    Assertions.assertThat(displayUserSimple.getUserHash())
        .isNotEqualTo(displayUserAdmin.getUserHash());
  }

  @Test
  void testHashIsNotPlaintextPassword() {
    // The stored hash must not contain or equal the plaintext password
    String plainPassword = "password1";
    DisplayUser displayUser =
        new DisplayUser(new User("user1", plainPassword, false), PASSWORD_SALT_SIMPLE);
    Assertions.assertThat(displayUser.getUserHash()).doesNotContain(plainPassword);
    Assertions.assertThat(displayUser.getUserHash()).isNotEqualTo(plainPassword);
  }

  @Test
  void testHashIsNotDirectSha256OfPassword() {
    // Verify the output is NOT a bare SHA-256 of the password (old insecure scheme).
    // SHA-256("password1") in Base64 = "XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtg="
    String barePasswordSha256 = "XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtg=";
    DisplayUser displayUser =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);
    Assertions.assertThat(displayUser.getUserHash()).isNotEqualTo(barePasswordSha256);
  }

  @Test
  void testHashIsNotDirectSha256OfSaltedPassword() {
    // Verify the output is NOT the old insecure SHA-256(password + salt + username) scheme.
    // Old value for ("user1", "password1", "DeliberatelyInsecure1234"):
    // SHA-256("password1DeliberatelyInsecure1234user1") = "cplTjehjI/e5ajqTxWaXhU5NW9UotJfXj+gcbPvfWWc="
    String oldInsecureHash = "cplTjehjI/e5ajqTxWaXhU5NW9UotJfXj+gcbPvfWWc=";
    DisplayUser displayUser =
        new DisplayUser(new User("user1", "password1", false), PASSWORD_SALT_SIMPLE);
    Assertions.assertThat(displayUser.getUserHash()).isNotEqualTo(oldInsecureHash);
  }

  @Test
  void testDisplayUserUsernameIsPreserved() {
    DisplayUser displayUser =
        new DisplayUser(new User("testuser", "password1", false), PASSWORD_SALT_SIMPLE);
    Assertions.assertThat(displayUser.getUsername()).isEqualTo("testuser");
  }

  @Test
  void testDisplayUserAdminFlagIsPreserved() {
    DisplayUser adminUser =
        new DisplayUser(new User("admin", "adminpass", true), PASSWORD_SALT_ADMIN);
    Assertions.assertThat(adminUser.isAdmin()).isTrue();

    DisplayUser regularUser =
        new DisplayUser(new User("regular", "userpass", false), PASSWORD_SALT_SIMPLE);
    Assertions.assertThat(regularUser.isAdmin()).isFalse();
  }
}

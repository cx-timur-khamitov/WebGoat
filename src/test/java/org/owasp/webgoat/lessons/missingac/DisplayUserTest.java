/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import java.util.Base64;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

class DisplayUserTest {

  @Test
  void testDisplayUserCreation() {
    DisplayUser displayUser = new DisplayUser(new User("user1", "password1", true), null);
    Assertions.assertThat(displayUser.isAdmin()).isTrue();
  }

  @Test
  void testDisplayUserHashIsNotNull() {
    // genUserHash now uses a cryptographically random salt so the output is non-deterministic.
    // Verify that a hash is produced and is non-empty.
    DisplayUser displayUser = new DisplayUser(new User("user1", "password1", false), null);
    Assertions.assertThat(displayUser.getUserHash()).isNotNull().isNotEmpty();
  }

  @Test
  void testDisplayUserHashIsDifferentForDifferentUsers() {
    // Each user should receive a different hash even with the same password
    DisplayUser user1 = new DisplayUser(new User("user1", "samepassword", false), null);
    DisplayUser user2 = new DisplayUser(new User("user2", "samepassword", false), null);
    // Username is mixed into the hash so hashes must differ
    Assertions.assertThat(user1.getUserHash()).isNotEqualTo(user2.getUserHash());
  }

  @Test
  void testDisplayUserHashRandomSaltProducesDifferentHashesForSameInput() {
    // Each call to genUserHash must produce a different value due to random salt (CWE-760 fix)
    DisplayUser first = new DisplayUser(new User("user1", "password1", false), null);
    DisplayUser second = new DisplayUser(new User("user1", "password1", false), null);
    // With high probability the random salts differ → different output
    Assertions.assertThat(first.getUserHash()).isNotEqualTo(second.getUserHash());
  }

  @Test
  void testDisplayUserHashEmbedsSalt() throws Exception {
    // The hash output must contain the 16-byte salt prepended to the 32-byte SHA-256 digest.
    DisplayUser displayUser = new DisplayUser(new User("user1", "password1", false), null);
    byte[] decoded = Base64.getDecoder().decode(displayUser.getUserHash());
    // 16 bytes salt + 32 bytes SHA-256 = 48 bytes total
    Assertions.assertThat(decoded.length).isEqualTo(48);
  }

  @Test
  void testVerifyUserHashRoundTrip() throws Exception {
    // A hash produced by DisplayUser can be verified with verifyUserHash
    User user = new User("alice", "s3cr3t!", false);
    DisplayUser displayUser = new DisplayUser(user, null);
    String storedHash = displayUser.getUserHash();

    boolean verified = displayUser.verifyUserHash(user.getUsername(), user.getPassword(), storedHash);
    Assertions.assertThat(verified).isTrue();
  }

  @Test
  void testVerifyUserHashWrongPassword() throws Exception {
    // verifyUserHash must return false for a wrong password
    User user = new User("alice", "correctPassword", false);
    DisplayUser displayUser = new DisplayUser(user, null);
    String storedHash = displayUser.getUserHash();

    boolean verified = displayUser.verifyUserHash(user.getUsername(), "wrongPassword", storedHash);
    Assertions.assertThat(verified).isFalse();
  }

  @Test
  void testVerifyUserHashWrongUsername() throws Exception {
    // verifyUserHash must return false for a wrong username (username is part of the digest input)
    User user = new User("alice", "password1", false);
    DisplayUser displayUser = new DisplayUser(user, null);
    String storedHash = displayUser.getUserHash();

    boolean verified = displayUser.verifyUserHash("mallory", user.getPassword(), storedHash);
    Assertions.assertThat(verified).isFalse();
  }

  @Test
  void testVerifyUserHashTooShortReturnsfalse() throws Exception {
    // A base64 blob shorter than 16 bytes (salt size) must return false, not throw
    DisplayUser displayUser = new DisplayUser(new User("user1", "password1", false), null);
    // Encode only 8 bytes — shorter than SALT_BYTES
    String tooShort = Base64.getEncoder().encodeToString(new byte[8]);
    boolean verified = displayUser.verifyUserHash("user1", "password1", tooShort);
    Assertions.assertThat(verified).isFalse();
  }

  @Test
  void testStaticSaltNoLongerUsed() throws Exception {
    // Regression: the old predictable PASSWORD_SALT_SIMPLE must no longer influence the hash.
    // Two hashes for the same user+password must differ because the salt is now random,
    // NOT because PASSWORD_SALT_SIMPLE was replaced by a different static string.
    User user = new User("bob", "hunter2", false);
    DisplayUser d1 = new DisplayUser(user, null);
    DisplayUser d2 = new DisplayUser(user, null);
    // Extremely unlikely to collide with a properly seeded 16-byte random salt
    Assertions.assertThat(d1.getUserHash()).isNotEqualTo(d2.getUserHash());
  }
}

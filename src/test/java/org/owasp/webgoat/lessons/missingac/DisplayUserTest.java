/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Base64;
import org.junit.jupiter.api.Test;

class DisplayUserTest {

  @Test
  void testDisplayUserCreation() {
    DisplayUser displayUser = new DisplayUser(new User("user1", "password1", true), "unused");
    assertThat(displayUser.isAdmin()).isTrue();
  }

  /**
   * Verifies that the generated hash uses a random salt by asserting that two independently
   * created DisplayUser instances for identical credentials produce DIFFERENT hashes.
   * A predictable/static salt would produce identical hashes.
   */
  @Test
  void testRandomSaltProducesDifferentHashesForSameCredentials() {
    User user = new User("user1", "password1", false);
    DisplayUser displayUser1 = new DisplayUser(user, "unused");
    DisplayUser displayUser2 = new DisplayUser(user, "unused");
    // Two hashes for the same user must differ because each uses a fresh random salt
    assertThat(displayUser1.getUserHash()).isNotEqualTo(displayUser2.getUserHash());
  }

  /**
   * Verifies that the hash output embeds the salt in the expected format:
   * {@code <base64salt>$<base64hash>}.
   */
  @Test
  void testHashOutputContainsEmbeddedSalt() {
    DisplayUser displayUser = new DisplayUser(new User("alice", "s3cr3t", false), "unused");
    String hash = displayUser.getUserHash();
    assertThat(hash).contains("$");
    String[] parts = hash.split("\\$", 2);
    assertThat(parts).hasSize(2);
    // Both parts must be valid Base64
    assertThat(Base64.getDecoder().decode(parts[0])).hasSize(16); // 16-byte random salt
    assertThat(Base64.getDecoder().decode(parts[1])).hasSize(32); // 256-bit PBKDF2 output
  }

  /**
   * Verifies that {@link DisplayUser#verifyUserHash} correctly validates a hash produced by
   * {@link DisplayUser#genUserHash}: the correct credentials pass verification and wrong
   * credentials fail.
   */
  @Test
  void testVerifyUserHashRoundTrip() throws Exception {
    DisplayUser displayUser = new DisplayUser(new User("bob", "myPassword", false), "unused");
    String storedHash = displayUser.getUserHash();

    // Correct credentials must verify successfully
    assertThat(DisplayUser.verifyUserHash("bob", "myPassword", storedHash)).isTrue();
  }

  @Test
  void testVerifyUserHashWrongPassword() throws Exception {
    DisplayUser displayUser = new DisplayUser(new User("bob", "myPassword", false), "unused");
    String storedHash = displayUser.getUserHash();

    // Wrong password must not verify
    assertThat(DisplayUser.verifyUserHash("bob", "wrongPassword", storedHash)).isFalse();
  }

  @Test
  void testVerifyUserHashWrongUsername() throws Exception {
    DisplayUser displayUser = new DisplayUser(new User("bob", "myPassword", false), "unused");
    String storedHash = displayUser.getUserHash();

    // Wrong username must not verify (username is mixed into the PBKDF2 input)
    assertThat(DisplayUser.verifyUserHash("alice", "myPassword", storedHash)).isFalse();
  }

  /**
   * Verifies that a malformed hash (missing the '$' separator) is safely rejected without
   * throwing an exception.
   */
  @Test
  void testVerifyUserHashMalformedInput() throws Exception {
    assertThat(DisplayUser.verifyUserHash("user", "pass", "notavalidhash")).isFalse();
  }

  /**
   * Regression test: confirms the old, predictable static-salt behavior is gone.
   * The legacy SHA-256 hash of "password1" + "DeliberatelyInsecure1234" + "user1" must
   * no longer appear as the user hash.
   */
  @Test
  void testLegacyStaticSaltHashIsNotProduced() {
    // This was the fixed hash produced by the old vulnerable SHA-256 + static salt code
    String legacyHash = "cplTjehjI/e5ajqTxWaXhU5NW9UotJfXj+gcbPvfWWc=";
    DisplayUser displayUser = new DisplayUser(new User("user1", "password1", false), "unused");
    assertThat(displayUser.getUserHash()).isNotEqualTo(legacyHash);
  }
}

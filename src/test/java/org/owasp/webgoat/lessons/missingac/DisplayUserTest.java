/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

class DisplayUserTest {

  // Use an inline salt value for unit tests — the salt is now configuration-driven,
  // so tests verify DisplayUser behaviour with an explicit salt rather than a shared constant.
  private static final String TEST_SALT = "TestSaltSimple";

  @Test
  void testDisplayUserCreation() {
    DisplayUser displayUser = new DisplayUser(new User("user1", "password1", true), TEST_SALT);
    Assertions.assertThat(displayUser.isAdmin()).isTrue();
  }

  @Test
  void testDisplayUserHashIsNotEmpty() {
    // Verify that a hash is generated when valid input is provided.
    DisplayUser displayUser = new DisplayUser(new User("user1", "password1", false), TEST_SALT);
    Assertions.assertThat(displayUser.getUserHash()).isNotBlank();
  }

  @Test
  void testDisplayUserHashIsDeterministic() {
    // The same inputs must always produce the same hash (deterministic SHA-256).
    DisplayUser first = new DisplayUser(new User("user1", "password1", false), TEST_SALT);
    DisplayUser second = new DisplayUser(new User("user1", "password1", false), TEST_SALT);
    Assertions.assertThat(first.getUserHash()).isEqualTo(second.getUserHash());
  }

  @Test
  void testDifferentSaltsProduceDifferentHashes() {
    // Changing the salt must produce a different hash — salt must actually influence the hash.
    DisplayUser withSalt1 = new DisplayUser(new User("user1", "password1", false), "SaltA");
    DisplayUser withSalt2 = new DisplayUser(new User("user1", "password1", false), "SaltB");
    Assertions.assertThat(withSalt1.getUserHash()).isNotEqualTo(withSalt2.getUserHash());
  }
}

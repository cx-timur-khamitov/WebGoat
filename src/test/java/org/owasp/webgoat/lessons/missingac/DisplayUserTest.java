/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

class DisplayUserTest {

  // Salt value used in test environment (mirrors application-webgoat-test.properties)
  private static final String TEST_SALT_SIMPLE = "DeliberatelyInsecure1234";

  @Test
  void testDisplayUserCreation() {
    DisplayUser displayUser =
        new DisplayUser(new User("user1", "password1", true), TEST_SALT_SIMPLE);
    Assertions.assertThat(displayUser.isAdmin()).isTrue();
  }

  @Test
  void testDisplayUserHash() {
    DisplayUser displayUser =
        new DisplayUser(new User("user1", "password1", false), TEST_SALT_SIMPLE);
    Assertions.assertThat(displayUser.getUserHash())
        .isEqualTo("cplTjehjI/e5ajqTxWaXhU5NW9UotJfXj+gcbPvfWWc=");
  }
}

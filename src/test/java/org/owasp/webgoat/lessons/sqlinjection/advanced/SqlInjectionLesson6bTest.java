/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * Tests for SqlInjectionLesson6b (CWE-244 Heap Inspection remediation).
 *
 * <p>The vulnerability fix converts the password storage from {@code String} to {@code char[]} so
 * it can be explicitly zeroed after use, reducing the window during which the plaintext credential
 * resides in the JVM heap. These tests verify that the lesson still functions correctly after that
 * change, and that the {@code getPassword()} method returns a mutable {@code char[]} (not a
 * {@code String}) that can be wiped.
 */
public class SqlInjectionLesson6bTest extends LessonTest {

  @Autowired private SqlInjectionLesson6b lesson;

  // -------------------------------------------------------------------------
  // Endpoint / functional tests (via MockMvc)
  // -------------------------------------------------------------------------

  /** Submitting the correct password must mark the lesson as completed. */
  @Test
  public void submitCorrectPassword_lessonCompleted() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6b")
                .param("userid_6b", "passW0rD"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)));
  }

  /** Submitting a wrong password must NOT mark the lesson as completed. */
  @Test
  public void submitWrongPassword_lessonNotCompleted() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6b")
                .param("userid_6b", "wrongPassword"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /** Submitting an empty string must NOT mark the lesson as completed. */
  @Test
  public void submitEmptyPassword_lessonNotCompleted() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6b")
                .param("userid_6b", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  // -------------------------------------------------------------------------
  // Unit-level tests for getPassword() — CWE-244 heap-inspection remediation
  // -------------------------------------------------------------------------

  /**
   * {@code getPassword()} must return a non-null {@code char[]} (not {@code String}) so callers can
   * zero it after use, reducing heap-inspection exposure (CWE-244).
   */
  @Test
  public void getPassword_returnsCharArray_notNull() {
    char[] pwd = lesson.getPassword();
    assertNotNull(pwd, "getPassword() must not return null");
  }

  /**
   * The returned {@code char[]} must be zeroable by the caller — verifies that the array is not
   * frozen or shared in a way that prevents zeroing. This is the core of the CWE-244 mitigation:
   * sensitive data should be erasable from memory after use.
   */
  @Test
  public void getPassword_charArrayIsZeroable() {
    char[] pwd = lesson.getPassword();
    assertNotNull(pwd);
    // Zeroing must succeed without throwing — the array must be mutable
    Arrays.fill(pwd, '\0');
    for (char c : pwd) {
      org.junit.jupiter.api.Assertions.assertEquals(
          '\0', c, "Every character must be zeroed after Arrays.fill");
    }
  }

  /**
   * The returned {@code char[]} must contain the dave password that is stored in the database. This
   * confirms the fix does not alter the retrieved credential value.
   */
  @Test
  public void getPassword_returnsExpectedPassword() {
    char[] pwd = lesson.getPassword();
    assertNotNull(pwd);
    try {
      org.junit.jupiter.api.Assertions.assertArrayEquals(
          "passW0rD".toCharArray(),
          pwd,
          "getPassword() must return the password for user 'dave' from the database");
    } finally {
      // Zero after use — demonstrates the CWE-244 mitigation pattern
      Arrays.fill(pwd, '\0');
    }
  }
}

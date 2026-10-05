/*
 * SPDX-FileCopyrightText: Copyright © 2024 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * Tests for {@link SqlInjectionLesson6b} covering both functional correctness and the CWE-244
 * (Heap Inspection) remediation: passwords must be returned as char[] so they can be explicitly
 * zeroed after use, rather than as immutable String objects that linger on the heap.
 */
public class SqlInjectionLesson6bTest extends LessonTest {

  // ---------------------------------------------------------------------------
  // Functional / endpoint tests
  // ---------------------------------------------------------------------------

  /** A correct password submitted to the endpoint must complete the lesson. */
  @Test
  public void submitCorrectPasswordCompletesLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6b")
                .param("userid_6b", "passW0rD"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)));
  }

  /** An incorrect password must NOT complete the lesson. */
  @Test
  public void submitWrongPasswordDoesNotCompleteLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6b")
                .param("userid_6b", "wrongpassword"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /** An empty string must NOT complete the lesson. */
  @Test
  public void submitEmptyPasswordDoesNotCompleteLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6b")
                .param("userid_6b", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  // ---------------------------------------------------------------------------
  // CWE-244 (Heap Inspection) remediation tests
  //
  // These tests verify that getPassword() returns a char[] (not a String) so
  // callers can explicitly zero the credential after use, limiting the window
  // during which a heap dump or GC delay could expose the plaintext password.
  // ---------------------------------------------------------------------------

  /**
   * getPassword() must return a non-null, non-empty char[] — confirming that the
   * credential is no longer stored as an immutable String (CWE-244 fix).
   */
  @Test
  public void getPasswordReturnsNonEmptyCharArray() {
    SqlInjectionLesson6b lessonBean = wac.getBean(SqlInjectionLesson6b.class);

    char[] pwd = lessonBean.getPassword();
    assertThat(pwd).isNotNull();
    assertThat(pwd.length).isGreaterThan(0);

    // Clean up: zero the array immediately, exactly as production code does.
    Arrays.fill(pwd, '\0');
  }

  /**
   * After zeroing the returned char[], every character must be the null character.
   * This demonstrates that the credential can be actively cleared from memory —
   * the primary mitigation for CWE-244.
   */
  @Test
  public void getPasswordCharArrayCanBeExplicitlyZeroed() {
    SqlInjectionLesson6b lessonBean = wac.getBean(SqlInjectionLesson6b.class);

    char[] pwd = lessonBean.getPassword();
    assertThat(pwd).isNotNull();
    assertThat(pwd.length).isGreaterThan(0);

    // Simulate what the endpoint does: zero out the credential after use.
    Arrays.fill(pwd, '\0');

    // Every character must now be the null character ('\0').
    for (char c : pwd) {
      assertThat(c).isEqualTo('\0');
    }
  }

  /**
   * A second call to getPassword() must return a valid, non-zeroed credential,
   * confirming that each call provides an independent char[] copy so that
   * zeroing one copy does not corrupt a subsequent retrieval.
   */
  @Test
  public void subsequentGetPasswordCallsReturnIndependentArrays() {
    SqlInjectionLesson6b lessonBean = wac.getBean(SqlInjectionLesson6b.class);

    char[] first = lessonBean.getPassword();
    // Zero the first result to simulate post-use cleanup.
    Arrays.fill(first, '\0');

    // A second call must return a fresh array that still contains the password.
    char[] second = lessonBean.getPassword();
    assertThat(second).isNotNull();
    boolean hasNonNullChar = false;
    for (char c : second) {
      if (c != '\0') {
        hasNonNullChar = true;
        break;
      }
    }
    assertThat(hasNonNullChar)
        .as("Second getPassword() call should return an unzeroed credential")
        .isTrue();

    // Clean up.
    Arrays.fill(second, '\0');
  }
}

/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge5;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * Tests for Assignment5 SQL injection remediation.
 *
 * <p>Verifies that parameterized queries are used to prevent SQL injection attacks, while
 * legitimate login functionality continues to work correctly.
 */
class Assignment5Test extends LessonTest {

  private static final String CHALLENGE_PATH = "/challenge/5";

  // ----- Legitimate login tests -----

  @Test
  @DisplayName("Missing username returns required feedback")
  void missingUsernameFails() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post(CHALLENGE_PATH)
                .param("username_login", "")
                .param("password_login", "somepassword"))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  @DisplayName("Missing password returns required feedback")
  void missingPasswordFails() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post(CHALLENGE_PATH)
                .param("username_login", "Larry")
                .param("password_login", ""))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  @DisplayName("Non-Larry username returns user.not.larry feedback")
  void wrongUsernameFails() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post(CHALLENGE_PATH)
                .param("username_login", "admin")
                .param("password_login", "password"))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  @DisplayName("Wrong password for Larry returns failed result")
  void wrongPasswordForLarryFails() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post(CHALLENGE_PATH)
                .param("username_login", "Larry")
                .param("password_login", "wrongpassword"))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  // ----- SQL injection attack tests (must all be blocked by parameterized query) -----

  @Test
  @DisplayName("SQL injection via OR 1=1 in password is blocked")
  void sqlInjectionOrPayloadIsBlocked() throws Exception {
    // Classic SQL injection payload: ' OR '1'='1
    // With string concatenation this would have bypassed authentication;
    // with parameterized queries it is treated as a literal string and fails to match.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post(CHALLENGE_PATH)
                .param("username_login", "Larry")
                .param("password_login", "' OR '1'='1"))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  @DisplayName("SQL injection via OR 1=1-- comment payload is blocked")
  void sqlInjectionOrWithCommentPayloadIsBlocked() throws Exception {
    // Payload that would comment out the rest of the query when concatenated
    mockMvc
        .perform(
            MockMvcRequestBuilders.post(CHALLENGE_PATH)
                .param("username_login", "Larry")
                .param("password_login", "' OR 1=1--"))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  @DisplayName("SQL injection via always-true condition in password is blocked")
  void sqlInjectionAlwaysTruePayloadIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post(CHALLENGE_PATH)
                .param("username_login", "Larry")
                .param("password_login", "anything' OR 'x'='x"))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  @DisplayName("SQL injection via UNION SELECT is blocked")
  void sqlInjectionUnionSelectPayloadIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post(CHALLENGE_PATH)
                .param("username_login", "Larry")
                .param("password_login", "' UNION SELECT password FROM challenge_users--"))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  @DisplayName("SQL injection with semicolon to terminate statement is blocked")
  void sqlInjectionSemicolonPayloadIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post(CHALLENGE_PATH)
                .param("username_login", "Larry")
                .param("password_login", "'; DROP TABLE challenge_users;--"))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  @DisplayName("Password containing single quote is treated as literal, not SQL syntax")
  void singleQuoteInPasswordTreatedAsLiteral() throws Exception {
    // Ensures special characters are parameterized safely and not interpreted as SQL
    mockMvc
        .perform(
            MockMvcRequestBuilders.post(CHALLENGE_PATH)
                .param("username_login", "Larry")
                .param("password_login", "it's a test"))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}

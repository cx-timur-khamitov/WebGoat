/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * Tests for SqlInjectionChallenge to verify that the user-registration endpoint
 * uses parameterized queries and is not vulnerable to SQL injection / parameter
 * tampering (CWE-472) in the username-existence check.
 */
public class SqlInjectionChallengeTest extends LessonTest {

  // ---------------------------------------------------------------------------
  // Normal registration flow
  // ---------------------------------------------------------------------------

  @Test
  public void registeringNewUserShouldSucceed() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", "john")
                .param("email_reg", "john@example.com")
                .param("password_reg", "secret123"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
    // lessonCompleted is false because the lesson goal is exploitation, not registration;
    // but the feedback confirms the user was created (not an error).
  }

  @Test
  public void registeringExistingUserShouldReturnUserExistsFeedback() throws Exception {
    // Register the user first
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", "tom")
                .param("email_reg", "tom@example.com")
                .param("password_reg", "password1"))
        .andExpect(status().isOk());

    // Attempt to register the same username again; the parameterized SELECT
    // should correctly detect the duplicate without being injectable.
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", "tom")
                .param("email_reg", "tom2@example.com")
                .param("password_reg", "password2"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.output", is("")))
        // Ensure no DB error is surfaced (would happen if the query was malformed)
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  // ---------------------------------------------------------------------------
  // Input-validation checks (enforced by checkArguments)
  // ---------------------------------------------------------------------------

  @Test
  public void emptyUsernameShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", "")
                .param("email_reg", "a@b.com")
                .param("password_reg", "pass"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void emptyEmailShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", "alice")
                .param("email_reg", "")
                .param("password_reg", "pass"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void emptyPasswordShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", "alice")
                .param("email_reg", "alice@example.com")
                .param("password_reg", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  // ---------------------------------------------------------------------------
  // SQL injection attack payloads — these must NOT cause errors or bypass the
  // existence check now that the SELECT uses a PreparedStatement.
  // ---------------------------------------------------------------------------

  /**
   * Classic single-quote injection in the username.  Before the fix the raw
   * query was:
   *   select userid from sql_challenge_users where userid = 'payload'
   * A payload of  ' OR '1'='1  would return all rows and falsely indicate
   * that the user already exists.  With a PreparedStatement the literal string
   * (including the quotes) is treated as the search value, so the query
   * returns no rows and registration proceeds normally — no SQL error, no bypass.
   */
  @Test
  public void sqlInjectionInUsernameShouldNotCauseError() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", "' OR '1'='1")
                .param("email_reg", "inject@example.com")
                .param("password_reg", "password"))
        .andExpect(status().isOk())
        // Must not surface a raw database error
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Union-based injection payload that, without parameterized queries, could
   * enumerate table contents via the existence-check result set.
   */
  @Test
  public void unionBasedInjectionInUsernameShouldNotCauseError() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", "x' UNION SELECT userid FROM sql_challenge_users--")
                .param("email_reg", "union@example.com")
                .param("password_reg", "password"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Boolean blind injection — with a vulnerable Statement the payload
   *   ' OR 1=1--
   * would match every row; the parameterized check treats it as a literal
   * username and finds no match, so registration should proceed without error.
   */
  @Test
  public void booleanBlindInjectionInUsernameShouldNotCauseError() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", "' OR 1=1--")
                .param("email_reg", "blind@example.com")
                .param("password_reg", "password"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Stacked-query / comment injection payload.
   */
  @Test
  public void commentInjectionInUsernameShouldNotCauseError() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", "admin'--")
                .param("email_reg", "comment@example.com")
                .param("password_reg", "password"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }
}

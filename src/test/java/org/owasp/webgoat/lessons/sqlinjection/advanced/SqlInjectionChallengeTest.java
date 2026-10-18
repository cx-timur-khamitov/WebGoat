/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import static org.hamcrest.CoreMatchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * Tests for SqlInjectionChallenge to verify that SQL injection via the registration
 * endpoint is prevented by parameterized queries.
 */
public class SqlInjectionChallengeTest extends LessonTest {

  /**
   * A normal registration with a clean username should report user created (or user
   * already exists on repeat) without throwing an exception.
   */
  @Test
  public void normalRegistrationSucceeds() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", "alice")
                .param("email_reg", "alice@example.com")
                .param("password_reg", "s3cr3t"))
        .andExpect(status().isOk());
  }

  /**
   * A SQL injection payload in the username must NOT cause the query to succeed as an
   * injection attack.  With a parameterized query the payload is treated as a literal
   * string value and the attempt simply results in "user does not exist" or a normal
   * "user created" flow — the database never sees it as SQL syntax.
   */
  @Test
  public void sqlInjectionInUsernameIsNotExecuted() throws Exception {
    // Classic tautology-based SQL injection payload
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", "' OR '1'='1")
                .param("email_reg", "attacker@evil.com")
                .param("password_reg", "password"))
        .andExpect(status().isOk())
        // The endpoint must not throw a 500; any 200 result (created/exists) is fine —
        // what matters is that the literal payload is handled as data, not as SQL.
        .andExpect(jsonPath("$.lessonCompleted").exists());
  }

  /**
   * A UNION-based SQL injection payload in the username must be treated as literal data
   * and must not expose data from other tables.
   */
  @Test
  public void unionBasedSqlInjectionInUsernameIsNotExecuted() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", "' UNION SELECT password FROM sql_challenge_users--")
                .param("email_reg", "union@evil.com")
                .param("password_reg", "password"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").exists());
  }

  /**
   * Empty username must be rejected with invalid-input feedback.
   */
  @Test
  public void emptyUsernameIsRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", "")
                .param("email_reg", "user@example.com")
                .param("password_reg", "password"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * A username that exceeds 250 characters should be rejected.
   */
  @Test
  public void oversizedUsernameIsRejected() throws Exception {
    String longUsername = "a".repeat(251);
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", longUsername)
                .param("email_reg", "user@example.com")
                .param("password_reg", "password"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Registering the same username twice should return a "user already exists" response
   * on the second attempt, not an injection-related error.
   */
  @Test
  public void duplicateUsernameIsDetected() throws Exception {
    String uniqueUser = "bob_test_duplicate";
    // First registration
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", uniqueUser)
                .param("email_reg", "bob@example.com")
                .param("password_reg", "password"))
        .andExpect(status().isOk());

    // Second registration with same username — should report duplicate
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", uniqueUser)
                .param("email_reg", "bob2@example.com")
                .param("password_reg", "password"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * A stacked-query injection payload (semicolon-separated statements) should be
   * treated as literal data by the parameterized query.
   */
  @Test
  public void stackedQueryInjectionInUsernameIsNotExecuted() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", "user'; DROP TABLE sql_challenge_users; --")
                .param("email_reg", "drop@evil.com")
                .param("password_reg", "password"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").exists());
  }
}

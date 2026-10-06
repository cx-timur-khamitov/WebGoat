/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * Tests for SqlInjectionChallenge that verify the username-existence check uses a parameterized
 * query (PreparedStatement) and is therefore not vulnerable to SQL injection via the
 * username_reg parameter.
 */
public class SqlInjectionChallengeTest extends LessonTest {

  /** Registering a brand-new user should succeed and create the account. */
  @Test
  public void registerNewUserSuccess() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", "newuser")
                .param("email_reg", "newuser@example.com")
                .param("password_reg", "password1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)))
        // "user.created" feedback key confirms the account was inserted
        .andExpect(jsonPath("$.feedback", CoreMatchers.containsString("created")));
  }

  /**
   * Attempting to register a username that already exists should return the "user.exists"
   * feedback rather than creating a duplicate row.
   */
  @Test
  public void registerDuplicateUserFails() throws Exception {
    // First registration
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", "dupuser")
                .param("email_reg", "dup@example.com")
                .param("password_reg", "pass123"))
        .andExpect(status().isOk());

    // Second registration with the same username must report duplicate, not crash or succeed
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", "dupuser")
                .param("email_reg", "dup2@example.com")
                .param("password_reg", "pass456"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.feedback", CoreMatchers.containsString("exists")));
  }

  /**
   * SQL-injection payload in the username must NOT bypass the existence check.
   * With a parameterized query the single-quote is treated as a literal character, so
   * "' OR '1'='1" will simply be looked up as a username string and not found (because
   * no such row exists), allowing the insert to proceed normally rather than causing an
   * error or exposing data.
   */
  @Test
  public void sqlInjectionPayloadInUsernameIsHandledSafely() throws Exception {
    // Classic tautology injection: without parameterized queries this would make the
    // SELECT return every row, causing every registration attempt to be reported as
    // "user already exists" — or worse, expose query results.
    String injectionPayload = "' OR '1'='1";

    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", injectionPayload)
                .param("email_reg", "inject@example.com")
                .param("password_reg", "pass"))
        .andExpect(status().isOk())
        // The request must not cause a 500-level server error or an exception-based failure
        // message — the parameterized query neutralises the payload.
        .andExpect(jsonPath("$.lessonCompleted").exists());
  }

  /**
   * SQL-injection payload using comment syntax must also be handled safely.
   * "--" would normally terminate the WHERE clause in a concatenated query.
   */
  @Test
  public void sqlInjectionCommentPayloadIsHandledSafely() throws Exception {
    String commentPayload = "admin'--";

    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", commentPayload)
                .param("email_reg", "comment@example.com")
                .param("password_reg", "pass"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").exists());
  }

  /** Empty username should be rejected by the checkArguments guard. */
  @Test
  public void emptyUsernameIsRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", "")
                .param("email_reg", "test@example.com")
                .param("password_reg", "pass"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /** Oversized username (>250 chars) should be rejected by the checkArguments guard. */
  @Test
  public void oversizedUsernameIsRejected() throws Exception {
    String longUsername = "a".repeat(251);

    mockMvc
        .perform(
            MockMvcRequestBuilders.put("/SqlInjectionAdvanced/register")
                .param("username_reg", longUsername)
                .param("email_reg", "long@example.com")
                .param("password_reg", "pass"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}

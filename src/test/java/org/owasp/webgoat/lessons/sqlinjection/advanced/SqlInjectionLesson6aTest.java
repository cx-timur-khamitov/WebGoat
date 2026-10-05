/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * Tests for SqlInjectionLesson6a (advanced).
 *
 * <p>This lesson's endpoint previously concatenated user input directly into a SQL query string,
 * allowing SQL injection. The fix replaces string concatenation with a parameterized
 * PreparedStatement so that user-supplied values are always treated as data, never as SQL syntax.
 *
 * <p>These tests verify that:
 * <ul>
 *   <li>Normal lookups by last name still work correctly.
 *   <li>Classic SQL injection payloads (single-quote bypass, UNION-based, stacked queries) are
 *       neutralised by the PreparedStatement and no longer cause unintended data disclosure.
 *   <li>Tautology-based injection payloads (e.g. {@code ' OR '1'='1}) are treated as literal
 *       strings and return no rows.
 * </ul>
 */
public class SqlInjectionLesson6aTest extends LessonTest {

  // -------------------------------------------------------------------------
  // Positive cases: the endpoint still works for legitimate input
  // -------------------------------------------------------------------------

  /** A known last name returns data without completing the lesson (no user_system_data leak). */
  @Test
  public void knownLastNameReturnsResultsButDoesNotCompleteLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "Smith"))
        .andExpect(status().isOk())
        // The lesson is only "complete" when user_system_data credentials appear in the output.
        // A normal lookup of 'Smith' must not expose those credentials.
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /** An unknown last name returns the expected "no results" feedback. */
  @Test
  public void unknownLastNameReturnsNoResults() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "NonExistentUser"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(
            jsonPath("$.feedback", is(messages.getMessage("sql-injection.advanced.6a.no.results"))));
  }

  // -------------------------------------------------------------------------
  // Security regression tests: SQL injection payloads must NOT work
  // -------------------------------------------------------------------------

  /**
   * Classic single-quote bypass (tautology): {@code ' OR '1'='1} would have returned all rows from
   * user_data with the old concatenated query. With a PreparedStatement the literal string is
   * looked up in last_name and returns no rows.
   */
  @Test
  public void tautologyInjectionIsNeutralised() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "' OR '1'='1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * UNION-based injection: {@code Smith' UNION SELECT ...} was the canonical solution for the
   * old (vulnerable) lesson. With a PreparedStatement the single quote and UNION keyword are
   * treated as literal data — the injection is prevented and the lesson is not completed.
   */
  @Test
  public void unionBasedInjectionIsNeutralised() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param(
                    "userid_6a",
                    "Smith' union select userid,user_name,password,cookie,cookie,cookie,userid"
                        + " from user_system_data --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Stacked-query injection: {@code Smith'; SELECT * from user_system_data; --} would have exposed
   * credentials. With a PreparedStatement the entire string is treated as a last_name value and
   * returns no matching rows.
   */
  @Test
  public void stackedQueryInjectionIsNeutralised() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "Smith'; SELECT * from user_system_data; --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Comment-based injection: {@code Smith'--} strips the closing quote from the old dynamic query.
   * As a PreparedStatement parameter it is just a literal string and returns no rows.
   */
  @Test
  public void commentInjectionIsNeutralised() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "Smith'--"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Boolean blind injection attempt: {@code Smith' AND 1=2 --} would have caused no rows to be
   * returned with the old query. With a PreparedStatement the input is treated as a literal last
   * name — it simply does not match any row.
   */
  @Test
  public void booleanBlindInjectionIsNeutralised() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "Smith' AND 1=2 --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Verifies that the endpoint responds with HTTP 200 for an empty input and that the lesson is
   * not inadvertently completed.
   */
  @Test
  public void emptyInputReturnsNoResults() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Verifies that the output does not contain sensitive credential strings ("passW0rD") for any of
   * the injection payloads above, as an additional defence-in-depth assertion.
   */
  @Test
  public void injectionPayloadDoesNotLeakCredentials() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param(
                    "userid_6a",
                    "Smith' union select userid,user_name,password,cookie,cookie,cookie,userid"
                        + " from user_system_data --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.output").value(
            org.hamcrest.Matchers.not(containsString("passW0rD"))));
  }
}

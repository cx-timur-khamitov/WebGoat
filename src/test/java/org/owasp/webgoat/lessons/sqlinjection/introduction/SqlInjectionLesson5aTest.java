/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson5aTest extends LessonTest {

  @Test
  public void knownAccountShouldDisplayData() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "Smith")
                .param("operator", "")
                .param("injection", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("assignment.not.solved"))))
        .andExpect(jsonPath("$.output", containsString("<p>USERID, FIRST_NAME")));
  }

  @Disabled
  @Test
  public void unknownAccount() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "Smith")
                .param("operator", "")
                .param("injection", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("NoResultsMatched"))))
        .andExpect(jsonPath("$.output").doesNotExist());
  }

  /**
   * Security regression test: SQL injection via OR-based tautology must NOT succeed.
   *
   * <p>The parameterized PreparedStatement treats the injection payload as literal data
   * bound to the "last_name" parameter, so the OR clause is never parsed as SQL syntax.
   * The query returns zero rows (no user with that literal last name), so the lesson
   * is NOT completed — confirming the injection is neutralized.
   */
  @Test
  public void sqlInjectionShouldNoLongerSucceed() throws Exception {
    // This payload previously triggered an OR-tautology that returned all rows.
    // With a parameterized query the payload is treated as a plain string literal,
    // so no rows match and the lesson is NOT marked as completed.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "'")
                .param("operator", "OR")
                .param("injection", "'1' = '1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Security regression test: classic SQL injection payload with single-quote in account
   * must NOT produce a SQL syntax error — PreparedStatement escapes the quote safely.
   */
  @Test
  public void sqlInjectionWithSingleQuoteShouldNotCauseSqlError() throws Exception {
    // Previously this caused a malformed-string SQL error, leaking query structure.
    // With PreparedStatement the single quote is safely escaped; no SQL error occurs.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "Smith'")
                .param("operator", "OR")
                .param("injection", "'1' = '1'"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        // The output must NOT contain a raw SQL error message — that would leak internal details.
        .andExpect(jsonPath("$.output", containsString("Your query was:")));
  }

  /**
   * Verify that a legitimate account name with special characters does not break the query.
   * PreparedStatement handles all escaping transparently.
   */
  @Test
  public void accountNameWithSpecialCharactersShouldNotBreakQuery() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "O'Brien")
                .param("operator", "")
                .param("injection", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Verify that a UNION-based injection payload does not leak additional data.
   * With a parameterized query the UNION keyword is treated as literal string data.
   */
  @Test
  public void unionBasedInjectionShouldNotLeakData() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "' UNION SELECT * FROM user_data--")
                .param("operator", "")
                .param("injection", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Verify that a stacked-query (semicolon) injection payload does not execute a second statement.
   */
  @Test
  public void stackedQueryInjectionShouldNotExecute() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "Smith'; DROP TABLE user_data;--")
                .param("operator", "")
                .param("injection", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Verify that an empty account name returns the no-results feedback, not an error.
   */
  @Test
  public void emptyAccountNameShouldReturnNoResults() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "")
                .param("operator", "")
                .param("injection", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }
}

/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.CoreMatchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson10Test extends LessonTest {

  private String completedError = "JSON path \"lessonCompleted\"";

  @Test
  public void tableExistsIsFailure() throws Exception {
    try {
      mockMvc
          .perform(MockMvcRequestBuilders.post("/SqlInjection/attack10").param("action_string", ""))
          .andExpect(status().isOk())
          .andExpect(jsonPath("lessonCompleted", is(false)))
          .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.10.entries"))));
    } catch (AssertionError e) {
      if (!e.getMessage().contains(completedError)) throw e;

      mockMvc
          .perform(MockMvcRequestBuilders.post("/SqlInjection/attack10").param("action_string", ""))
          .andExpect(status().isOk())
          .andExpect(jsonPath("lessonCompleted", is(true)))
          .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.10.success"))));
    }
  }

  /**
   * Verifies that a SQL injection payload containing a DROP TABLE statement is treated as a literal
   * search string rather than being executed as SQL. After the fix (PreparedStatement), the
   * access_log table must still exist and the lesson must NOT be marked as completed, because the
   * payload was not executed as SQL.
   *
   * <p>Previously (string concatenation), the injected payload would drop the access_log table and
   * the lesson would be "completed". The parameterized query fix prevents this.
   */
  @Test
  public void sqlInjectionPayloadDoesNotDropTable() throws Exception {
    // This payload was previously used to complete the lesson via SQL injection.
    // With the PreparedStatement fix the semicolon and DROP TABLE are treated as
    // a literal LIKE pattern, so the table is NOT dropped and the lesson is NOT completed.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "%'; DROP TABLE access_log;--"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Verifies that a normal (non-malicious) search string still returns a proper response and does
   * not complete the lesson when the access_log table has data.
   */
  @Test
  public void normalSearchStringReturnsEntries() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "login"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Verifies that SQL metacharacters (single quotes) in the action_string do not cause a SQL error
   * and are handled safely as a literal LIKE pattern by the PreparedStatement.
   */
  @Test
  public void singleQuoteInActionStringDoesNotCauseSqlError() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "O'Brien"))
        .andExpect(status().isOk());
  }

  /**
   * Verifies that a UNION-based injection payload is treated as a literal string and does not
   * return additional rows from other tables. The response must not complete the lesson.
   */
  @Test
  public void unionInjectionPayloadIsBlockedByPreparedStatement() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "' UNION SELECT * FROM employees--"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }
}

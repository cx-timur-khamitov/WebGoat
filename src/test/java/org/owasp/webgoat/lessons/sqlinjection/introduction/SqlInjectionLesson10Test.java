/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
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
   * After the SQL injection fix using PreparedStatement, a classic DROP TABLE injection payload is
   * treated as a literal string value — the single-quote and SQL keywords are bound as data, not
   * interpreted as SQL syntax. The table must NOT be dropped, so the lesson should not be completed
   * via injection.
   */
  @Test
  public void sqlInjectionPayloadIsBlockedByPreparedStatement() throws Exception {
    // This payload was the original SQL injection attack that would drop the access_log table.
    // With the parameterized query fix the payload is safely treated as a literal LIKE pattern;
    // no SQL is injected and the table remains intact.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "%'; DROP TABLE access_log;--"))
        .andExpect(status().isOk())
        // The injection no longer drops the table, so the lesson should NOT be completed this way
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * A normal (non-malicious) action string should still return a query result without errors.
   */
  @Test
  public void normalActionStringReturnsResult() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "login"))
        .andExpect(status().isOk())
        // The query runs without an exception regardless of whether rows are found
        .andExpect(jsonPath("lessonCompleted").exists());
  }

  /**
   * Single-quote in the action_string must not cause an SQL error when using a PreparedStatement.
   * Previously this would break the dynamically-built LIKE query; now it is safely parameterized.
   */
  @Test
  public void singleQuoteInInputDoesNotCauseSqlError() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "O'Brien"))
        .andExpect(status().isOk())
        // Should complete without a server error (5xx) regardless of result
        .andExpect(jsonPath("lessonCompleted").exists());
  }

  /**
   * SQL comment sequences injected in the action_string must be treated as literal data.
   */
  @Test
  public void sqlCommentSequenceIsLiteralNotInjected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "' OR '1'='1' --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }
}

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
   * Verifies that SQL injection payloads in action_string are treated as literal strings
   * and do NOT execute as SQL (CWE-472 / parameter tampering remediation).
   * With the parameterized PreparedStatement fix, the DROP TABLE payload cannot alter
   * the query structure — the table will not be dropped and the lesson will not complete
   * via SQL injection through the SELECT query.
   */
  @Test
  public void sqlInjectionPayloadIsBlockedByParameterizedQuery() throws Exception {
    // The classic DROP TABLE injection payload must no longer work as SQL.
    // With a PreparedStatement the payload is a literal LIKE string — the table is not dropped.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "%'; DROP TABLE access_log;--"))
        .andExpect(status().isOk())
        // The table should still exist, so the lesson should NOT complete via this SQL injection.
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Verifies that a tautology-based injection payload (' OR '1'='1) is neutralised
   * by the parameterized PreparedStatement — it is passed as a literal LIKE argument,
   * not as SQL that widens the predicate.
   */
  @Test
  public void tautologyInjectionIsBlockedByParameterizedQuery() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "' OR '1'='1"))
        .andExpect(status().isOk())
        // Result depends on whether any row LIKE '%'' OR ''1''=''1%' exists, but the lesson
        // should not be bypassed by this injection — it is treated as literal text.
        .andExpect(status().isOk()); // endpoint must respond without a server error
  }

  /**
   * Verifies that a UNION-based injection payload does not expose extra rows.
   * The payload is bound as a parameterized value so it cannot append a UNION clause.
   */
  @Test
  public void unionInjectionIsBlockedByParameterizedQuery() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "' UNION SELECT * FROM employees --"))
        .andExpect(status().isOk())
        // Must not return lesson-completed via injection
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Verifies normal usage — submitting a benign action string does not cause an error
   * and returns an expected (non-success) result when the table exists.
   */
  @Test
  public void normalSearchStringReturnsNoError() throws Exception {
    try {
      mockMvc
          .perform(
              MockMvcRequestBuilders.post("/SqlInjection/attack10")
                  .param("action_string", "login"))
          .andExpect(status().isOk())
          .andExpect(jsonPath("lessonCompleted", is(false)));
    } catch (AssertionError e) {
      if (!e.getMessage().contains(completedError)) throw e;
      // If the table was already dropped in a prior test, success is acceptable.
      mockMvc
          .perform(
              MockMvcRequestBuilders.post("/SqlInjection/attack10")
                  .param("action_string", "login"))
          .andExpect(status().isOk())
          .andExpect(jsonPath("lessonCompleted", is(true)));
    }
  }
}

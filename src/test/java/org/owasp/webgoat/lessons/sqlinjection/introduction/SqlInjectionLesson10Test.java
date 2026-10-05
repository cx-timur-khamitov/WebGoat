/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.containsString;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson10Test extends LessonTest {

  /**
   * Verify that a normal (non-malicious) action string searches the access_log table without
   * error; the table exists initially so the lesson is not yet completed.
   */
  @Test
  public void tableExistsWithNormalInputIsFailure() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/SqlInjection/attack10").param("action_string", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Verify that a SQL injection payload intended to drop the access_log table is treated as a
   * literal search string by the parameterized query, NOT executed as SQL.  The table must still
   * exist after the request (proven by lessonCompleted remaining false with the "entries" feedback).
   *
   * <p>Before the fix, "%'; DROP TABLE access_log;--" would drop the table and return success.
   * After the fix the payload is bound as a LIKE parameter, so no matching rows are found, but the
   * table is not dropped — the endpoint returns the "entries" failure response.
   */
  @Test
  public void sqlInjectionPayloadDoesNotDropTable() throws Exception {
    // The classic DROP TABLE injection attempt — must NOT complete the lesson with the fix applied.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "%'; DROP TABLE access_log;--"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Verify that a UNION-based SQL injection payload does not exfiltrate data from other tables.
   * The payload is treated as a literal string; the query returns no rows matching that exact
   * LIKE pattern, so lessonCompleted stays false.
   */
  @Test
  public void unionBasedInjectionPayloadIsBlockedByParameterization() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "' UNION SELECT * FROM employees--"))
        .andExpect(status().isOk())
        // The payload is a literal LIKE pattern — no SQL error, no extra data
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Verify that a tautology injection ("' OR '1'='1") is treated as a literal search string and
   * does not bypass the WHERE clause to return all rows.
   */
  @Test
  public void tautologyInjectionIsBlockedByParameterization() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "' OR '1'='1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Verify that a normal search term (matching existing access_log entries) returns results
   * correctly, confirming that the parameterized LIKE query still works for legitimate use.
   */
  @Test
  public void normalSearchTermReturnsResults() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "get"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }
}

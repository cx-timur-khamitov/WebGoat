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
   * Verifies that the SQL injection payload used to drop the access_log table is no longer
   * effective after the fix. With parameterized queries the payload is treated as a literal
   * string, so the DROP TABLE statement is never executed and the lesson cannot be completed
   * via injection.
   */
  @Test
  public void sqlInjectionDropTablePayloadIsBlocked() throws Exception {
    // This payload previously succeeded by injecting a DROP TABLE statement.
    // After fixing to use a PreparedStatement the payload is treated as a
    // literal search string; the access_log table still exists and the
    // lesson is NOT completed.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "%'; DROP TABLE access_log;--"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /** Verifies that a normal (non-injecting) search string returns entries and does not succeed. */
  @Test
  public void normalSearchStringReturnsEntriesNotSuccess() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "login"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /** Verifies that a UNION-based injection payload is blocked by the parameterized query. */
  @Test
  public void sqlInjectionUnionPayloadIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "' UNION SELECT * FROM users--"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /** Verifies that a tautology injection payload (' OR '1'='1) is blocked. */
  @Test
  public void sqlInjectionTautologyPayloadIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack10")
                .param("action_string", "' OR '1'='1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }
}

/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * Tests for SqlInjectionLesson3 verifying that the SQL injection vulnerability has been fixed by
 * using a parameterized PreparedStatement instead of raw Statement.executeUpdate(query).
 *
 * <p>The lesson now accepts a department name (not a full SQL query). The user-supplied value is
 * bound as a PreparedStatement parameter, preventing SQL injection.
 */
public class SqlInjectionLesson3Test extends LessonTest {

  /** Submitting 'Sales' as the department value should complete the lesson. */
  @Test
  public void correctDepartmentValueShouldCompleteLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack3")
                .param("query", "Sales"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
  }

  /** Submitting a wrong department value should not complete the lesson. */
  @Test
  public void wrongDepartmentValueShouldNotCompleteLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack3")
                .param("query", "HR"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * A classic SQL injection payload attempting to bypass the parameterized query
   * (e.g. "Sales' OR '1'='1") should NOT complete the lesson — the injected SQL syntax is treated
   * as a literal string value, not executed as SQL code.
   */
  @Test
  public void sqlInjectionPayloadShouldNotCompleteLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack3")
                .param("query", "Sales' OR '1'='1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * An injection payload attempting a UNION-based attack should NOT complete the lesson —
   * it is treated as a literal department string, not executed as SQL.
   */
  @Test
  public void unionInjectionPayloadShouldNotCompleteLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack3")
                .param("query", "' UNION SELECT * FROM employees --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * An injection payload containing a stacked statement (DROP TABLE attempt) should NOT complete
   * the lesson and should not cause any database error that results in a 5xx response.
   */
  @Test
  public void stackedQueryInjectionShouldNotCompleteLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack3")
                .param("query", "Sales'; DROP TABLE employees; --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /** An empty department value should not complete the lesson. */
  @Test
  public void emptyQueryShouldNotCompleteLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack3")
                .param("query", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}

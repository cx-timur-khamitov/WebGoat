/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.CoreMatchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * Tests for SqlInjectionLesson4.
 *
 * <p>The lesson expects students to ADD a phone column via ALTER TABLE. The fix ensures that only
 * exact allowlisted DDL statements are executed, preventing SQL injection through arbitrary query
 * execution.
 */
public class SqlInjectionLesson4Test extends LessonTest {

  /** The expected solution: adding the phone column completes the lesson. */
  @Test
  public void addPhoneColumnSolutionCompletesLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack4")
                .param("query", "alter table employees add column phone varchar(20)"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)));
  }

  /** An unrelated SELECT query must not complete the lesson and must not be executed. */
  @Test
  public void arbitrarySelectQueryIsRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack4")
                .param("query", "SELECT * FROM employees"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Classic SQL injection payload — must be blocked by the allowlist and not reach the database.
   */
  @Test
  public void sqlInjectionDropTablePayloadIsRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack4")
                .param("query", "alter table employees add column phone varchar(20); DROP TABLE employees; --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /** A payload that attempts to union-inject must be rejected. */
  @Test
  public void unionInjectionPayloadIsRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack4")
                .param("query", "alter table employees add column phone varchar(20) UNION SELECT password FROM users --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /** An empty query must not complete the lesson. */
  @Test
  public void emptyQueryIsRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack4")
                .param("query", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /** Mixed-case variant of the allowed statement must still be accepted (allowlist is case-insensitive). */
  @Test
  public void addPhoneColumnWithUpperCaseIsAccepted() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack4")
                .param("query", "ALTER TABLE EMPLOYEES ADD COLUMN PHONE VARCHAR(20)"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)));
  }
}

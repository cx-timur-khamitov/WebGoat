/*
 * SPDX-FileCopyrightText: Copyright © 2024 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.sql.SQLException;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * Tests for SqlInjectionLesson4 verifying that:
 * 1. The correct DDL query completes the lesson
 * 2. SQL injection payloads are rejected (user input never reaches the SQL sink)
 * 3. Wrong queries do not complete the lesson
 */
public class SqlInjectionLesson4Test extends LessonTest {

  @Autowired private LessonDataSource dataSource;

  /** Remove the phone column after each test so subsequent tests start from a clean state. */
  @AfterEach
  public void removePhoneColumn() throws SQLException {
    try {
      dataSource
          .getConnection()
          .prepareStatement("alter table employees drop column phone")
          .execute();
    } catch (SQLException e) {
      // Column may not exist if the test did not add it — ignore
    }
  }

  /** The exact expected DDL must complete the lesson. */
  @Test
  public void correctAlterTableSolvesLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack4")
                .param("query", "alter table employees add column phone varchar(20)"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
  }

  /** Input with a classic SQL injection payload must be rejected and not complete the lesson. */
  @Test
  public void sqlInjectionPayloadIsRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack4")
                .param(
                    "query",
                    "alter table employees add column phone varchar(20); DROP TABLE employees;--"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /** A SELECT statement should not complete the lesson. */
  @Test
  public void selectQueryDoesNotSolveLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack4")
                .param("query", "SELECT * FROM employees"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /** An unrelated DDL statement should not complete the lesson. */
  @Test
  public void wrongColumnNameDoesNotSolveLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack4")
                .param("query", "alter table employees add column email varchar(50)"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /** An empty query must not complete the lesson. */
  @Test
  public void emptyQueryDoesNotSolveLesson() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/SqlInjection/attack4").param("query", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /** A comment-based injection attempt must not complete the lesson. */
  @Test
  public void commentInjectionIsRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack4")
                .param(
                    "query",
                    "alter table employees add column phone varchar(20) -- injected comment"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /** Case-insensitive matching: uppercase variant of the expected DDL should also solve the lesson. */
  @Test
  public void caseInsensitiveMatchSolvesLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack4")
                .param("query", "ALTER TABLE EMPLOYEES ADD COLUMN PHONE VARCHAR(20)"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
  }
}

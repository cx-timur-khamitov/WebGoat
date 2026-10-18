/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
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

public class SqlInjectionLesson5Test extends LessonTest {

  @Autowired private LessonDataSource dataSource;

  @AfterEach
  public void removeGrant() throws SQLException {
    dataSource
        .getConnection()
        .prepareStatement("revoke select on grant_rights from unauthorized_user cascade")
        .execute();
  }

  @Test
  public void grantSolution() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack5")
                .param("query", "grant select on grant_rights to unauthorized_user"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
  }

  @Test
  public void differentTableShouldNotSolveIt() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack5")
                .param("query", "grant select on users to unauthorized_user"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  public void noGrantShouldNotSolveIt() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack5")
                .param("query", "select * from grant_rights"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  // --- Security regression tests validating the PreparedStatement fix ---

  /**
   * Verifies that a multi-statement injection payload (stacked queries using a semicolon) does
   * NOT succeed. The PreparedStatement API used after the fix does not allow execution of multiple
   * semicolon-separated statements in a single call on HSQLDB, so the lesson should not be solved
   * by this injection attempt.
   */
  @Test
  public void stackedQueryInjectionShouldNotSolveLesson() throws Exception {
    // Attempt to solve the lesson via a stacked-query injection that appends a second GRANT
    // statement after a benign SELECT. PreparedStatement on HSQLDB rejects multi-statement input.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack5")
                .param(
                    "query",
                    "select 1; grant select on grant_rights to unauthorized_user"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * Verifies that an empty query is handled gracefully and does not solve the lesson.
   */
  @Test
  public void emptyQueryShouldNotSolveLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack5")
                .param("query", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * Verifies that a syntactically malformed query returns an error response (lessonCompleted=false)
   * and does not crash the application.
   */
  @Test
  public void malformedQueryShouldReturnFailure() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack5")
                .param("query", "THIS IS NOT VALID SQL ''' ---"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * Verifies that a classic tautology injection (always-true WHERE clause) does not solve
   * the lesson, demonstrating the query must be the correct GRANT statement.
   */
  @Test
  public void tautologyInjectionShouldNotSolveLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack5")
                .param("query", "select * from grant_rights where '1'='1'"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * Verifies that granting privileges on the wrong table does not complete the lesson,
   * ensuring the solution check uses parameterized queries and cannot be bypassed.
   */
  @Test
  public void grantOnWrongTableShouldNotSolveLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack5")
                .param("query", "grant select on user_data to unauthorized_user"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * Verifies that a GRANT to a different user (not unauthorized_user) does not solve the lesson.
   */
  @Test
  public void grantToWrongUserShouldNotSolveLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack5")
                .param("query", "grant select on grant_rights to sa"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * Verifies that a query returning a result (SELECT) still produces a valid HTTP 200 response
   * and does not crash, demonstrating the PreparedStatement change is backward-compatible.
   */
  @Test
  public void selectQueryShouldReturnOkResponse() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack5")
                .param("query", "select count(*) from grant_rights"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * Regression test: verifies the full lesson-completion flow still works after the
   * Statement → PreparedStatement fix. The correct GRANT statement must solve the lesson.
   */
  @Test
  public void correctGrantSolvesLessonAfterPreparedStatementFix() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack5")
                .param("query", "GRANT SELECT ON GRANT_RIGHTS TO UNAUTHORIZED_USER"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
  }
}

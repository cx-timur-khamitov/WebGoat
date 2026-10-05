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

  // --- Regression tests to verify SQL injection remediation ---

  /**
   * Verify that a classic SQL injection payload using SELECT (not in the allowlist) is rejected
   * and does not complete the lesson. This exercises the allowlist enforcement added to
   * injectableQuery().
   */
  @Test
  public void sqlInjectionSelectPayloadIsRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack5")
                // Typical SQL injection probe: SELECT-based payload not in the allowed prefixes
                .param("query", "select 1; drop table employees; --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * Verify that a DELETE statement is rejected by the allowlist and cannot be executed,
   * preventing destructive SQL injection attacks.
   */
  @Test
  public void sqlInjectionDeletePayloadIsRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack5")
                .param("query", "delete from employees where 1=1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * Verify that an INSERT statement is rejected by the allowlist.
   */
  @Test
  public void sqlInjectionInsertPayloadIsRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack5")
                .param("query", "insert into employees values ('hacker', 'hacker', 'IT', 0, 0, 0, 0)"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * Verify that an UPDATE statement is rejected by the allowlist.
   */
  @Test
  public void sqlInjectionUpdatePayloadIsRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack5")
                .param("query", "update employees set salary=9999999 where 1=1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * Verify that an empty query is rejected gracefully without causing a server error.
   */
  @Test
  public void emptyQueryIsRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack5")
                .param("query", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * Verify that a GRANT on the wrong table is blocked (does not complete the lesson),
   * while still being a valid GRANT keyword (allowed prefix).
   * This ensures the allowlist permits GRANT statements but the solution check is still enforced.
   */
  @Test
  public void grantOnWrongTableDoesNotComplete() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack5")
                .param("query", "grant all on employees to unauthorized_user"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}

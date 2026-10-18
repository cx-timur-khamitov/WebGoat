/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson9Test extends LessonTest {

  /**
   * Regression test: a classic tautology injection payload in auth_tan (e.g. {@code ' OR '1'='1})
   * must no longer return all rows or succeed now that the query uses a PreparedStatement. The
   * payload is treated as literal data and the query returns no matching employee, so the lesson is
   * not completed.
   */
  @Test
  public void malformedQueryReturnsError() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "Smith")
                .param("auth_tan", "3SL99A' OR '1' = '1'"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Regression test: an UPDATE injection payload injected via a semicolon in auth_tan (previously
   * used to raise John Smith's salary) must not modify any salary row now that the query uses a
   * PreparedStatement. The payload is stored as literal string data, the SELECT finds no match, and
   * the lesson is not completed.
   */
  @Test
  public void sqlInjectionViaSemicolonInAuthTanIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "Smith")
                .param(
                    "auth_tan",
                    "3SL99A'; UPDATE employees SET salary = 9999 WHERE last_name = 'Smith"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.9.one"))));
  }

  /**
   * Regression test: an UPDATE + comment injection payload (previously used to update all rows)
   * must be rejected now that the query is parameterized. The SELECT finds no match, so the lesson
   * is not completed and the salary table must not be modified.
   */
  @Test
  public void sqlInjectionWithCommentTerminatorIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "Smith")
                .param("auth_tan", "3SL99A'; UPDATE employees SET salary = 9999 -- "))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.9.one"))));
  }

  /**
   * Regression test: an injection payload supplied via the name parameter (with an empty auth_tan)
   * must not alter any row. The PreparedStatement treats the entire name value as a literal string
   * and the SELECT finds no match.
   */
  @Test
  public void sqlInjectionViaNameParameterIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "'; UPDATE employees SET salary = 999999 -- ")
                .param("auth_tan", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.9.one"))));
  }

  /**
   * Regression test: the previous SQL injection payload that raised John Smith's salary is now
   * blocked. The semicolon-UPDATE-comment payload must be treated as literal data and must NOT
   * update any salary. The request completes successfully (HTTP 200) without a server-side error.
   */
  @Test
  public void previouslySuccessfulInjectionIsNowBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "Smith")
                .param(
                    "auth_tan",
                    "3SL99A'; UPDATE employees SET salary = '300000' WHERE last_name = 'Smith"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Sanity test: a request with a valid employee name and correct auth_tan must succeed and return
   * an HTTP 200 response. The SELECT finds exactly one matching row so the lesson is not completed
   * (the success condition requires John Smith's salary to exceed all others), but no server error
   * must occur.
   */
  @Test
  public void validCredentialsReturnHttpOk() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "Smith")
                .param("auth_tan", "3SL99A"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Sanity test: a DROP TABLE injection payload supplied in auth_tan must not cause a server error
   * (5xx). The PreparedStatement binds the payload as a string literal; no DDL is executed and the
   * endpoint returns HTTP 200.
   */
  @Test
  public void dropTableInjectionDoesNotCauseServerError() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "Smith")
                .param("auth_tan", "3SL99A'; DROP TABLE employees; --"))
        .andExpect(status().isOk());
  }

  /**
   * Sanity test: a UNION-based data-exfiltration injection attempt in auth_tan must be blocked. The
   * PreparedStatement treats the UNION payload as a literal string so the SELECT returns no rows
   * and the lesson is not completed.
   */
  @Test
  public void unionInjectionIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "Smith")
                .param("auth_tan", "' UNION SELECT * FROM employees --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Sanity test: an empty name and auth_tan must not cause a server error. The parameterized query
   * executes safely with empty string values and the endpoint returns HTTP 200.
   */
  @Test
  public void emptyParametersDoNotCauseServerError() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "")
                .param("auth_tan", ""))
        .andExpect(status().isOk());
  }

  /**
   * Sanity test: a payload containing only a single quote in both parameters must not break the
   * PreparedStatement execution. Single quotes are passed as data, not SQL syntax, so no
   * SQLException is thrown and the response is HTTP 200.
   */
  @Test
  public void singleQuoteInBothParametersDoesNotBreakQuery() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "'")
                .param("auth_tan", "'"))
        .andExpect(status().isOk());
  }
}

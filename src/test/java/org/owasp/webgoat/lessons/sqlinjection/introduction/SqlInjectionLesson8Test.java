/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
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

public class SqlInjectionLesson8Test extends LessonTest {

  @Test
  public void oneAccount() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack8")
                .param("name", "Smith")
                .param("auth_tan", "3SL99A"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.8.one"))))
        .andExpect(jsonPath("$.output", containsString("<table><tr><th>")));
  }

  /**
   * Regression test: after fixing SQL injection with a PreparedStatement, a classic OR-based
   * injection payload in auth_tan must be treated as a literal string and return no results
   * (the literal value "3SL99A' OR '1' = '1" is not a valid TAN in the database).
   *
   * <p>Previously, the concatenated query allowed injection; now the parameterized query prevents
   * the payload from altering query structure.
   */
  @Test
  public void sqlInjectionPayloadInAuthTanIsBlockedByPreparedStatement() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack8")
                .param("name", "Smith")
                // Classic OR-injection — must NOT return multiple rows with parameterized queries
                .param("auth_tan", "3SL99A' OR '1' = '1"))
        .andExpect(status().isOk())
        // The injection payload is a literal string; no employee has this auth_tan value,
        // so the query returns no results and the lesson is NOT completed.
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  @Test
  public void wrongNameReturnsNoAccounts() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack8")
                .param("name", "Smithh")
                .param("auth_tan", "3SL99A"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.8.no.results"))))
        .andExpect(jsonPath("$.output").doesNotExist());
  }

  @Test
  public void wrongTANReturnsNoAccounts() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack8")
                .param("name", "Smithh")
                .param("auth_tan", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.8.no.results"))))
        .andExpect(jsonPath("$.output").doesNotExist());
  }

  /**
   * Regression test: after fixing with PreparedStatement, a payload that previously produced a
   * malformed query (unbalanced quotes) must no longer cause a SQL syntax error — it is safely
   * bound as a parameter. The request must return a well-formed HTTP 200 response with no results,
   * rather than a 5xx or a "feedback-negative" error output.
   */
  @Test
  public void payloadWithUnbalancedQuoteDoesNotCauseSqlError() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack8")
                .param("name", "Smith")
                // Previously this unbalanced-quote payload broke the concatenated query structure.
                // With PreparedStatement it is treated as a literal value — no SQL error.
                .param("auth_tan", "3SL99A' OR '1' = '1'"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Regression test: an auth_tan payload containing a SQL injection sequence that previously could
   * corrupt the access_log INSERT statement (second-order injection via the log() method) must now
   * be treated as literal data. The endpoint must still return a well-formed HTTP 200 response — no
   * server error caused by the injection payload being interpreted as SQL.
   *
   * <p>Before the fix, the log() method built its INSERT by string concatenation, so a payload such
   * as {@code '), ('injected','injected} would terminate the VALUES list and inject an extra row.
   * After the fix, PreparedStatement binds the action as a plain string parameter and the payload
   * is stored verbatim without altering the query structure.
   */
  @Test
  public void sqlInjectionInLogMethodDoesNotCauseServerError() throws Exception {
    // This payload previously could break the INSERT inside log() via second-order injection.
    // With the parameterized PreparedStatement fix, it must be harmless and the request must
    // complete without a 5xx error.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack8")
                .param("name", "Smith")
                .param("auth_tan", "'), ('2099-01-01 00:00:00', 'injected_row"))
        .andExpect(status().isOk());
  }

  /**
   * Regression test: a classic SQL injection attempt in auth_tan that targets the log() INSERT
   * must not cause a server-side SQL error after the PreparedStatement fix. The payload contains a
   * single-quote that previously would have broken the concatenated INSERT query.
   */
  @Test
  public void singleQuoteInAuthTanDoesNotBreakLogInsert() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack8")
                .param("name", "Smith")
                .param("auth_tan", "x' OR 'x'='x"))
        // The employee query is now parameterized (preventing injection), and the log INSERT
        // must also succeed without a SQL syntax error caused by the unescaped single quote.
        .andExpect(status().isOk());
  }

  /**
   * Regression test: a semicolon-and-comment injection attempt in auth_tan should not cause the
   * employee SELECT or the log() INSERT to be split into multiple statements or otherwise silently
   * corrupted after the PreparedStatement fix.
   */
  @Test
  public void semicolonInjectionInAuthTanDoesNotBreakQuery() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack8")
                .param("name", "Smith")
                .param("auth_tan", "3SL99A'; DROP TABLE access_log; --"))
        .andExpect(status().isOk());
  }

  /**
   * Verify that a specially crafted name parameter containing an injection payload is also treated
   * as a literal string and does not alter query structure.
   */
  @Test
  public void sqlInjectionInNameParameterIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack8")
                // Injection in name: ' OR '1'='1 would previously return all rows
                .param("name", "' OR '1'='1")
                .param("auth_tan", "3SL99A"))
        .andExpect(status().isOk())
        // With PreparedStatement the injected name is a literal — no match in the DB
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Verify that a UNION-based injection attempt in auth_tan is blocked by the parameterized query.
   * Previously, a UNION SELECT could be used to exfiltrate data from other tables.
   */
  @Test
  public void unionBasedInjectionInAuthTanIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack8")
                .param("name", "Smith")
                .param("auth_tan", "' UNION SELECT 1,2,3,4,5,6 --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }
}

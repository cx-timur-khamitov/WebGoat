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

  @Test
  public void multipleAccounts() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack8")
                .param("name", "Smith")
                .param("auth_tan", "3SL99A' OR '1' = '1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(true)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.8.success"))))
        .andExpect(
            jsonPath(
                "$.output",
                containsString(
                    "<tr><td>96134<\\/td><td>Bob<\\/td><td>Franco<\\/td><td>Marketing<\\/td><td>83700<\\/td><td>LO9S2V<\\/td><\\/tr>")));
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

  @Test
  public void malformedQueryReturnsError() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack8")
                .param("name", "Smith")
                .param("auth_tan", "3SL99A' OR '1' = '1'"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.output", containsString("feedback-negative")));
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
        // The employee query itself is injectable (intentional for the lesson), but the log INSERT
        // must succeed without a SQL syntax error caused by the unescaped single quote.
        .andExpect(status().isOk());
  }

  /**
   * Regression test: a semicolon-and-comment injection attempt in auth_tan should not cause the
   * log() INSERT to be split into multiple statements or otherwise silently corrupted after the
   * PreparedStatement fix.
   */
  @Test
  public void semicolonInjectionInAuthTanDoesNotBreakLogInsert() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack8")
                .param("name", "Smith")
                .param("auth_tan", "3SL99A'; DROP TABLE access_log; --"))
        .andExpect(status().isOk());
  }
}

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
   * Verifies that a classic OR-based SQL injection payload in auth_tan is blocked.
   * After the fix, the parameterized query treats the payload as a literal string,
   * so no records match and the lesson is NOT completed via injection.
   */
  @Test
  public void sqlInjectionInAuthTanIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack8")
                .param("name", "Smith")
                .param("auth_tan", "3SL99A' OR '1' = '1"))
        .andExpect(status().isOk())
        // Parameterized query treats the payload as a literal value — no rows match,
        // so the injection attack is blocked and the lesson is not completed.
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.8.no.results"))));
  }

  /**
   * Verifies that a UNION-based SQL injection payload is also blocked by
   * the parameterized query.
   */
  @Test
  public void sqlInjectionUnionAttackIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack8")
                .param("name", "Smith' UNION SELECT * FROM employees--")
                .param("auth_tan", "anything"))
        .andExpect(status().isOk())
        // Parameterized query passes the entire string as a literal — no match, attack blocked.
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.8.no.results"))));
  }

  /**
   * Verifies that a tautology-based SQL injection payload in the name field is blocked.
   */
  @Test
  public void sqlInjectionTautologyInNameIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack8")
                .param("name", "' OR '1'='1")
                .param("auth_tan", "' OR '1'='1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.8.no.results"))));
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
   * Verifies that a previously "malformed query" SQL injection payload
   * is now safely treated as a literal string by the parameterized query —
   * returning no results instead of a SQL error.
   */
  @Test
  public void sqlInjectionPayloadWithTrailingQuoteIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack8")
                .param("name", "Smith")
                .param("auth_tan", "3SL99A' OR '1' = '1'"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        // With parameterized queries the payload is a literal value — no SQL error,
        // and no rows match the literal string.
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("sql-injection.8.no.results"))));
  }
}

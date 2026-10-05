/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
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
   * Verifies that the log() method stores the action as literal data even when the action string
   * contains SQL metacharacters (single quotes). Before the fix, the string concatenation in log()
   * allowed an attacker-controlled query (containing single quotes) to break out of the SQL string
   * literal and inject arbitrary SQL into the INSERT. The parameterized PreparedStatement fix must
   * cause the payload to be stored verbatim as a row in access_log rather than being executed as
   * SQL.
   */
  @Test
  public void logMethodStoresSqlInjectionPayloadAsLiteralData() throws Exception {
    // Set up an in-memory HSQLDB database that mimics the access_log table structure.
    try (Connection connection =
        DriverManager.getConnection("jdbc:hsqldb:mem:logtest", "sa", "")) {
      Statement setup = connection.createStatement();
      setup.execute(
          "CREATE TABLE IF NOT EXISTS access_log (time VARCHAR(50), action VARCHAR(500))");

      // Payload that would break out of a string-concatenated INSERT and inject SQL.
      // With the old code the single quote in the payload would terminate the SQL string literal
      // and allow arbitrary SQL to be appended. With the PreparedStatement fix, the payload
      // must be stored verbatim and the table must still exist after the call.
      String sqlInjectionPayload = "Smith' AND '1'='1";
      SqlInjectionLesson8.log(connection, sqlInjectionPayload);

      // The table must still exist and contain exactly the inserted row.
      ResultSet rows = connection.createStatement().executeQuery("SELECT action FROM access_log");
      assertTrue(rows.next(), "access_log must contain exactly one row inserted by log()");
      assertEquals(
          sqlInjectionPayload,
          rows.getString("action"),
          "The SQL injection payload must be stored as literal data, not executed as SQL");
    }
  }

  /**
   * Verifies that log() safely stores an action containing single quotes without throwing an
   * SQLException. The old string-concatenation approach would produce malformed SQL when the action
   * contained an odd number of single quotes. The PreparedStatement fix must handle this correctly.
   */
  @Test
  public void logMethodHandlesSingleQuotesInActionWithoutError() throws Exception {
    try (Connection connection =
        DriverManager.getConnection("jdbc:hsqldb:mem:logtest2", "sa", "")) {
      Statement setup = connection.createStatement();
      setup.execute(
          "CREATE TABLE IF NOT EXISTS access_log (time VARCHAR(50), action VARCHAR(500))");

      // An action with a single quote — previously would produce malformed SQL with concatenation.
      String actionWithQuote =
          "SELECT * FROM employees WHERE last_name = 'Smith' AND auth_tan = 'x";
      SqlInjectionLesson8.log(connection, actionWithQuote);

      ResultSet rows = connection.createStatement().executeQuery("SELECT action FROM access_log");
      assertTrue(rows.next(), "access_log must contain the row inserted by log()");
      assertEquals(
          actionWithQuote,
          rows.getString("action"),
          "Action containing single quotes must be stored verbatim");
    }
  }
}

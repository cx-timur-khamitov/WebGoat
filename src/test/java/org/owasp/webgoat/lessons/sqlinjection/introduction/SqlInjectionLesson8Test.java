/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.sql.Connection;
import java.sql.PreparedStatement;
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
   * Verifies that the log() method uses a PreparedStatement (parameterized query) so that SQL
   * injection payloads in the logged action string are treated as data, not executable SQL.
   * The fix replaced string concatenation in the INSERT with positional parameters (?, ?).
   */
  @Test
  public void logMethodUsesParameterizedQueryPreventingSqlInjection() throws Exception {
    Connection mockConnection = mock(Connection.class);
    PreparedStatement mockPreparedStatement = mock(PreparedStatement.class);

    // The parameterized INSERT query with placeholders
    when(mockConnection.prepareStatement("INSERT INTO access_log (time, action) VALUES (?, ?)"))
        .thenReturn(mockPreparedStatement);

    // A SQL injection payload that would break a concatenated query
    String sqlInjectionPayload = "'); DROP TABLE access_log; --";

    // Must not throw even with a malicious action string
    assertDoesNotThrow(() -> SqlInjectionLesson8.log(mockConnection, sqlInjectionPayload));

    // Verify prepareStatement was called with the parameterized template (not a concatenated string)
    verify(mockConnection, times(1))
        .prepareStatement("INSERT INTO access_log (time, action) VALUES (?, ?)");

    // Verify the injection payload was passed as a safe parameter, not concatenated into SQL
    verify(mockPreparedStatement, times(1)).setString(2, sqlInjectionPayload);
    verify(mockPreparedStatement, times(1)).executeUpdate();
  }

  /**
   * Verifies that a SQL injection payload with single-quote characters in the action is stored
   * as a literal string parameter and does not cause a syntax error or alter query logic.
   */
  @Test
  public void logMethodHandlesSingleQuotesInActionSafely() throws Exception {
    Connection mockConnection = mock(Connection.class);
    PreparedStatement mockPreparedStatement = mock(PreparedStatement.class);

    when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);

    // Single quotes are the classic SQL injection vector; parameterized queries handle them safely
    String actionWithSingleQuotes = "SELECT * FROM employees WHERE last_name = 'Smith' OR '1'='1'";

    assertDoesNotThrow(() -> SqlInjectionLesson8.log(mockConnection, actionWithSingleQuotes));

    // The raw payload (including single quotes) should be passed as a parameter value
    verify(mockPreparedStatement, times(1)).setString(2, actionWithSingleQuotes);
    verify(mockPreparedStatement, times(1)).executeUpdate();
  }
}

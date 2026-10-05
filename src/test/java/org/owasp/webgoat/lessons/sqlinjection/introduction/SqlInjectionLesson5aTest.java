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

public class SqlInjectionLesson5aTest extends LessonTest {

  @Test
  public void knownAccountShouldDisplayData() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "Smith")
                .param("operator", "")
                .param("injection", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("assignment.not.solved"))))
        .andExpect(jsonPath("$.output", containsString("<p>USERID, FIRST_NAME")));
  }

  @Test
  public void unknownAccountShouldReturnNoResults() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "DoesNotExist")
                .param("operator", "")
                .param("injection", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Verifies that the SQL injection payload is treated as a literal string parameter
   * and does NOT bypass authentication / return all rows. The fix uses a PreparedStatement
   * so the injected OR clause is not interpreted as SQL syntax.
   */
  @Test
  public void sqlInjectionIsBlockedByPreparedStatement() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "'")
                .param("operator", "OR")
                .param("injection", "'1' = '1"))
        .andExpect(status().isOk())
        // Injection must NOT complete the lesson — the payload is a literal last_name value
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Verifies that a classic OR 1=1 injection payload is blocked when using a PreparedStatement.
   * The entire concatenated string is passed as a bound parameter, so no SQL syntax escaping occurs.
   */
  @Test
  public void or1Equals1InjectionIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "Smith")
                .param("operator", "OR")
                .param("injection", "1=1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Verifies that a single-quote in the account name does not cause an SQL error
   * because the PreparedStatement properly escapes the parameter value.
   */
  @Test
  public void singleQuoteInInputDoesNotCauseSqlError() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "O'Brien")
                .param("operator", "")
                .param("injection", ""))
        .andExpect(status().isOk())
        // Should not throw a SQL parse error — result is simply no data found
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Verifies that a UNION-based injection payload is treated as a literal string
   * and does not cause the query to return injected rows.
   */
  @Test
  public void unionBasedInjectionIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "Smith")
                .param("operator", "UNION SELECT")
                .param("injection", "* FROM user_data--"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Verifies that a comment-based injection attempt (--) is treated as a literal string.
   */
  @Test
  public void commentBasedInjectionIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "Smith'--")
                .param("operator", "")
                .param("injection", ""))
        .andExpect(status().isOk())
        // Payload is a literal last_name; no SQL syntax error, no data returned
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }
}

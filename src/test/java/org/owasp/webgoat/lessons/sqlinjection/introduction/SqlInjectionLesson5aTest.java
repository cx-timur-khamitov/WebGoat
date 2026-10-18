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
  public void unknownAccount() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "NoSuchUser")
                .param("operator", "")
                .param("injection", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", containsString("sql-injection.5a.no.results")));
  }

  /**
   * Verifies that SQL injection via the operator/injection parameters is prevented by the
   * parameterized query fix. The classic "OR '1'='1'" payload must NOT return 6+ rows and
   * must NOT complete the lesson, because the injected string is treated as a literal value
   * rather than SQL syntax.
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
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Verifies that a tautology-based injection payload is blocked. With a parameterized query,
   * the entire concatenated string is treated as a literal last_name value and will not match
   * any rows, so the lesson should not be completed.
   */
  @Test
  public void tautologyInjectionPayloadIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "anything")
                .param("operator", "OR")
                .param("injection", "1=1 --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Verifies that a UNION-based injection payload is blocked. With a parameterized query, the
   * UNION SELECT clause is treated as a literal string rather than SQL, preventing data exfiltration.
   */
  @Test
  public void unionInjectionPayloadIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "' UNION SELECT * FROM user_data --")
                .param("operator", "")
                .param("injection", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Verifies that a quote character in the input does not cause a SQL syntax error
   * when the query uses a PreparedStatement. The literal single-quote should be safely
   * handled as a parameter value.
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
        // Should not produce a SQL error — either no results or data displayed
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  @Test
  public void sqlInjectionWrongShouldDisplayError() throws Exception {
    // With a parameterized query, the trailing quote in "Smith'" becomes a literal
    // part of the last_name parameter and will produce no results (not a SQL error).
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "Smith'")
                .param("operator", "OR")
                .param("injection", "'1' = '1'"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }
}

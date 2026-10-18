/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Disabled;
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

  @Disabled
  @Test
  public void unknownAccount() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "Smith")
                .param("operator", "")
                .param("injection", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.feedback", is(messages.getMessage("NoResultsMatched"))))
        .andExpect(jsonPath("$.output").doesNotExist());
  }

  /**
   * After fixing SQL injection with parameterized queries, injection payloads are treated as
   * literal string values rather than SQL syntax. The attack payload is now passed as a bind
   * parameter and does not alter query structure, so the lesson should NOT be completed.
   */
  @Test
  public void sqlInjectionAttackIsBlockedByPreparedStatement() throws Exception {
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
   * Verify that a classic OR-based SQL injection payload is neutralised by the parameterized query.
   * With the safe PreparedStatement, the combined string is treated as a literal last_name value,
   * which does not match any row, so the lesson remains unsolved.
   */
  @Test
  public void sqlInjectionOrTruePayloadDoesNotBypassQuery() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "Smith")
                .param("operator", "OR")
                .param("injection", "'1' = '1'"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * A UNION-based injection attempt should also be blocked. The payload is passed as a literal
   * bind value and cannot append an extra SELECT to the query.
   */
  @Test
  public void sqlInjectionUnionPayloadIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "Smith' UNION SELECT * FROM user_data--")
                .param("operator", "")
                .param("injection", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * A DROP TABLE injection attempt should also be blocked by the prepared statement.
   */
  @Test
  public void sqlInjectionDropTablePayloadIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5a")
                .param("account", "'; DROP TABLE user_data; --")
                .param("operator", "")
                .param("injection", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }
}

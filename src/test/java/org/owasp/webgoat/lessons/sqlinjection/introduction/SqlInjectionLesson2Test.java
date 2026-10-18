/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson2Test extends LessonTest {

  /** Correct userid for a Marketing department employee — lesson should complete successfully. */
  @Test
  public void solution() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack2").param("userid", "96134"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
  }

  /** A userid that does not belong to the Marketing department should not complete the lesson. */
  @Test
  public void wrongDepartmentShouldFail() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack2").param("userid", "1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /** A non-existent userid should not complete the lesson. */
  @Test
  public void nonExistentUseridShouldFail() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack2").param("userid", "999999"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  /**
   * Classic SQL injection payloads — the prepared statement must prevent them from altering the
   * query structure.  These should all fail (not complete the lesson and not throw a 5xx error).
   */
  @Test
  public void sqlInjectionPayloadOrOneShouldNotSucceed() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack2")
                .param("userid", "1 OR 1=1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  public void sqlInjectionUnionPayloadShouldNotSucceed() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack2")
                .param("userid", "1 UNION SELECT department FROM employees--"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  public void sqlInjectionAlwaysTrueWithCommentShouldNotSucceed() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack2")
                .param("userid", "96134' OR '1'='1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  public void sqlInjectionDropTablePayloadShouldNotSucceed() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack2")
                .param("userid", "1; DROP TABLE employees--"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }
}

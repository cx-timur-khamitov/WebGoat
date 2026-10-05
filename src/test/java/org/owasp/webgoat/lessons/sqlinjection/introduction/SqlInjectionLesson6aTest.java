/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson6aTest extends LessonTest {

  @Test
  public void wrongSolution() throws Exception {
    // A plain name that doesn't match any last name returns no results / not completed.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "John"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void knownLastNameReturnsResults() throws Exception {
    // A known last name "Smith" should return data rows without completing the lesson.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "Smith"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  // --- Security regression tests: SQL injection payloads must NOT complete the lesson ---

  @Test
  public void sqlInjectionUnionPayloadIsBlocked() throws Exception {
    // UNION injection that previously exposed user_system_data must now be treated as a literal
    // string lookup (parameterized query). No rows matching that literal last name → not completed.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param(
                    "userid_6a",
                    "Smith' union select userid,user_name, password,cookie,cookie, cookie,userid"
                        + " from user_system_data --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void sqlInjectionStackedQueryPayloadIsBlocked() throws Exception {
    // A stacked-query injection must be treated as a literal string, not injected SQL.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "Smith'; SELECT * from user_system_data; --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void sqlInjectionTautologyPayloadIsBlocked() throws Exception {
    // A tautology payload that previously caused no results must still return not completed.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "Smith' and 1 = 2 --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void sqlInjectionUnionWrongColumnsIsBlocked() throws Exception {
    // UNION with wrong column count — parameterized query prevents this from being executed as SQL.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param(
                    "userid_6a",
                    "Smith' union select userid,user_name, password,cookie from user_system_data"
                        + " --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void sqlInjectionAlterCasePayloadIsBlocked() throws Exception {
    // Mixed-case or embedded keyword payload must not bypass the parameterized query.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "S'; Select * from user_system_data; --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void emptyInputReturnsNotCompleted() throws Exception {
    // An empty input should not complete the lesson.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }
}

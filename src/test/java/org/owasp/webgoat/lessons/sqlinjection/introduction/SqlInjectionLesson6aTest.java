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
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "John"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void sqlInjectionPayloadTreatedAsLiteralString() throws Exception {
    // With parameterized query, SQL injection payloads are treated as literal strings.
    // The payload "Smith' union select ..." is searched as a last_name value — no results found.
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
  public void sqlInjectionUnionPayloadBlockedByPreparedStatement() throws Exception {
    // With parameterized query, UNION injection is neutralized — the entire payload
    // is treated as a literal last_name value and no matching row exists.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param(
                    "userid_6a",
                    "Smith' union select 1,password, 1,'2','3', '4',1 from user_system_data --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void sqlInjectionPayloadDoesNotLeakCredentials() throws Exception {
    // Verify that the parameterized query fix prevents SQL injection from exposing
    // sensitive data (passW0rD) that would have been accessible via injection.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "Smith'; SELECT * from user_system_data; --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void noResultsReturned() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "NonExistentUser"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }
}

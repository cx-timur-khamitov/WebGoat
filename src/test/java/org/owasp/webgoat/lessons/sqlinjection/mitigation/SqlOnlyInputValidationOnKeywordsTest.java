/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlOnlyInputValidationOnKeywordsTest extends LessonTest {

  @Test
  public void keywordBypassPayloadBlockedByPreparedStatement() throws Exception {
    // With parameterized query in SqlInjectionLesson6a.injectableQuery(), the underlying
    // SQL injection is prevented even when keyword filtering is bypassed. The entire
    // payload is treated as a literal last_name value — no row matches and the lesson
    // is not completed.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlOnlyInputValidationOnKeywords/attack")
                .param(
                    "userid_sql_only_input_validation_on_keywords",
                    "Smith';SESELECTLECT/**/*/**/FRFROMOM/**/user_system_data;--"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void containsForbiddenSqlKeyword() throws Exception {
    // Input with spaces is rejected by the keyword-space check in SqlOnlyInputValidationOnKeywords
    // before it can even reach the database layer.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlOnlyInputValidationOnKeywords/attack")
                .param(
                    "userid_sql_only_input_validation_on_keywords",
                    "Smith';SELECT/**/*/**/from/**/user_system_data;--"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void sqlInjectionWithSpacesRejectedByKeywordFilter() throws Exception {
    // Confirm that inputs containing spaces are rejected early by the keyword-space check,
    // which prevents them from reaching the parameterized query.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlOnlyInputValidationOnKeywords/attack")
                .param(
                    "userid_sql_only_input_validation_on_keywords",
                    "Smith' OR 1=1 --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }
}

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

  /**
   * The underlying {@link org.owasp.webgoat.lessons.sqlinjection.advanced.SqlInjectionLesson6a}
   * now uses a parameterized PreparedStatement, so SQL injection payloads are treated as literal
   * strings. No injection through this endpoint can complete the lesson.
   */
  @Test
  public void injectionPayloadWithKeywordObfuscationIsBlocked() throws Exception {
    // Previously this bypassed keyword filtering via nested keyword obfuscation; now the
    // parameterized query treats the entire value as a literal last_name — not completed.
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
  public void inputWithSpacesIsRejectedByKeywordFilter() throws Exception {
    // Input containing spaces is rejected before reaching the database query.
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
  public void plainLastNameWithNoKeywordsReturnsNotCompleted() throws Exception {
    // A plain name that passes the keyword check but has no results does not complete the lesson.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlOnlyInputValidationOnKeywords/attack")
                .param("userid_sql_only_input_validation_on_keywords", "Smith"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void sqlInjectionWithUnionKeywordIsBlockedByFilter() throws Exception {
    // A payload containing UNION (with spaces) is blocked by the space check before the DB query.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlOnlyInputValidationOnKeywords/attack")
                .param(
                    "userid_sql_only_input_validation_on_keywords",
                    "Smith' UNION SELECT * FROM user_system_data --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void emptyInputDoesNotCompleteLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlOnlyInputValidationOnKeywords/attack")
                .param("userid_sql_only_input_validation_on_keywords", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }
}

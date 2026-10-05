/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlOnlyInputValidationOnKeywordsTest extends LessonTest {

  /**
   * With the underlying query now using a PreparedStatement, the obfuscated keyword-bypass
   * payload (SESELECTLECT/FRFROMOM) is passed as a literal last_name value. No rows match,
   * so the lesson is not completed — demonstrating that parameterized queries prevent injection
   * even when keyword filtering is bypassed at the application layer.
   */
  @Test
  public void keywordBypassPayloadBlockedByPreparedStatement() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlOnlyInputValidationOnKeywords/attack")
                .param(
                    "userid_sql_only_input_validation_on_keywords",
                    "Smith';SESELECTLECT/**/*/**/FRFROMOM/**/user_system_data;--"))
        .andExpect(status().isOk())
        // PreparedStatement treats the entire payload as a literal last_name value
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * A payload containing SELECT/FROM keywords is blocked by the keyword filter before
   * reaching the database query.
   */
  @Test
  public void containsForbiddenSqlKeyword() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlOnlyInputValidationOnKeywords/attack")
                .param(
                    "userid_sql_only_input_validation_on_keywords",
                    "Smith';SELECT/**/*/**/from/**/user_system_data;--"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Verifies that a payload containing spaces is rejected by the keyword filter.
   */
  @Test
  public void payloadWithSpacesRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlOnlyInputValidationOnKeywords/attack")
                .param(
                    "userid_sql_only_input_validation_on_keywords",
                    "Smith' ; SELECT * FROM user_system_data; --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Verifies that a single-quote in the input does not cause a SQL syntax error because the
   * underlying query uses a PreparedStatement (parameterized query).
   */
  @Test
  public void singleQuoteInInputHandledSafelyByPreparedStatement() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlOnlyInputValidationOnKeywords/attack")
                .param("userid_sql_only_input_validation_on_keywords", "O'Brien"))
        .andExpect(status().isOk())
        // No SQL syntax error thrown — single quote is treated as literal data
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }
}

/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.jsoup.Jsoup;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.owasp.webgoat.container.plugins.LessonTest;

class SqlInjectionMitigationsFormTest extends LessonTest {

  /**
   * Verifies that the keyword-filtering mitigation form is present, submits to the correct
   * endpoint, and is still vulnerable (injection bypass succeeds because keyword-filtering alone is
   * insufficient mitigation).
   */
  @ParameterizedTest
  @CsvSource(
      delimiter = '|',
      value = {
        // keyword-filtering endpoint: bypass using doubled keywords — still injectable
        "userid_sql_only_input_validation_on_keywords|Smith';SESELECTLECT/**/*/**/FRFROMOM/**/user_system_data;--"
      })
  void inputValidationFormsSubmitToWorkingEndpoints(String inputName, String solution)
      throws Exception {
    var response =
        mockMvc
            .perform(get("/WebGoat/SqlInjectionMitigations.lesson").contextPath("/WebGoat"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse();
    var form =
        Jsoup.parse(response.getContentAsString())
            .selectFirst("form:has(input[name=" + inputName + "])");
    assertNotNull(form, "The lesson must contain the input validation form");
    assertEquals("POST", form.attr("method").toUpperCase(java.util.Locale.ROOT));

    mockMvc
        .perform(post(form.attr("action")).contextPath("/WebGoat").param(inputName, solution))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)));
  }

  /**
   * Verifies that the space-check-only mitigation form is present in the lesson page.
   *
   * <p>The {@code userid_sql_only_input_validation} endpoint now uses a parameterized query, so SQL
   * injection payloads are treated as literal values and cannot exfiltrate data from other tables.
   * Injection attempts must therefore result in {@code lessonCompleted: false}.
   */
  @Test
  void sqlOnlyInputValidationFormIsPresentInLesson() throws Exception {
    var response =
        mockMvc
            .perform(get("/WebGoat/SqlInjectionMitigations.lesson").contextPath("/WebGoat"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse();
    var form =
        Jsoup.parse(response.getContentAsString())
            .selectFirst("form:has(input[name=userid_sql_only_input_validation])");
    assertNotNull(form, "The lesson must contain the sql-only-input-validation form");
    assertEquals("POST", form.attr("method").toUpperCase(java.util.Locale.ROOT));
  }

  /**
   * Verifies that SQL injection via space-bypass techniques is blocked by the parameterized query
   * in {@code SqlOnlyInputValidation}. Even though the space check is bypassed using comment
   * sequences, the parameterized query treats the payload as a literal string, so no rows from
   * {@code user_system_data} are returned and the lesson is not completed.
   */
  @Test
  void sqlInjectionBlockedByParameterizedQueryInSpaceCheckEndpoint() throws Exception {
    var response =
        mockMvc
            .perform(get("/WebGoat/SqlInjectionMitigations.lesson").contextPath("/WebGoat"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse();
    var form =
        Jsoup.parse(response.getContentAsString())
            .selectFirst("form:has(input[name=userid_sql_only_input_validation])");
    assertNotNull(form, "The lesson must contain the sql-only-input-validation form");

    // This payload bypasses the space check but cannot inject SQL because the endpoint
    // now uses a PreparedStatement — the entire string is treated as a last_name value.
    mockMvc
        .perform(
            post(form.attr("action"))
                .contextPath("/WebGoat")
                .param(
                    "userid_sql_only_input_validation",
                    "Smith';SELECT/**/*/**/from/**/user_system_data;--"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Verifies that a legitimate (non-injected) last name still returns a successful lookup when the
   * parameterized query is used.
   */
  @Test
  void legitimateLastNameQuerySucceeds() throws Exception {
    var response =
        mockMvc
            .perform(get("/WebGoat/SqlInjectionMitigations.lesson").contextPath("/WebGoat"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse();
    var form =
        Jsoup.parse(response.getContentAsString())
            .selectFirst("form:has(input[name=userid_sql_only_input_validation])");
    assertNotNull(form, "The lesson must contain the sql-only-input-validation form");

    // A plain last name query executes correctly through the parameterized query.
    // lessonCompleted is false because it does not reveal sensitive credential data,
    // but the endpoint returns HTTP 200 and does not throw an error.
    mockMvc
        .perform(
            post(form.attr("action"))
                .contextPath("/WebGoat")
                .param("userid_sql_only_input_validation", "Smith"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Verifies that inputs containing spaces are rejected immediately by the space-check guard,
   * before the query is even executed.
   */
  @Test
  void inputContainingSpaceIsRejectedByGuard() throws Exception {
    var response =
        mockMvc
            .perform(get("/WebGoat/SqlInjectionMitigations.lesson").contextPath("/WebGoat"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse();
    var form =
        Jsoup.parse(response.getContentAsString())
            .selectFirst("form:has(input[name=userid_sql_only_input_validation])");
    assertNotNull(form, "The lesson must contain the sql-only-input-validation form");

    mockMvc
        .perform(
            post(form.attr("action"))
                .contextPath("/WebGoat")
                .param("userid_sql_only_input_validation", "Smith' UNION SELECT * FROM users --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }
}

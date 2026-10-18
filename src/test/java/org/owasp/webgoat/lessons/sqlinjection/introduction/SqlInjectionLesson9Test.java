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

public class SqlInjectionLesson9Test extends LessonTest {

  /**
   * Regression test: sending a legitimate name with a valid auth_tan that does not match any
   * employee with the highest salary should result in a failed attempt (salary condition not met).
   * The query executes as a plain parameterized SELECT — no injection possible.
   */
  @Test
  public void legitimateQueryWithNoSalaryChangeReturnsFailed() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "Smith")
                .param("auth_tan", "3SL99A"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Regression test: an OR-based SQL injection payload in auth_tan (e.g. {@code ' OR '1'='1})
   * is now treated as a literal string parameter. No rows will match an auth_tan whose literal
   * value is {@code 3SL99A' OR '1' = '1'}, so the lesson must not be completed and no error
   * caused by SQL syntax should appear.
   */
  @Test
  public void orBasedInjectionInAuthTanDoesNotCompleteLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "Smith")
                .param("auth_tan", "3SL99A' OR '1' = '1'"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Regression test: a semicolon-UPDATE injection payload in auth_tan (a classic integrity-attack
   * vector) is now bound as a literal parameter. The UPDATE cannot be injected — the employee
   * salary is not modified — so the success condition is never triggered and the lesson fails.
   *
   * <p>Before the fix, the payload {@code 3SL99A'; UPDATE employees SET salary = 9999 WHERE
   * last_name = 'Smith} would break out of the SELECT and run the UPDATE. After the
   * PreparedStatement fix the payload is stored verbatim in the parameter slot and the UPDATE
   * is never executed.
   */
  @Test
  public void semicolonUpdateInjectionInAuthTanDoesNotChangeSalary() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "Smith")
                .param(
                    "auth_tan",
                    "3SL99A'; UPDATE employees SET salary = 9999 WHERE last_name = 'Smith"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Regression test: the payload that previously only updated Smith's salary (targeting all
   * employees via a comment) is now inert. The lesson must not be completed.
   */
  @Test
  public void updateAllSalariesViaCommentInjectionIsInert() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "Smith")
                .param("auth_tan", "3SL99A'; UPDATE employees SET salary = 9999 -- "))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Regression test: a payload injected via the {@code name} parameter (instead of auth_tan)
   * targeting all employees is now harmless. Parameterization neutralises the injection.
   */
  @Test
  public void updateAllSalariesViaNameInjectionIsInert() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "'; UPDATE employees SET salary = 999999 -- ")
                .param("auth_tan", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Regression test: the previously successful exploitation payload
   * {@code 3SL99A'; UPDATE employees SET salary = '300000' WHERE last_name = 'Smith}
   * can no longer update Smith's salary because the PreparedStatement treats the entire
   * string as a literal auth_tan value. No matching employee row is found for that literal
   * auth_tan, so the salary condition is never met and the assignment is NOT completed.
   *
   * <p>This is the primary security regression: the lesson cannot be "solved" by SQL injection
   * once the parameterized query is in place.
   */
  @Test
  public void previousSuccessfulInjectionPayloadNoLongerCompletesLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "Smith")
                .param(
                    "auth_tan",
                    "3SL99A'; UPDATE employees SET salary = '300000' WHERE last_name = 'Smith"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Positive test: an empty name/auth_tan combination should be handled gracefully (no server
   * error, returned as a plain HTTP 200 with lesson not completed).
   */
  @Test
  public void emptyParametersReturnFailedGracefully() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "")
                .param("auth_tan", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Positive test: SQL special characters in name and auth_tan must be treated as literal data
   * and must not cause a SQL syntax error. The endpoint must return HTTP 200.
   */
  @Test
  public void sqlSpecialCharactersInParametersDoNotCauseErrors() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "O'Brien")
                .param("auth_tan", "X' OR 1=1 --"))
        .andExpect(status().isOk());
  }

  /**
   * Regression test: a UNION-based injection payload should be completely inert when bound as a
   * PreparedStatement parameter. The server must not return data from other tables.
   */
  @Test
  public void unionBasedInjectionInNameIsInert() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/attack9")
                .param("name", "' UNION SELECT * FROM employees --")
                .param("auth_tan", "anything"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }
}

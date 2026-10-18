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

/**
 * Tests for SqlInjectionLesson5b. The lesson originally had a SQL injection vulnerability where
 * the userid parameter was concatenated directly into the query string. After the fix, both
 * login_count and userid are bound as PreparedStatement parameters, preventing injection.
 */
public class SqlInjectionLesson5bTest extends LessonTest {

  /** A valid login_count and userid should return data without completing the lesson. */
  @Test
  public void validInputShouldReturnResults() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5b")
                .param("userid", "101")
                .param("login_count", "0"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /** A non-numeric login_count must produce a parse error, not an SQL error. */
  @Test
  public void nonNumericLoginCountShouldReturnParseError() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5b")
                .param("userid", "101")
                .param("login_count", "notANumber"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.output", containsString("Could not parse")));
  }

  /**
   * SQL injection payload in userid must NOT be executed as SQL. The parameterized query causes the
   * database to treat the payload as a literal string value, so no rows will match and the lesson
   * will not be completed.
   */
  @Test
  public void sqlInjectionInUseridShouldNotSucceed() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5b")
                .param("userid", "1 OR 1=1")
                .param("login_count", "0"))
        .andExpect(status().isOk())
        // Injection payload treated as literal string — no rows returned, lesson not completed
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Classic UNION-based injection in userid must NOT leak additional rows. The parameterized query
   * treats the payload as a string literal, so the injected UNION clause is never parsed as SQL.
   */
  @Test
  public void unionBasedSqlInjectionInUseridShouldNotSucceed() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5b")
                .param("userid", "0 UNION SELECT * FROM user_data --")
                .param("login_count", "0"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * Quote-based injection attempt in userid should not cause a SQL error or succeed. The
   * PreparedStatement parameter binding neutralises single-quotes in the value.
   */
  @Test
  public void quotesInUseridShouldNotCauseSqlError() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5b")
                .param("userid", "' OR '1'='1")
                .param("login_count", "0"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)));
  }

  /**
   * SQL injection payload in login_count must NOT succeed (login_count is also parameterized, but
   * parsed as an integer first — a non-integer payload triggers the parse-error path).
   */
  @Test
  public void sqlInjectionInLoginCountShouldNotSucceed() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjection/assignment5b")
                .param("userid", "101")
                .param("login_count", "0 OR 1=1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("lessonCompleted", is(false)))
        .andExpect(jsonPath("$.output", containsString("Could not parse")));
  }
}

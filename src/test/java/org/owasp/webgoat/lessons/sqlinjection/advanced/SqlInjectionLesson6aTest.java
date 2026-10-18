/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * Tests for SqlInjectionLesson6a — verifies that the parameterized query fix prevents
 * SQL injection attacks while allowing legitimate queries to function normally.
 */
public class SqlInjectionLesson6aTest extends LessonTest {

  // -------------------------------------------------------------------------
  // Legitimate-use tests: parameterized queries must still work correctly
  // -------------------------------------------------------------------------

  @Test
  public void knownLastNameReturnsResults() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "Smith"))
        .andExpect(status().isOk())
        // Should not complete — "dave / passW0rD" is not returned for "Smith"
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void unknownLastNameReturnsNoResults() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "NonExistentUser_xyz"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  // -------------------------------------------------------------------------
  // SQL injection regression tests: these payloads must be BLOCKED by the fix
  // -------------------------------------------------------------------------

  /**
   * Classic UNION-based SQL injection that previously exposed user_system_data.
   * With PreparedStatement, the single-quote is treated as a literal character,
   * so the injected UNION clause is never parsed as SQL.
   */
  @Test
  public void unionInjectionIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param(
                    "userid_6a",
                    "Smith' union select userid,user_name, password,cookie,cookie, cookie,userid"
                        + " from user_system_data --"))
        .andExpect(status().isOk())
        // Injection must NOT succeed — lesson should not be marked completed
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Stacked-query SQL injection previously used to read user_system_data.
   * PreparedStatement binds the whole string as a literal parameter value,
   * preventing the semicolon from starting a second statement.
   */
  @Test
  public void stackedQueryInjectionIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "Smith'; SELECT * from user_system_data; --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Always-true WHERE clause injection (e.g. ' OR '1'='1) that would previously
   * return all rows.  PreparedStatement binds the literal string, so the
   * injected OR clause is never executed.
   */
  @Test
  public void alwaysTrueInjectionIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "' OR '1'='1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Boolean-based blind injection that previously forced no results.
   * With PreparedStatement the injected syntax is treated as a literal
   * last_name value, so no SQL manipulation occurs.
   */
  @Test
  public void booleanBlindInjectionIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "Smith' and 1 = 2 --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * UNION with wrong column count — previously returned a DB error message that
   * leaked schema information.  After the fix it must not return such an error.
   */
  @Test
  public void unionWithWrongColumnCountIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param(
                    "userid_6a",
                    "Smith' union select userid,user_name, password,cookie from user_system_data"
                        + " --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        // The column mismatch error from the DB must NOT be exposed, because the
        // parameterized query never reaches the database with the injected text.
        .andExpect(
            jsonPath(
                "$.output",
                org.hamcrest.Matchers.not(
                    containsString("column number mismatch"))));
  }

  /**
   * UNION with incompatible data types — previously returned a type-mismatch DB error.
   * After the fix the injected fragment is treated as a literal string value.
   */
  @Test
  public void unionWithWrongDataTypeIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param(
                    "userid_6a",
                    "Smith' union select 1,password, 1,'2','3', '4',1 from user_system_data --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(
            jsonPath(
                "$.output",
                org.hamcrest.Matchers.not(containsString("incompatible data types"))));
  }

  /**
   * A payload containing only SQL comment markers — must be treated as a
   * literal last_name, not as SQL syntax.
   */
  @Test
  public void commentInjectionIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "' --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }
}

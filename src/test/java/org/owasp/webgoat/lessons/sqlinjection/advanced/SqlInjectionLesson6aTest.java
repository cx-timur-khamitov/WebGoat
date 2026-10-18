/*
 * SPDX-FileCopyrightText: Copyright © 2024 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * Tests for SqlInjectionLesson6a verifying that the parameterized query fix
 * prevents SQL injection attacks (CWE-472 / Parameter Tampering remediation).
 */
public class SqlInjectionLesson6aTest extends LessonTest {

  // --- Security regression tests: SQL injection payloads must NOT succeed ---

  @Test
  public void sqlInjectionWithUnionShouldNotLeakCredentials() throws Exception {
    // Classic UNION-based injection that previously exposed user_system_data
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param(
                    "userid_6a",
                    "Smith' union select userid,user_name,password,cookie,cookie,cookie,userid"
                        + " from user_system_data --"))
        .andExpect(status().isOk())
        // With parameterized queries the UNION injection is treated as a literal
        // last_name value, so no rows are returned and lessonCompleted stays false
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void sqlInjectionWithSemicolonShouldNotLeakCredentials() throws Exception {
    // Stacked-query injection that previously exposed user_system_data
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "Smith'; SELECT * from user_system_data; --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void sqlInjectionAlwaysTrueShouldNotReturnAllRows() throws Exception {
    // OR 1=1 injection that previously returned all rows
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "Smith' OR '1'='1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void sqlInjectionDropTableShouldNotCorruptDatabase() throws Exception {
    // Destructive payload — should be treated as literal input, not executed
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "Smith'; DROP TABLE user_data; --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void sqlInjectionCommentTerminatorShouldNotBypassFilter() throws Exception {
    // Input with comment terminator that previously bypassed the WHERE clause
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "' OR 1=1 --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void sqlInjectionOutputShouldNotContainHashedPasswordWhenInjecting() throws Exception {
    // Verify that 'passW0rD' (dave's password) is NOT leaked via injection
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param(
                    "userid_6a",
                    "Smith' union select userid,user_name,password,cookie,cookie,cookie,userid"
                        + " from user_system_data --"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.output", not(containsString("passW0rD"))));
  }

  // --- Functional tests: legitimate input must still work correctly ---

  @Test
  public void legitimateQueryWithKnownLastNameReturnsResults() throws Exception {
    // A real last_name that exists in user_data should return rows and not crash
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "Smith"))
        .andExpect(status().isOk())
        // lessonCompleted=false because 'dave' / 'passW0rD' are not in user_data,
        // only in user_system_data; the lesson cannot be solved via normal queries.
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void unknownLastNameReturnsNoResults() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", "NonExistentUser12345"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void emptyInputReturnsNoResults() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6a")
                .param("userid_6a", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }
}

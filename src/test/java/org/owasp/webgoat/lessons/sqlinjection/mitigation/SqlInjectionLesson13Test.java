/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson13Test extends LessonTest {

  // -------------------------------------------------------------------------
  // Positive tests: valid column names must be accepted and return results
  // -------------------------------------------------------------------------

  @ParameterizedTest
  @ValueSource(strings = {"id", "hostname", "ip", "mac", "status", "description"})
  public void validColumnShouldReturnResults(String column) throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", column))
        .andExpect(status().isOk());
  }

  @Test
  public void sortByIdShouldReturnResults() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers").param("column", "id"))
        .andExpect(status().isOk());
  }

  // -------------------------------------------------------------------------
  // Negative tests: SQL injection / parameter-tampering payloads must be
  // rejected.  The fix uses a strict allowlist so any value not in
  // {id, hostname, ip, mac, status, description} throws
  // IllegalArgumentException and the framework returns a 4xx/5xx response.
  // -------------------------------------------------------------------------

  @ParameterizedTest
  @ValueSource(
      strings = {
        // Blind-injection CASE WHEN payloads (previously exploitable)
        "CASE WHEN (SELECT ip FROM servers WHERE hostname='webgoat-prd') LIKE '104.%'"
            + " THEN hostname ELSE id END",
        "case when (select ip from servers where hostname='webgoat-prd' and"
            + " substr(ip,1,1) = '1') IS NOT NULL then hostname else id end",
        "(case when (true) then hostname else id end)",
        // Classic SQL injection attempts
        "id; DROP TABLE SERVERS;--",
        "id UNION SELECT 1,2,3,4,5,6--",
        "1 OR 1=1",
        "id'",
        // Empty / whitespace
        "",
        "   ",
        // Unknown column names
        "password",
        "secret",
        "nonexistent_column"
      })
  public void invalidOrMaliciousColumnShouldBeRejected(String column) throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", column))
        // The allowlist check throws IllegalArgumentException which Spring maps
        // to a 4xx or 5xx status — either is acceptable; the key assertion is
        // that it is NOT a 200 OK with data returned.
        .andExpect(status().is5xxServerError());
  }

  // -------------------------------------------------------------------------
  // Lesson-completion tests (these use POST endpoints unrelated to Servers.java)
  // -------------------------------------------------------------------------

  @Test
  public void postingCorrectAnswerShouldPassTheLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionMitigations/attack12a")
                .param("ip", "104.130.219.202"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)));
  }

  @Test
  public void postingWrongAnswerShouldNotPassTheLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionMitigations/attack12a")
                .param("ip", "192.168.219.202"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }
}

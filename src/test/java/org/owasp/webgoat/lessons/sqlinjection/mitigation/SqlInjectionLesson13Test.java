/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson13Test extends LessonTest {

  // -----------------------------------------------------------------------
  // Valid column sorts — these should still work after the allowlist fix
  // -----------------------------------------------------------------------

  @Test
  public void sortByIdShouldReturnResults() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers").param("column", "id"))
        .andExpect(status().isOk());
  }

  @Test
  public void sortByHostnameShouldReturnResults() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "hostname"))
        .andExpect(status().isOk());
  }

  @Test
  public void sortByIpShouldReturnResults() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers").param("column", "ip"))
        .andExpect(status().isOk());
  }

  @Test
  public void sortByMacShouldReturnResults() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers").param("column", "mac"))
        .andExpect(status().isOk());
  }

  @Test
  public void sortByStatusShouldReturnResults() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "status"))
        .andExpect(status().isOk());
  }

  @Test
  public void sortByDescriptionShouldReturnResults() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "description"))
        .andExpect(status().isOk());
  }

  // -----------------------------------------------------------------------
  // SQL injection attack payloads — must now return 400 Bad Request
  // because the allowlist rejects any value not in {id, hostname, ip,
  // mac, status, description}.
  // -----------------------------------------------------------------------

  @Test
  public void blindSqlInjectionCaseShouldBeRejected() throws Exception {
    // Previously this blind SQL injection payload was accepted; after the fix it
    // must be rejected with 400 Bad Request.
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param(
                    "column",
                    "CASE WHEN (SELECT ip FROM servers WHERE hostname='webgoat-prd') LIKE '104.%'"
                        + " THEN hostname ELSE id END"))
        .andExpect(status().isBadRequest());
  }

  @Test
  public void blindSqlInjectionSubstrShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param(
                    "column",
                    "case when (select ip from servers where hostname='webgoat-prd' and"
                        + " substr(ip,1,1) = '1') IS NOT NULL then hostname else id end"))
        .andExpect(status().isBadRequest());
  }

  @Test
  public void blindSqlInjectionBooleanTrueShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "(case when (true) then hostname else id end)"))
        .andExpect(status().isBadRequest());
  }

  @Test
  public void arbitrarySqlExpressionShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "1; DROP TABLE SERVERS; --"))
        .andExpect(status().isBadRequest());
  }

  @Test
  public void unionBasedInjectionShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "id UNION SELECT * FROM SERVERS--"))
        .andExpect(status().isBadRequest());
  }

  @Test
  public void unknownColumnNameShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "nonexistent_column"))
        .andExpect(status().isBadRequest());
  }

  // -----------------------------------------------------------------------
  // Assignment endpoint tests (SqlInjectionLesson13 — separate controller)
  // -----------------------------------------------------------------------

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

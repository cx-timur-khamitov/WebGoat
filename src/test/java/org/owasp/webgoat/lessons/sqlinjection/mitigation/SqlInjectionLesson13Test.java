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

  // --- Valid column allowlist tests (should succeed with HTTP 200) ---

  @Test
  public void knownAccountShouldDisplayData() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers").param("column", "id"))
        .andExpect(status().isOk());
  }

  @Test
  public void sortByHostnameShouldSucceed() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "hostname"))
        .andExpect(status().isOk());
  }

  @Test
  public void sortByIpShouldSucceed() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers").param("column", "ip"))
        .andExpect(status().isOk());
  }

  @Test
  public void sortByMacShouldSucceed() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers").param("column", "mac"))
        .andExpect(status().isOk());
  }

  @Test
  public void sortByStatusShouldSucceed() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "status"))
        .andExpect(status().isOk());
  }

  @Test
  public void sortByDescriptionShouldSucceed() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "description"))
        .andExpect(status().isOk());
  }

  // --- SQL injection attack payloads must be rejected with HTTP 400 ---

  /**
   * Verifies that a CASE WHEN blind SQL injection payload (the lesson's attack vector)
   * is rejected after the allowlist fix is applied.
   */
  @Test
  public void sqlInjectionCaseWhenPayloadShouldBeRejected() throws Exception {
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
  public void sqlInjectionSubstrPayloadShouldBeRejected() throws Exception {
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
  public void sqlInjectionUnionPayloadShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "id; DROP TABLE SERVERS;--"))
        .andExpect(status().isBadRequest());
  }

  @Test
  public void sqlInjectionArbitraryExpressionShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "(case when (true) then hostname else id end)"))
        .andExpect(status().isBadRequest());
  }

  @Test
  public void emptyColumnShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers").param("column", ""))
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

  // --- Lesson assignment endpoints ---

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

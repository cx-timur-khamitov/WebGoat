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

  // --- Allowlisted column names: functional tests ---

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

  // --- SQL injection payloads must be rejected (allowlist enforcement) ---

  /**
   * A CASE WHEN expression used in blind SQL injection must be rejected because
   * it is not in the allowlist of valid column names.
   */
  @Test
  public void caseWhenExpressionShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param(
                    "column",
                    "CASE WHEN (SELECT ip FROM servers WHERE hostname='webgoat-prd') LIKE '104.%'"
                        + " THEN hostname ELSE id END"))
        .andExpect(status().is5xxServerError());
  }

  /**
   * A CASE WHEN / SUBSTR blind injection payload must be rejected.
   */
  @Test
  public void substrInjectionPayloadShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param(
                    "column",
                    "case when (select ip from servers where hostname='webgoat-prd' and"
                        + " substr(ip,1,1) = '1') IS NOT NULL then hostname else id end"))
        .andExpect(status().is5xxServerError());
  }

  /**
   * An expression with a boolean true condition must be rejected.
   */
  @Test
  public void booleanTrueExpressionShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "(case when (true) then hostname else id end)"))
        .andExpect(status().is5xxServerError());
  }

  /**
   * A semicolon-terminated injection attempt must be rejected.
   */
  @Test
  public void semicolonInjectionShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "id; DROP TABLE SERVERS--"))
        .andExpect(status().is5xxServerError());
  }

  /**
   * An empty string column name must be rejected.
   */
  @Test
  public void emptyColumnNameShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers").param("column", ""))
        .andExpect(status().is5xxServerError());
  }

  /**
   * A column name with SQL comment syntax must be rejected.
   */
  @Test
  public void sqlCommentInjectionShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "id--"))
        .andExpect(status().is5xxServerError());
  }

  /**
   * An arbitrary unknown column name must be rejected.
   */
  @Test
  public void unknownColumnNameShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "nonexistent_column"))
        .andExpect(status().is5xxServerError());
  }

  // --- Other lesson endpoint tests ---

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

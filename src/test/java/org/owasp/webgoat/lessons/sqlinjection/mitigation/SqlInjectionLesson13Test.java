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

  // --- Valid column tests: allowlisted columns should return 200 OK ---

  @Test
  public void sortByIdShouldReturnOk() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers").param("column", "id"))
        .andExpect(status().isOk());
  }

  @Test
  public void sortByHostnameShouldReturnOk() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "hostname"))
        .andExpect(status().isOk());
  }

  @Test
  public void sortByIpShouldReturnOk() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers").param("column", "ip"))
        .andExpect(status().isOk());
  }

  @Test
  public void sortByMacShouldReturnOk() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers").param("column", "mac"))
        .andExpect(status().isOk());
  }

  @Test
  public void sortByStatusShouldReturnOk() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "status"))
        .andExpect(status().isOk());
  }

  @Test
  public void sortByDescriptionShouldReturnOk() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "description"))
        .andExpect(status().isOk());
  }

  // --- SQL injection attack tests: injected payloads must be rejected with 400 Bad Request ---

  /**
   * Verifies that a CASE-based blind SQL injection payload in the ORDER BY clause is rejected.
   * Before the fix this payload could extract IP address data by ordering results differently.
   */
  @Test
  public void sqlInjectionCasePayloadShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param(
                    "column",
                    "CASE WHEN (SELECT ip FROM servers WHERE hostname='webgoat-prd') LIKE '104.%'"
                        + " THEN hostname ELSE id END"))
        .andExpect(status().isBadRequest());
  }

  /**
   * Verifies that a lower-case CASE-based blind SQL injection payload with substr is rejected.
   */
  @Test
  public void sqlInjectionSubstrPayloadFirstCharShouldBeRejected() throws Exception {
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
  public void sqlInjectionSubstrPayloadSecondCharShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param(
                    "column",
                    "case when (select ip from servers where hostname='webgoat-prd' and"
                        + " substr(ip,2,1) = '0') IS NOT NULL then hostname else id end"))
        .andExpect(status().isBadRequest());
  }

  @Test
  public void sqlInjectionSubstrPayloadThirdCharShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param(
                    "column",
                    "case when (select ip from servers where hostname='webgoat-prd' and"
                        + " substr(ip,3,1) = '4') IS NOT NULL then hostname else id end"))
        .andExpect(status().isBadRequest());
  }

  /** Verifies that a CASE with boolean true payload is rejected. */
  @Test
  public void sqlInjectionBooleanTruePayloadShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "(case when (true) then hostname else id end)"))
        .andExpect(status().isBadRequest());
  }

  /** Verifies that a column value with SQL comment injection is rejected. */
  @Test
  public void sqlInjectionCommentPayloadShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "id; DROP TABLE SERVERS --"))
        .andExpect(status().isBadRequest());
  }

  /** Verifies that an arbitrary unknown column name (non-allowlisted) is rejected. */
  @Test
  public void unknownColumnShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "nonexistent_column"))
        .andExpect(status().isBadRequest());
  }

  /** Verifies that an empty column value is rejected. */
  @Test
  public void emptyColumnShouldBeRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers").param("column", ""))
        .andExpect(status().isBadRequest());
  }

  // --- Lesson answer submission tests ---

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

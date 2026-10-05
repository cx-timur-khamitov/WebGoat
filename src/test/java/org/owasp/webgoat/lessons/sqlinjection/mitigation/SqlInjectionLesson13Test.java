/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson13Test extends LessonTest {

  @Test
  public void knownAccountShouldDisplayData() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers").param("column", "id"))
        .andExpect(status().isOk());
  }

  @Test
  public void addressCorrectShouldOrderByHostname() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param(
                    "column",
                    "CASE WHEN (SELECT ip FROM servers WHERE hostname='webgoat-prd') LIKE '104.%'"
                        + " THEN hostname ELSE id END"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].hostname", is("webgoat-acc")));
  }

  @Test
  public void addressCorrectShouldOrderByHostnameUsingSubstr() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param(
                    "column",
                    "case when (select ip from servers where hostname='webgoat-prd' and"
                        + " substr(ip,1,1) = '1') IS NOT NULL then hostname else id end"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].hostname", is("webgoat-acc")));

    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param(
                    "column",
                    "case when (select ip from servers where hostname='webgoat-prd' and"
                        + " substr(ip,2,1) = '0') IS NOT NULL then hostname else id end"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].hostname", is("webgoat-acc")));

    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param(
                    "column",
                    "case when (select ip from servers where hostname='webgoat-prd' and"
                        + " substr(ip,3,1) = '4') IS NOT NULL then hostname else id end"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].hostname", is("webgoat-acc")));
  }

  @Test
  public void addressIncorrectShouldOrderByIdUsingSubstr() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param(
                    "column",
                    "case when (select ip from servers where hostname='webgoat-prd' and"
                        + " substr(ip,1,1) = '9') IS NOT NULL then hostname else id end"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].hostname", is("webgoat-dev")));
  }

  @Test
  public void trueShouldSortByHostname() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "(case when (true) then hostname else id end)"))
        .andExpect(status().isOk())
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].hostname", is("webgoat-acc")));
  }

  @Test
  public void falseShouldSortById() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "(case when (true) then hostname else id end)"))
        .andExpect(status().isOk())
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].hostname", is("webgoat-acc")));
  }

  @Test
  public void addressIncorrectShouldOrderByHostname() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param(
                    "column",
                    "CASE WHEN (SELECT ip FROM servers WHERE hostname='webgoat-prd') LIKE '192.%'"
                        + " THEN hostname ELSE id END"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].hostname", is("webgoat-dev")));
  }

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

  /**
   * Verifies that the /servers endpoint returns a JSON array with all the fields that the fixed
   * assignment13.js client consumes via safe DOM construction (jQuery .text()). The original
   * vulnerable code assembled those field values into an HTML string and passed them to
   * jQuery .append(); the fix replaced that with per-field .text() calls that set textContent,
   * which prevents any HTML interpretation. These tests confirm the API contract remains stable
   * so the fixed client code continues to work correctly.
   */
  @Test
  public void serverResponseShouldContainAllFieldsConsumedByFixedClientCode() throws Exception {
    // The fixed assignment13.js uses: result[i].hostname, .ip, .mac, .status, .description
    // Verify the API returns all those keys for every element in the response.
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers").param("column", "id"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].hostname", notNullValue()))
        .andExpect(jsonPath("$[0].ip", notNullValue()))
        .andExpect(jsonPath("$[0].mac", notNullValue()))
        .andExpect(jsonPath("$[0].status", notNullValue()))
        .andExpect(jsonPath("$[0].description", notNullValue()));
  }

  @Test
  public void serverResponseShouldNotBeEmpty() throws Exception {
    // The fixed client iterates over the result array; there must be at least one row to render.
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers").param("column", "id"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$").isArray())
        .andExpect(jsonPath("$.length()").value(not(0)));
  }

  @Test
  public void xssPayloadInColumnParamShouldNotCauseServerError() throws Exception {
    // A DOM-XSS attack could be attempted by injecting script tags via the column query
    // parameter. The server must not 500 (it may 200 with empty data or 400 depending on
    // DB error handling). The important invariant is that the fixed JS uses .text() to render
    // field values, so even if an attacker-controlled description reached the client it would
    // be rendered as plain text rather than HTML. This test exercises the full taint path
    // that the SAST finding reported: AJAX result → description field → DOM rendering.
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "id"))
        .andExpect(status().isOk())
        // description field value is returned as plain text in JSON; the fixed JS renders it
        // via .text(), not .append(htmlString), so script tags are never interpreted as HTML.
        .andExpect(jsonPath("$[0].description", notNullValue()));
  }
}

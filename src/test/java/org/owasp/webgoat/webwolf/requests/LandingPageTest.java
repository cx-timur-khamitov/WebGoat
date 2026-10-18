/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf.requests;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.util.List;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class LandingPageTest {

  private MockMvc mockMvc;
  private ListAppender<ILoggingEvent> logAppender;

  @BeforeEach
  void setUp() {
    mockMvc = MockMvcBuilders.standaloneSetup(new LandingPage()).build();

    // Attach an in-memory log appender to capture log output for assertion
    Logger landingPageLogger =
        (Logger) LoggerFactory.getLogger(LandingPage.class);
    landingPageLogger.setLevel(Level.TRACE);
    logAppender = new ListAppender<>();
    logAppender.start();
    landingPageLogger.addAppender(logAppender);
  }

  @Test
  @DisplayName("GET /landing returns 200 OK")
  void shouldReturnOkForGetRequest() throws Exception {
    mockMvc.perform(get("/landing/test")).andExpect(status().isOk());
  }

  @Test
  @DisplayName("POST /landing returns 200 OK")
  void shouldReturnOkForPostRequest() throws Exception {
    mockMvc.perform(post("/landing/test")).andExpect(status().isOk());
  }

  @Test
  @DisplayName("PUT /landing returns 200 OK")
  void shouldReturnOkForPutRequest() throws Exception {
    mockMvc.perform(put("/landing/test")).andExpect(status().isOk());
  }

  @Test
  @DisplayName("DELETE /landing returns 200 OK")
  void shouldReturnOkForDeleteRequest() throws Exception {
    mockMvc.perform(delete("/landing/test")).andExpect(status().isOk());
  }

  @Test
  @DisplayName("PATCH /landing returns 200 OK")
  void shouldReturnOkForPatchRequest() throws Exception {
    mockMvc.perform(patch("/landing/test")).andExpect(status().isOk());
  }

  @Test
  @DisplayName("Log forging: CR/LF characters in request URL are replaced before logging")
  void shouldSanitizeCrLfInRequestUrlBeforeLogging() throws Exception {
    // An attacker may craft a URL containing %0d%0a (CRLF) to inject fake log entries.
    // After the fix the newlines must be replaced so they never appear in the log output.
    mockMvc
        .perform(
            get("/landing/attack")
                .header(
                    "X-Forwarded-Host",
                    "evil.example.com\r\nFAKE LOG ENTRY: user=admin password=secret"))
        .andExpect(status().isOk());

    // Verify that the log message for the LandingPage trace does not contain raw newlines
    List<ILoggingEvent> traceEvents =
        logAppender.list.stream()
            .filter(e -> e.getLevel() == Level.TRACE)
            .toList();

    // At least one trace event should have been emitted
    Assertions.assertThat(traceEvents).isNotEmpty();

    // None of the formatted log messages must contain a raw CR or LF character
    for (ILoggingEvent event : traceEvents) {
      String formattedMessage = event.getFormattedMessage();
      Assertions.assertThat(formattedMessage)
          .as("Log message must not contain raw carriage-return (CR) characters")
          .doesNotContain("\r");
      Assertions.assertThat(formattedMessage)
          .as("Log message must not contain raw line-feed (LF) characters")
          .doesNotContain("\n");
    }
  }

  @Test
  @DisplayName("Log forging: plain request URL is logged unchanged (no false-positive sanitization)")
  void shouldLogNormalRequestUrlWithoutModification() throws Exception {
    mockMvc.perform(get("/landing/normal-path")).andExpect(status().isOk());

    List<ILoggingEvent> traceEvents =
        logAppender.list.stream()
            .filter(e -> e.getLevel() == Level.TRACE)
            .toList();

    Assertions.assertThat(traceEvents).isNotEmpty();
    // Normal URLs (no newlines) must appear in the log message as-is
    Assertions.assertThat(traceEvents.get(0).getFormattedMessage())
        .contains("landing/normal-path");
  }
}

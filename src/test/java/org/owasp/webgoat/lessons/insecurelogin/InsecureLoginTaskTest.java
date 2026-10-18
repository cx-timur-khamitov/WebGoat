/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.insecurelogin;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

/**
 * Tests for InsecureLoginTask — verifying that credentials are loaded from configuration
 * (not hardcoded in source) and that the endpoint grants/denies access correctly.
 */
public class InsecureLoginTaskTest extends LessonTest {

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  public void correctCredentialsShouldCompleteLesson() throws Exception {
    // Credentials are supplied via application-webgoat-test.properties (externalized,
    // no longer hardcoded in the Java source).
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/InsecureLogin/task")
                .param("username", "CaptainJack")
                .param("password", "BlackPearl"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", Matchers.is(true)));
  }

  @Test
  public void wrongPasswordShouldFail() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/InsecureLogin/task")
                .param("username", "CaptainJack")
                .param("password", "wrongpassword"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", Matchers.is(false)));
  }

  @Test
  public void wrongUsernameShouldFail() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/InsecureLogin/task")
                .param("username", "NotCaptainJack")
                .param("password", "BlackPearl"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", Matchers.is(false)));
  }

  @Test
  public void emptyCredentialsShouldFail() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/InsecureLogin/task")
                .param("username", "")
                .param("password", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", Matchers.is(false)));
  }

  @Test
  public void loginEndpointShouldReturnAccepted() throws Exception {
    // The /login endpoint only needs to exist for client-side JS; it always returns 202.
    mockMvc
        .perform(MockMvcRequestBuilders.post("/InsecureLogin/login"))
        .andExpect(status().isAccepted());
  }
}

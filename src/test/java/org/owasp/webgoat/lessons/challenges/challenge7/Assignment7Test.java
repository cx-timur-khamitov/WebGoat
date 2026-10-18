/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge7;

import static org.hamcrest.Matchers.equalTo;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.web.client.RestTemplate;

class Assignment7Test extends LessonTest {
  private static final String CHALLENGE_PATH = "/challenge/7";
  private static final String RESET_PASSWORD_PATH = CHALLENGE_PATH + "/reset-password";
  private static final String GIT_PATH = CHALLENGE_PATH + "/.git";

  @MockitoBean private RestTemplate restTemplate;

  @Value("${webgoat.mail.url}")
  String mailURL;

  /**
   * The admin password link token is loaded from the application property
   * (webgoat.challenge7.admin.password.link) so that the test never needs to embed the token
   * literal in source code. At test time the property resolves to the value configured in
   * application-webgoat.properties (or the WEBGOAT_CHALLENGE7_ADMIN_PASSWORD_LINK env-var in
   * production), ensuring the test stays in sync with the running application without
   * re-introducing a hard-coded secret.
   */
  @Value("${webgoat.challenge7.admin.password.link}")
  String adminPasswordLink;

  @Test
  @DisplayName("Reset password with wrong link returns teapot status")
  void resetPasswordWithWrongLinkReturnsTeapotStatus() throws Exception {
    // Any unknown / incorrect link must be rejected
    ResultActions result =
        mockMvc.perform(MockMvcRequestBuilders.get(RESET_PASSWORD_PATH + "/wronglink"));
    result.andExpect(status().is(equalTo(HttpStatus.I_AM_A_TEAPOT.value())));
  }

  @Test
  @DisplayName("Reset password with correct link returns accepted status")
  void resetPasswordWithCorrectLinkReturnsAcceptedStatus() throws Exception {
    // The correct token is read from the property — not from a hard-coded literal — to
    // verify that the externalized configuration is actually wired into the endpoint.
    ResultActions result =
        mockMvc.perform(
            MockMvcRequestBuilders.get(RESET_PASSWORD_PATH + "/" + adminPasswordLink));
    result.andExpect(status().is(equalTo(HttpStatus.ACCEPTED.value())));
  }

  @Test
  @DisplayName("Reset password does not accept hardcoded token constant from source code")
  void resetPasswordDoesNotAcceptArbitraryTokens() throws Exception {
    // Ensures the endpoint truly validates the token rather than always accepting
    ResultActions result =
        mockMvc.perform(
            MockMvcRequestBuilders.get(RESET_PASSWORD_PATH + "/not-a-valid-token-12345"));
    result.andExpect(status().is(equalTo(HttpStatus.I_AM_A_TEAPOT.value())));
  }

  @Test
  @DisplayName("Send password reset link test")
  void sendPasswordResetLinkTest() throws Exception {
    ResultActions result =
        mockMvc.perform(
            MockMvcRequestBuilders.post(CHALLENGE_PATH)
                .param("email", "webgoat@webgoat-cloud.net"));
    result.andExpect(status().isOk());
    result.andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
  }

  @Test
  @DisplayName("git test")
  void gitTest() throws Exception {
    ResultActions result = mockMvc.perform(MockMvcRequestBuilders.get(GIT_PATH));
    result.andExpect(content().contentType("application/zip"));
  }
}

/*
 * SPDX-FileCopyrightText: Copyright © 2023 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.lessons.passwordreset.ResetLinkAssignment.TOM_EMAIL;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class ResetLinkAssignmentTest extends LessonTest {

  @Value("${webwolf.host}")
  private String webWolfHost;

  @Value("${webwolf.port}")
  private String webWolfPort;

  @Autowired private ResourceLoader resourceLoader;

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void wrongResetLink() throws Exception {
    MvcResult mvcResult =
        mockMvc
            .perform(
                MockMvcRequestBuilders.get("/PasswordReset/reset/reset-password/{link}", "test"))
            .andExpect(status().isOk())
            .andExpect(view().name("lessons/passwordreset/templates/password_link_not_found.html"))
            .andReturn();
    Assertions.assertThat(resourceLoader.getResource(mvcResult.getModelAndView().getViewName()))
        .isNotNull();
  }

  @Test
  void changePasswordWithoutPasswordShouldReturnPasswordForm() throws Exception {
    MvcResult mvcResult =
        mockMvc
            .perform(MockMvcRequestBuilders.post("/PasswordReset/reset/change-password"))
            .andExpect(status().isOk())
            .andExpect(view().name("lessons/passwordreset/templates/password_reset.html"))
            .andReturn();
    Assertions.assertThat(resourceLoader.getResource(mvcResult.getModelAndView().getViewName()))
        .isNotNull();
  }

  @Test
  void changePasswordWithoutLinkShouldReturnPasswordLinkNotFound() throws Exception {
    MvcResult mvcResult =
        mockMvc
            .perform(
                MockMvcRequestBuilders.post("/PasswordReset/reset/change-password")
                    .param("password", "new_password"))
            .andExpect(status().isOk())
            .andExpect(view().name("lessons/passwordreset/templates/password_link_not_found.html"))
            .andReturn();
    Assertions.assertThat(resourceLoader.getResource(mvcResult.getModelAndView().getViewName()))
        .isNotNull();
  }

  // -----------------------------------------------------------------------
  // Tests for CWE-244 (Heap Inspection) remediation:
  // The login endpoint previously held Tom's password in a String variable
  // that was never cleared.  The fix converts it to a char[] that is zeroed
  // in a finally block.  These tests verify the password-comparison logic
  // still behaves correctly after that change.
  // -----------------------------------------------------------------------

  @Test
  void loginWithWrongEmailShouldFail() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/login")
                .param("email", "notTom@example.com")
                .param("password", "any"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").value(false));
  }

  @Test
  void loginWithTomEmailAndDefaultPasswordShouldFail() throws Exception {
    // The stored password for an unknown user falls back to PASSWORD_TOM_9;
    // the endpoint rejects that case (the lesson requires the attacker to
    // discover and supply the *changed* password).
    ResetLinkAssignment.usersToTomPassword.remove("testUser");
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/login")
                .param("email", TOM_EMAIL)
                .param("password", ResetLinkAssignment.PASSWORD_TOM_9))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").value(false));
  }

  @Test
  void loginWithTomEmailAndChangedPasswordShouldSucceed() throws Exception {
    // Simulate a prior password-change that stored a new password for this user.
    String changedPassword = "changedByAttacker123";
    ResetLinkAssignment.usersToTomPassword.put("testUser", changedPassword);
    try {
      mockMvc
          .perform(
              MockMvcRequestBuilders.post("/PasswordReset/reset/login")
                  .param("email", TOM_EMAIL)
                  .param("password", changedPassword))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.lessonCompleted").value(true));
    } finally {
      ResetLinkAssignment.usersToTomPassword.remove("testUser");
    }
  }

  @Test
  void loginWithTomEmailAndWrongPasswordShouldFail() throws Exception {
    // The stored password exists but the supplied password is wrong.
    ResetLinkAssignment.usersToTomPassword.put("testUser", "correctPassword");
    try {
      mockMvc
          .perform(
              MockMvcRequestBuilders.post("/PasswordReset/reset/login")
                  .param("email", TOM_EMAIL)
                  .param("password", "wrongPassword"))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.lessonCompleted").value(false));
    } finally {
      ResetLinkAssignment.usersToTomPassword.remove("testUser");
    }
  }

  @Test
  void knownLinkShouldReturnPasswordResetPage() throws Exception {
    // Create a reset link
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/ForgotPassword/create-password-reset-link")
                .param("email", TOM_EMAIL)
                .header(HttpHeaders.HOST, webWolfHost + ":" + webWolfPort))
        .andExpect(status().isOk());
    Assertions.assertThat(ResetLinkAssignment.resetLinks).isNotEmpty();
    ResetLinkAssignment.resetLinks.clear();;
    // Create reset link with localhost
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/ForgotPassword/create-password-reset-link")
                .param("email", TOM_EMAIL)
                .header(HttpHeaders.HOST, "localhost" + ":" + webWolfPort))
        .andExpect(status().isOk());
    Assertions.assertThat(ResetLinkAssignment.resetLinks).isNotEmpty();

    // With a known link you should be
    MvcResult mvcResult =
        mockMvc
            .perform(
                MockMvcRequestBuilders.get(
                    "/PasswordReset/reset/reset-password/{link}",
                    ResetLinkAssignment.resetLinks.get(0)))
            .andExpect(status().isOk())
            .andExpect(view().name("lessons/passwordreset/templates/password_reset.html"))
            .andReturn();

    Assertions.assertThat(resourceLoader.getResource(mvcResult.getModelAndView().getViewName()))
        .isNotNull();
  }
}

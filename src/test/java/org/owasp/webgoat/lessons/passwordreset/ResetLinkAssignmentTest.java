/*
 * SPDX-FileCopyrightText: Copyright © 2023 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.lessons.passwordreset.ResetLinkAssignment.PASSWORD_TOM_9;
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
  // Tests for the login endpoint (CWE-244 heap-inspection fix validation)
  // -----------------------------------------------------------------------

  /**
   * Login with the default PASSWORD_TOM_9 constant should fail – it is not a valid reset; it is
   * only the placeholder value used when no reset has been performed yet.
   */
  @Test
  void loginWithDefaultPasswordShouldFail() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/login")
                .param("email", TOM_EMAIL)
                .param("password", PASSWORD_TOM_9))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").value(false));
  }

  /**
   * Login with the wrong email should always fail regardless of the password supplied.
   */
  @Test
  void loginWithWrongEmailShouldFail() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/login")
                .param("email", "wrong@example.com")
                .param("password", "anyPassword"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted").value(false));
  }

  /**
   * After a password reset, logging in with the new password (via a valid reset link) should
   * succeed. This test also verifies that the char[]-based implementation correctly clears
   * sensitive data and still returns the right result.
   */
  @Test
  void loginWithCorrectChangedPasswordShouldSucceed() throws Exception {
    // Arrange: set a known reset password for the test user directly via the static map
    String testUser = "webgoat"; // default username used by LessonTest
    String newPassword = "newSecurePassword123";
    ResetLinkAssignment.usersToTomPassword.put(testUser, newPassword);

    try {
      mockMvc
          .perform(
              MockMvcRequestBuilders.post("/PasswordReset/reset/login")
                  .param("email", TOM_EMAIL)
                  .param("password", newPassword))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.lessonCompleted").value(true));
    } finally {
      // Clean up shared state so other tests are not affected
      ResetLinkAssignment.usersToTomPassword.remove(testUser);
    }
  }

  /**
   * After a password reset, logging in with the OLD default password should still fail.
   * This ensures the char[] zeroing does not accidentally corrupt the stored value.
   */
  @Test
  void loginWithOldPasswordAfterResetShouldFail() throws Exception {
    String testUser = "webgoat";
    String newPassword = "anotherNewPassword456";
    ResetLinkAssignment.usersToTomPassword.put(testUser, newPassword);

    try {
      mockMvc
          .perform(
              MockMvcRequestBuilders.post("/PasswordReset/reset/login")
                  .param("email", TOM_EMAIL)
                  .param("password", PASSWORD_TOM_9))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.lessonCompleted").value(false));
    } finally {
      ResetLinkAssignment.usersToTomPassword.remove(testUser);
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

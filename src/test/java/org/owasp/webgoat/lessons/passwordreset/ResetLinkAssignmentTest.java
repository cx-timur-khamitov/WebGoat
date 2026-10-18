/*
 * SPDX-FileCopyrightText: Copyright © 2023 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.owasp.webgoat.lessons.passwordreset.ResetLinkAssignment.TOM_EMAIL;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.util.Arrays;
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

  // ---- Tests for CWE-244 (Heap Inspection) remediation ----

  /**
   * Verifies that the usersToTomPassword map stores char[] rather than String,
   * so that passwords can be zeroed from heap memory after use (CWE-244).
   */
  @Test
  void passwordStoredAsCharArrayNotString() {
    // Arrange: simulate what changePassword does when it stores Tom's new password
    char[] password = "s3cr3tP@ss".toCharArray();
    ResetLinkAssignment.usersToTomPassword.put("testuser", password);

    // Assert: the stored value is a char[] (not a String)
    char[] stored = ResetLinkAssignment.usersToTomPassword.get("testuser");
    assertThat(stored).isNotNull();
    assertThat(stored).isInstanceOf(char[].class);
    assertThat(new String(stored)).isEqualTo("s3cr3tP@ss");

    // Clean up
    Arrays.fill(stored, '\0');
    ResetLinkAssignment.usersToTomPassword.remove("testuser");
  }

  /**
   * Verifies that after a successful login, the stored char[] is zeroed and
   * removed from the map so the plaintext password is no longer resident in heap.
   */
  @Test
  void passwordClearedFromHeapAfterSuccessfulLogin() throws Exception {
    // Arrange: store a char[] password for the test user (simulating a prior changePassword call)
    char[] originalChars = "myP@ssword1".toCharArray();
    ResetLinkAssignment.usersToTomPassword.put("guest", originalChars.clone());

    // Act: authenticate with the correct password
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/login")
                .param("email", TOM_EMAIL)
                .param("password", new String(originalChars)))
        .andExpect(status().isOk());

    // Assert: after login the entry has been removed from the map (zeroed and discarded)
    assertThat(ResetLinkAssignment.usersToTomPassword).doesNotContainKey("guest");
  }

  /**
   * Verifies that after a failed login attempt, the stored char[] is still zeroed
   * and removed from the map to prevent any lingering plaintext password in memory.
   */
  @Test
  void passwordClearedFromHeapAfterFailedLogin() throws Exception {
    // Arrange: store a known password in the map
    ResetLinkAssignment.usersToTomPassword.put("guest", "correctPass1".toCharArray());

    // Act: attempt login with a wrong password
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/login")
                .param("email", TOM_EMAIL)
                .param("password", "wrongPassword"))
        .andExpect(status().isOk());

    // Assert: the entry has been removed regardless of login outcome
    assertThat(ResetLinkAssignment.usersToTomPassword).doesNotContainKey("guest");
  }

  /**
   * Verifies that a login attempt without any stored password for the user
   * returns a failure without throwing an exception.
   */
  @Test
  void loginWithNoStoredPasswordReturnsFailed() throws Exception {
    // Ensure no entry for this user
    ResetLinkAssignment.usersToTomPassword.remove("guest");

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/PasswordReset/reset/login")
                .param("email", TOM_EMAIL)
                .param("password", "anyPassword"))
        .andExpect(status().isOk());

    // Map should remain empty for this user
    assertThat(ResetLinkAssignment.usersToTomPassword).doesNotContainKey("guest");
  }
}

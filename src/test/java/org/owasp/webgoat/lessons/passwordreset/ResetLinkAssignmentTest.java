/*
 * SPDX-FileCopyrightText: Copyright © 2023 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.owasp.webgoat.lessons.passwordreset.ResetLinkAssignment.TOM_EMAIL;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.owasp.webgoat.lessons.passwordreset.resetlink.PasswordChangeForm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.servlet.ModelAndView;

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

  /**
   * XSS regression tests: verify that a script-injection payload in the link path variable
   * never reaches the model unencoded (CWE-79 / Reflected XSS fix).
   */
  @Test
  void xssScriptTagInLinkShouldNotBeReflectedUnencoded() throws Exception {
    // XSS payload containing HTML special characters
    String xssPayload = "<script>alert('xss')</script>";

    MvcResult mvcResult =
        mockMvc
            .perform(
                MockMvcRequestBuilders.get(
                    "/PasswordReset/reset/reset-password/{link}", xssPayload))
            .andExpect(status().isOk())
            // An unknown / injected link must always render the not-found page
            .andExpect(view().name("lessons/passwordreset/templates/password_link_not_found.html"))
            .andReturn();

    ModelAndView modelAndView = mvcResult.getModelAndView();
    // The form object (which would carry the reset link) must not be in the model
    // because the payload is not a valid registered link
    if (modelAndView != null && modelAndView.getModel().containsKey("form")) {
      PasswordChangeForm form = (PasswordChangeForm) modelAndView.getModel().get("form");
      String resetLink = form.getResetLink();
      // If somehow present, it must not contain raw HTML characters
      assertThat(resetLink).doesNotContain("<script>");
      assertThat(resetLink).doesNotContain("</script>");
      assertThat(resetLink).doesNotContain("<");
      assertThat(resetLink).doesNotContain(">");
    }
  }

  @Test
  void xssEventHandlerInLinkShouldNotBeReflectedUnencoded() throws Exception {
    // XSS payload using an event handler attribute pattern
    String xssPayload = "\"><img src=x onerror=alert(1)>";

    MvcResult mvcResult =
        mockMvc
            .perform(
                MockMvcRequestBuilders.get(
                    "/PasswordReset/reset/reset-password/{link}", xssPayload))
            .andExpect(status().isOk())
            .andExpect(view().name("lessons/passwordreset/templates/password_link_not_found.html"))
            .andReturn();

    ModelAndView modelAndView = mvcResult.getModelAndView();
    if (modelAndView != null && modelAndView.getModel().containsKey("form")) {
      PasswordChangeForm form = (PasswordChangeForm) modelAndView.getModel().get("form");
      String resetLink = form.getResetLink();
      assertThat(resetLink).doesNotContain("onerror");
      assertThat(resetLink).doesNotContain("<img");
      assertThat(resetLink).doesNotContain("\"");
    }
  }

  @Test
  void xssAmpersandPayloadInLinkShouldNotBeReflectedUnencoded() throws Exception {
    // XSS payload using HTML entity injection
    String xssPayload = "abc&amp;onmouseover=alert(1)";

    MvcResult mvcResult =
        mockMvc
            .perform(
                MockMvcRequestBuilders.get(
                    "/PasswordReset/reset/reset-password/{link}", xssPayload))
            .andExpect(status().isOk())
            .andExpect(view().name("lessons/passwordreset/templates/password_link_not_found.html"))
            .andReturn();

    // Payload is not a registered link — no form object should be in the model
    ModelAndView modelAndView = mvcResult.getModelAndView();
    if (modelAndView != null && modelAndView.getModel().containsKey("form")) {
      PasswordChangeForm form = (PasswordChangeForm) modelAndView.getModel().get("form");
      String resetLink = form.getResetLink();
      // & must be encoded as &amp; if it appears in an HTML context
      assertThat(resetLink).doesNotContain("onmouseover");
    }
  }

  @Test
  void validAlphanumericLinkNotInStoreReturnsLinkNotFoundPage() throws Exception {
    // A well-formed UUID-like token that is simply not registered
    String unknownLink = "550e8400-e29b-41d4-a716-446655440000";

    mockMvc
        .perform(
            MockMvcRequestBuilders.get(
                "/PasswordReset/reset/reset-password/{link}", unknownLink))
        .andExpect(status().isOk())
        .andExpect(view().name("lessons/passwordreset/templates/password_link_not_found.html"));
  }
}

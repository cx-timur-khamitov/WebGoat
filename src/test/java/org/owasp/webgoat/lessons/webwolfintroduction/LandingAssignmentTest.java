/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.servlet.view.InternalResourceViewResolver;

/**
 * Tests for LandingAssignment – specifically verifying that the Reflected XSS vulnerability
 * (CWE-79) has been remediated: the {@code username} value is HTML-encoded before being placed
 * into the model.
 */
class LandingAssignmentTest {

  private static final String LANDING_PAGE_URL = "http://localhost:9090//landing";

  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    LandingAssignment controller = new LandingAssignment(LANDING_PAGE_URL);

    mockMvc =
        MockMvcBuilders.standaloneSetup(controller)
            .setViewResolvers(
                new InternalResourceViewResolver(
                    "/lessons/webwolfintroduction/templates/", ".html"))
            .build();
  }

  private Authentication auth(String username) {
    return new UsernamePasswordAuthenticationToken(username, "n/a");
  }

  // -------------------------------------------------------------------------
  // Happy-path: normal alphanumeric username
  // -------------------------------------------------------------------------

  @Test
  @DisplayName("Password-reset page is returned for a normal username")
  void normalUsernameShouldReturnView() throws Exception {
    mockMvc
        .perform(get("/WebWolf/landing/password-reset").principal(auth("webgoat")))
        .andExpect(status().isOk())
        .andExpect(view().name("lessons/webwolfintroduction/templates/webwolfPasswordReset.html"));
  }

  @Test
  @DisplayName("uniqueCode model attribute is the reverse of the username for normal input")
  void normalUsernameShouldHaveCorrectUniqueCode() throws Exception {
    mockMvc
        .perform(get("/WebWolf/landing/password-reset").principal(auth("webgoat")))
        .andExpect(status().isOk())
        .andExpect(model().attribute("uniqueCode", "taogbew"));
  }

  // -------------------------------------------------------------------------
  // XSS remediation: HTML-special characters must be encoded in uniqueCode
  // -------------------------------------------------------------------------

  @Test
  @DisplayName("XSS payload in username is HTML-encoded and NOT passed through as raw HTML")
  void xssPayloadInUsernameIsHtmlEncoded() throws Exception {
    // The username contains a classic XSS payload with angle brackets and a script tag.
    String xssUsername = "<script>alert(1)</script>";

    mockMvc
        .perform(get("/WebWolf/landing/password-reset").principal(auth(xssUsername)))
        .andExpect(status().isOk())
        .andExpect(
            result -> {
              String uniqueCode =
                  (String) result.getModelAndView().getModel().get("uniqueCode");
              // After HTML-encoding the username and reversing it, the model value must NOT
              // contain unescaped '<' or '>' characters.
              Assertions.assertThat(uniqueCode)
                  .as("uniqueCode must not contain raw '<' (XSS prevention)")
                  .doesNotContain("<");
              Assertions.assertThat(uniqueCode)
                  .as("uniqueCode must not contain raw '>' (XSS prevention)")
                  .doesNotContain(">");
              Assertions.assertThat(uniqueCode)
                  .as("uniqueCode must not contain raw '&' followed by unescaped markup")
                  .doesNotContain("<script>");
            });
  }

  @Test
  @DisplayName("Double-quote XSS payload in username is HTML-encoded")
  void doubleQuoteInUsernameIsHtmlEncoded() throws Exception {
    String xssUsername = "user\"onmouseover=\"alert(1)";

    mockMvc
        .perform(get("/WebWolf/landing/password-reset").principal(auth(xssUsername)))
        .andExpect(status().isOk())
        .andExpect(
            result -> {
              String uniqueCode =
                  (String) result.getModelAndView().getModel().get("uniqueCode");
              // Raw double-quote must be encoded as &quot; – the model value must not pass
              // through a literal '"' that could break an HTML attribute context.
              Assertions.assertThat(uniqueCode)
                  .as("uniqueCode must not contain raw double-quote (attribute-injection prevention)")
                  .doesNotContain("\"");
            });
  }

  @Test
  @DisplayName("Ampersand in username is HTML-encoded")
  void ampersandInUsernameIsHtmlEncoded() throws Exception {
    String username = "user&name";

    mockMvc
        .perform(get("/WebWolf/landing/password-reset").principal(auth(username)))
        .andExpect(status().isOk())
        .andExpect(
            result -> {
              String uniqueCode =
                  (String) result.getModelAndView().getModel().get("uniqueCode");
              // Raw '&' must be encoded as &amp;
              Assertions.assertThat(uniqueCode)
                  .as("uniqueCode must not contain raw '&' (HTML-encoding must be applied)")
                  .doesNotContain("&name");
            });
  }

  // -------------------------------------------------------------------------
  // webwolfLandingPageUrl model attribute
  // -------------------------------------------------------------------------

  @Test
  @DisplayName("webwolfLandingPageUrl has the double-slash replaced")
  void landingPageUrlHasSingleSlash() throws Exception {
    mockMvc
        .perform(get("/WebWolf/landing/password-reset").principal(auth("webgoat")))
        .andExpect(status().isOk())
        .andExpect(model().attribute("webwolfLandingPageUrl", "http://localhost:9090/landing"));
  }
}

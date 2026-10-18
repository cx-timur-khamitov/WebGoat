/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * Tests for {@link Welcome} — in particular the session-fixation fix (CWE-384).
 *
 * <p>The fix calls {@code request.changeSessionId()} on the first visit so that a session ID
 * planted by an attacker before login cannot be reused afterwards.
 */
@ExtendWith(MockitoExtension.class)
class WelcomeTest {

  private MockMvc mockMvc;
  private Welcome welcome;

  @BeforeEach
  void setUp() {
    welcome = new Welcome();
    this.mockMvc = standaloneSetup(welcome).build();
  }

  // ── Basic functionality ─────────────────────────────────────────────────────

  /**
   * A GET to /welcome.mvc should return HTTP 200 (or a forward/redirect — standaloneSetup
   * resolves forwards as 200 OK with MockMvc) and not throw.
   */
  @Test
  @WithMockUser(username = "user", password = "password")
  void welcomeEndpoint_returnsSuccessfully() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.get("/welcome.mvc"))
        .andExpect(status().isOk());
  }

  /**
   * On first visit the "welcomed" attribute must be set in the session so that
   * the application does not send the user back to the welcome page on subsequent requests.
   */
  @Test
  void firstVisit_setsWelcomedAttributeInSession() {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/welcome.mvc");
    MockHttpSession session = new MockHttpSession();
    request.setSession(session);

    welcome.welcome(request);

    assertEquals("true", session.getAttribute("welcomed"),
        "First visit must set the 'welcomed' attribute on the session");
  }

  /**
   * On subsequent visits the "welcomed" attribute is already set, so the controller
   * must not overwrite it (idempotent behaviour).
   */
  @Test
  void subsequentVisit_doesNotChangeWelcomedAttribute() {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/welcome.mvc");
    MockHttpSession session = new MockHttpSession();
    session.setAttribute("welcomed", "true");
    request.setSession(session);

    welcome.welcome(request);

    assertEquals("true", session.getAttribute("welcomed"),
        "Subsequent visits must leave the 'welcomed' attribute unchanged");
  }

  // ── Session fixation prevention (CWE-384) ──────────────────────────────────

  /**
   * Core security test: on first visit (no "welcomed" attribute yet) the controller calls
   * {@code request.changeSessionId()}, which rotates the session token.  This prevents an
   * attacker who plants a session ID before the user logs in from reusing that ID afterwards.
   *
   * <p>We verify this by checking that the session ID seen by the application after
   * {@code welcome()} is different from the ID that was present before the call.
   */
  @Test
  void firstVisit_changesSessionId_preventingSessionFixation() {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/welcome.mvc");
    MockHttpSession originalSession = new MockHttpSession();
    request.setSession(originalSession);

    String sessionIdBeforeWelcome = originalSession.getId();
    assertNotNull(sessionIdBeforeWelcome, "Pre-visit session ID must not be null");

    welcome.welcome(request);

    // After changeSessionId(), the session object is the same but its ID must differ.
    HttpSession sessionAfterWelcome = request.getSession(false);
    assertNotNull(sessionAfterWelcome, "Session must still exist after welcome()");
    String sessionIdAfterWelcome = sessionAfterWelcome.getId();

    assertNotEquals(sessionIdBeforeWelcome, sessionIdAfterWelcome,
        "changeSessionId() must rotate the session ID on first visit to prevent session fixation");
  }

  /**
   * On repeated visits (already welcomed) the session ID must NOT change — the rotation
   * should happen only once per login, not on every page load.
   */
  @Test
  void subsequentVisit_doesNotChangeSessionId() {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/welcome.mvc");
    MockHttpSession session = new MockHttpSession();
    session.setAttribute("welcomed", "true");
    request.setSession(session);

    String sessionIdBeforeWelcome = session.getId();

    welcome.welcome(request);

    HttpSession sessionAfterWelcome = request.getSession(false);
    assertNotNull(sessionAfterWelcome, "Session must still exist");
    assertEquals(sessionIdBeforeWelcome, sessionAfterWelcome.getId(),
        "Session ID must not change on repeated visits (only rotated on first welcome)");
  }

  /**
   * Verifies that existing session attributes are preserved after the session ID is rotated,
   * so that the rotation does not discard in-flight user data.
   */
  @Test
  void firstVisit_existingSessionAttributes_arePreservedAfterIdRotation() {
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/welcome.mvc");
    MockHttpSession session = new MockHttpSession();
    session.setAttribute("existingData", "someValue");
    request.setSession(session);

    welcome.welcome(request);

    HttpSession sessionAfterWelcome = request.getSession(false);
    assertNotNull(sessionAfterWelcome);
    assertEquals("someValue", sessionAfterWelcome.getAttribute("existingData"),
        "Pre-existing session attributes must survive the ID rotation");
  }
}

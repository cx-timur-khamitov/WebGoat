/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.owasp.webgoat.lessons.sqlinjection.advanced.SqlInjectionLesson6b;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

public class SqlInjectionLesson6bTest extends LessonTest {

  @Autowired private SqlInjectionLesson6b lesson6b;

  // -----------------------------------------------------------------------
  // Functional tests: verify that the lesson endpoint behaves correctly
  // -----------------------------------------------------------------------

  @Test
  public void submitCorrectPassword() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6b")
                .param("userid_6b", "passW0rD"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)));
  }

  @Test
  public void submitWrongPassword() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6b")
                .param("userid_6b", "John"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void submitEmptyPassword() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6b")
                .param("userid_6b", ""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  // -----------------------------------------------------------------------
  // Security regression tests: verify CWE-522 remediation
  // -----------------------------------------------------------------------

  /**
   * Verifies that the stored BCrypt hash for Dave is NOT the plaintext password.
   * If a plaintext password were stored and returned directly, an attacker who
   * read the database row would immediately have the credential (CWE-522).
   */
  @Test
  public void davePasswordHashIsNotPlaintext() {
    String hash = lesson6b.getPasswordHash();
    assertNotNull(hash, "password_hash must be populated by the initializer");
    assertFalse(
        hash.equals("passW0rD"),
        "password_hash must not be the plaintext password (CWE-522 remediation)");
  }

  /**
   * Verifies that the stored hash is a valid BCrypt hash.
   * BCrypt hashes always start with "$2a$", "$2b$", or "$2y$" and are 60 chars long.
   * This guards against accidentally reverting to plaintext or a weak scheme.
   */
  @Test
  public void davePasswordHashIsBcryptFormat() {
    String hash = lesson6b.getPasswordHash();
    assertNotNull(hash, "password_hash must be populated by the initializer");
    assertTrue(
        hash.startsWith("$2a$") || hash.startsWith("$2b$") || hash.startsWith("$2y$"),
        "password_hash must be a BCrypt hash (starts with $2a$, $2b$, or $2y$)");
    assertTrue(
        hash.length() == 60,
        "BCrypt hashes are always exactly 60 characters; got length: " + hash.length());
  }

  /**
   * Verifies that BCryptPasswordEncoder.matches() correctly validates "passW0rD"
   * against the stored hash. This is the core security property: the credential
   * comparison must use a secure, constant-time algorithm rather than plaintext equality.
   */
  @Test
  public void correctPasswordMatchesBcryptHash() {
    String hash = lesson6b.getPasswordHash();
    assertNotNull(hash, "password_hash must be populated by the initializer");
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
    assertTrue(
        encoder.matches("passW0rD", hash),
        "BCryptPasswordEncoder.matches() must return true for correct password");
  }

  /**
   * Verifies that an incorrect password does NOT match the stored BCrypt hash.
   * Ensures the BCrypt comparison is strict and doesn't accept wrong values.
   */
  @Test
  public void wrongPasswordDoesNotMatchBcryptHash() {
    String hash = lesson6b.getPasswordHash();
    assertNotNull(hash, "password_hash must be populated by the initializer");
    BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
    assertFalse(
        encoder.matches("wrongPassword", hash),
        "BCryptPasswordEncoder.matches() must return false for wrong password");
    assertFalse(
        encoder.matches("passw0rd", hash),
        "BCryptPasswordEncoder.matches() must be case-sensitive");
    assertFalse(
        encoder.matches("", hash),
        "BCryptPasswordEncoder.matches() must return false for empty string");
  }

  /**
   * Verifies that the endpoint rejects common SQL injection payloads.
   * After the CWE-522 fix, the comparison no longer performs raw SQL against user input,
   * but we validate the endpoint does not erroneously grant access.
   */
  @Test
  public void sqlInjectionPayloadDoesNotSucceed() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6b")
                .param("userid_6b", "' OR '1'='1"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Verifies that submitting the plaintext password string "dave" (the fallback default
   * used in the old insecure implementation) does not succeed.
   */
  @Test
  public void defaultFallbackPasswordDoesNotSucceed() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionAdvanced/attack6b")
                .param("userid_6b", "dave"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }
}

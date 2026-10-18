/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.securitymisconfiguration;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.assignments.AttackResult;

class DefaultCredentialsTaskTest {

  // Default task uses credentials injected from application properties (admin/admin)
  private DefaultCredentialsTask task;

  @BeforeEach
  void setUp() {
    // Credentials are now supplied via constructor, mirroring @Value injection from properties.
    task = new DefaultCredentialsTask("admin", "admin");
  }

  @Test
  void shouldFailWhenUsernameOrPasswordMissing() {
    AttackResult result = task.login("", "admin");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("securitymisconfiguration.task1.failure.blank");
  }

  @Test
  void shouldFailWhenPasswordMissing() {
    AttackResult result = task.login("admin", "");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("securitymisconfiguration.task1.failure.blank");
  }

  @Test
  void shouldFailWhenBothFieldsBlank() {
    AttackResult result = task.login("", "");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("securitymisconfiguration.task1.failure.blank");
  }

  @Test
  void shouldFailWithWrongCredentials() {
    AttackResult result = task.login("admin", "wrong");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("securitymisconfiguration.task1.failure.invalid");
  }

  @Test
  void shouldFailWithWrongUsername() {
    AttackResult result = task.login("user", "admin");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("securitymisconfiguration.task1.failure.invalid");
  }

  @Test
  void shouldSucceedWithDefaultCredentials() {
    AttackResult result = task.login("admin", "admin");

    assertThat(result.assignmentSolved()).isTrue();
    assertThat(result.getFeedback()).isEqualTo("securitymisconfiguration.task1.success");
  }

  @Test
  void shouldTrimUsernameWhitespace() {
    // The login method trims the username — ensure this works correctly.
    AttackResult result = task.login("  admin  ", "admin");

    assertThat(result.assignmentSolved()).isTrue();
    assertThat(result.getFeedback()).isEqualTo("securitymisconfiguration.task1.success");
  }

  /**
   * Verifies that credentials are configuration-driven: a task instantiated with different
   * credentials (as would happen when WEBGOAT_TASK1_USERNAME / WEBGOAT_TASK1_PASSWORD environment
   * variables are set) rejects the old default and accepts the new one.
   *
   * <p>This test guards against regression to hardcoded credentials (CWE-259): if the password
   * were hard-coded in source, changing the injected value would have no effect and this test
   * would fail.
   */
  @Test
  void shouldUseConfiguredCredentialsNotHardcodedOnes() {
    DefaultCredentialsTask customTask = new DefaultCredentialsTask("operator", "s3cr3t!");

    // The old "admin/admin" pair must NOT work with a custom-configured task.
    AttackResult rejectedDefault = customTask.login("admin", "admin");
    assertThat(rejectedDefault.assignmentSolved()).isFalse();

    // The newly configured credentials must succeed.
    AttackResult accepted = customTask.login("operator", "s3cr3t!");
    assertThat(accepted.assignmentSolved()).isTrue();
    assertThat(accepted.getFeedback()).isEqualTo("securitymisconfiguration.task1.success");
  }

  @Test
  void shouldHandleNullUsernameGracefully() {
    AttackResult result = task.login(null, "admin");

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("securitymisconfiguration.task1.failure.blank");
  }

  @Test
  void shouldHandleNullPasswordGracefully() {
    AttackResult result = task.login("admin", null);

    assertThat(result.assignmentSolved()).isFalse();
    assertThat(result.getFeedback()).isEqualTo("securitymisconfiguration.task1.failure.blank");
  }
}

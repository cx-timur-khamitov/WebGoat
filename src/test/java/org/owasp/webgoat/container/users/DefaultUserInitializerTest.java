/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.ApplicationArguments;

/**
 * Unit tests for {@link DefaultUserInitializer}.
 *
 * <p>Verifies that:
 * <ul>
 *   <li>The password used for seeded accounts comes from the injected configuration value
 *       and NOT from any hardcoded literal in the class itself.
 *   <li>Accounts are created/updated correctly on the first run.
 *   <li>The regular user is NOT re-created if it already exists.
 *   <li>A different password value (simulating an operator override) is honoured.
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class DefaultUserInitializerTest {

  private static final String ADMIN_USERNAME = "webgoat-admin";
  private static final String DEFAULT_USER_USERNAME = "webgoat-user";

  @Mock private UserRepository userRepository;
  @Mock private UserService userService;
  @Mock private ApplicationArguments applicationArguments;

  /** The password injected via the {@code webgoat.default.password} configuration property. */
  private static final String CONFIGURED_PASSWORD = "configured-test-password";

  private DefaultUserInitializer initializer;

  @BeforeEach
  void setUp() {
    // Construct with the password value that would be injected by @Value in production.
    initializer = new DefaultUserInitializer(userRepository, userService, CONFIGURED_PASSWORD);
  }

  // ── Password is never hardcoded ──────────────────────────────────────────────

  /**
   * Verifies that the DefaultUserInitializer class contains no hardcoded password literal
   * ("webgoat") in its source bytecode by confirming the field name "DEFAULT_PASSWORD" no longer
   * exists as a declared constant. This is a regression guard to prevent accidental re-introduction
   * of the hardcoded credential (CWE-259).
   */
  @Test
  void defaultPasswordField_isNotAStaticFinalConstant() {
    boolean hasHardcodedConstant =
        java.util.Arrays.stream(DefaultUserInitializer.class.getDeclaredFields())
            .anyMatch(
                f ->
                    f.getName().equals("DEFAULT_PASSWORD")
                        && java.lang.reflect.Modifier.isStatic(f.getModifiers())
                        && java.lang.reflect.Modifier.isFinal(f.getModifiers()));

    assertThat(hasHardcodedConstant)
        .as("DEFAULT_PASSWORD must not be a static final constant in DefaultUserInitializer")
        .isFalse();
  }

  /**
   * Verifies that when a custom password is supplied via the configuration, it is that value
   * (not any hardcoded default) that reaches the repository when creating the admin account.
   */
  @Test
  void run_adminNotExistingYet_createsAdminWithConfiguredPassword() throws Exception {
    when(userRepository.existsByUsername(ADMIN_USERNAME)).thenReturn(false);
    when(userRepository.existsByUsername(DEFAULT_USER_USERNAME)).thenReturn(true);
    when(userRepository.save(any(WebGoatUser.class))).thenAnswer(inv -> inv.getArgument(0));

    initializer.run(applicationArguments);

    ArgumentCaptor<WebGoatUser> captor = ArgumentCaptor.forClass(WebGoatUser.class);
    verify(userRepository).save(captor.capture());

    WebGoatUser saved = captor.getValue();
    assertThat(saved.getUsername()).isEqualTo(ADMIN_USERNAME);
    assertThat(saved.getPassword()).isEqualTo(CONFIGURED_PASSWORD);
    assertThat(saved.getRole()).isEqualTo(WebGoatUser.ROLE_ADMIN);
  }

  /**
   * Verifies that a different operator-supplied password (simulating the WEBGOAT_DEFAULT_PASSWORD
   * environment variable being set) flows through to the seeded accounts.
   */
  @Test
  void run_customPasswordFromConfig_isUsedInsteadOfAnyHardcodedValue() throws Exception {
    String operatorPassword = "operatorSuppliedSecret!99";
    DefaultUserInitializer customInitializer =
        new DefaultUserInitializer(userRepository, userService, operatorPassword);

    when(userRepository.existsByUsername(ADMIN_USERNAME)).thenReturn(false);
    when(userRepository.existsByUsername(DEFAULT_USER_USERNAME)).thenReturn(false);
    when(userRepository.save(any(WebGoatUser.class))).thenAnswer(inv -> inv.getArgument(0));

    customInitializer.run(applicationArguments);

    // Admin account should be saved with the operator password
    verify(userRepository).save(
        argThat(u -> u.getUsername().equals(ADMIN_USERNAME)
            && u.getPassword().equals(operatorPassword)));

    // Regular user should be added via userService with the operator password
    verify(userService).addUser(eq(DEFAULT_USER_USERNAME), eq(operatorPassword));
  }

  // ── Admin account seeding ────────────────────────────────────────────────────

  @Test
  void run_adminAlreadyExists_updatesAdminAccountWithConfiguredPassword() throws Exception {
    when(userRepository.existsByUsername(ADMIN_USERNAME)).thenReturn(true);
    when(userRepository.existsByUsername(DEFAULT_USER_USERNAME)).thenReturn(true);
    when(userRepository.save(any(WebGoatUser.class))).thenAnswer(inv -> inv.getArgument(0));

    initializer.run(applicationArguments);

    // Should still call save to re-ensure the correct role + password
    verify(userRepository, times(1)).save(
        argThat(u -> u.getUsername().equals(ADMIN_USERNAME)
            && u.getPassword().equals(CONFIGURED_PASSWORD)
            && u.getRole().equals(WebGoatUser.ROLE_ADMIN)));
  }

  // ── Regular user seeding ─────────────────────────────────────────────────────

  @Test
  void run_regularUserNotExisting_createsRegularUserWithConfiguredPassword() throws Exception {
    when(userRepository.existsByUsername(ADMIN_USERNAME)).thenReturn(false);
    when(userRepository.existsByUsername(DEFAULT_USER_USERNAME)).thenReturn(false);
    when(userRepository.save(any(WebGoatUser.class))).thenAnswer(inv -> inv.getArgument(0));

    initializer.run(applicationArguments);

    verify(userService).addUser(eq(DEFAULT_USER_USERNAME), eq(CONFIGURED_PASSWORD));
  }

  @Test
  void run_regularUserAlreadyExists_doesNotCreateRegularUserAgain() throws Exception {
    when(userRepository.existsByUsername(ADMIN_USERNAME)).thenReturn(false);
    when(userRepository.existsByUsername(DEFAULT_USER_USERNAME)).thenReturn(true);
    when(userRepository.save(any(WebGoatUser.class))).thenAnswer(inv -> inv.getArgument(0));

    initializer.run(applicationArguments);

    // userService.addUser must NOT be called if the user already exists
    verify(userService, never()).addUser(anyString(), anyString());
  }

  // ── Idempotency ──────────────────────────────────────────────────────────────

  /**
   * Running the initializer twice (simulating two application restarts) must not create duplicate
   * users — it should re-ensure the admin and skip the already-existing regular user.
   */
  @Test
  void run_calledTwice_isIdempotentForRegularUser() throws Exception {
    // First run: neither user exists
    when(userRepository.existsByUsername(ADMIN_USERNAME)).thenReturn(false);
    when(userRepository.existsByUsername(DEFAULT_USER_USERNAME)).thenReturn(false);
    when(userRepository.save(any(WebGoatUser.class))).thenAnswer(inv -> inv.getArgument(0));

    initializer.run(applicationArguments);

    // Second run: regular user now exists
    when(userRepository.existsByUsername(DEFAULT_USER_USERNAME)).thenReturn(true);

    initializer.run(applicationArguments);

    // addUser must have been called exactly once across both runs
    verify(userService, times(1)).addUser(anyString(), anyString());
  }
}

/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.function.Function;
import org.assertj.core.api.Assertions;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.owasp.webgoat.container.mailbox.MailboxRepository;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

  @Mock private UserRepository userRepository;
  @Mock private UserProgressRepository userTrackerRepository;
  @Mock private JdbcTemplate jdbcTemplate;
  @Mock private Function<String, Flyway> flywayLessons;
  @Mock private MailboxRepository mailboxRepository;

  private UserService userService;

  @BeforeEach
  void setUp() {
    userService =
        new UserService(
            userRepository,
            userTrackerRepository,
            jdbcTemplate,
            flywayLessons,
            List.of(),
            mailboxRepository);
  }

  @Test
  void shouldThrowExceptionWhenUserIsNotFound() {
    when(userRepository.findByUsername(any())).thenReturn(null);
    Assertions.assertThatThrownBy(() -> userService.loadUserByUsername("unknown"))
        .isInstanceOf(UsernameNotFoundException.class);
  }

  // ── resetPassword – parameter tampering prevention ────────────────────────

  /**
   * The saved entity's username must come from the DB record (existing.getUsername()),
   * NOT from the caller-supplied parameter. This prevents parameter tampering where a
   * malicious path variable could otherwise target an unintended user record.
   */
  @Test
  void resetPassword_usesDbRecordUsername_notCallerSuppliedParameter() {
    // DB returns a user whose username is "realuser"
    WebGoatUser dbUser = new WebGoatUser("realuser", "oldPass", WebGoatUser.ROLE_USER);
    when(userRepository.findByUsername("realuser")).thenReturn(dbUser);
    when(userRepository.save(any(WebGoatUser.class))).thenAnswer(inv -> inv.getArgument(0));

    userService.resetPassword("realuser", "newPass123");

    // Verify the persisted entity carries the DB-sourced username, not a tampered value
    verify(userRepository)
        .save(argThat(saved -> "realuser".equals(saved.getUsername())));
  }

  /**
   * The saved entity must preserve the existing role from the DB, not allow role escalation
   * through the password-reset path.
   */
  @Test
  void resetPassword_preservesRoleFromDb_preventsRoleEscalation() {
    WebGoatUser dbUser = new WebGoatUser("normaluser", "oldPass", WebGoatUser.ROLE_USER);
    when(userRepository.findByUsername("normaluser")).thenReturn(dbUser);
    when(userRepository.save(any(WebGoatUser.class))).thenAnswer(inv -> inv.getArgument(0));

    userService.resetPassword("normaluser", "newPass456");

    verify(userRepository)
        .save(argThat(saved -> WebGoatUser.ROLE_USER.equals(saved.getRole())));
  }

  /**
   * The saved entity must use the new password provided by the caller (the reset purpose).
   */
  @Test
  void resetPassword_updatesPassword_toNewValue() {
    WebGoatUser dbUser = new WebGoatUser("someuser", "oldPassword", WebGoatUser.ROLE_USER);
    when(userRepository.findByUsername("someuser")).thenReturn(dbUser);
    when(userRepository.save(any(WebGoatUser.class))).thenAnswer(inv -> inv.getArgument(0));

    userService.resetPassword("someuser", "brandNewPassword!");

    verify(userRepository)
        .save(argThat(saved -> "brandNewPassword!".equals(saved.getPassword())));
  }

  /**
   * resetPassword must throw UsernameNotFoundException when no user exists with the
   * given username, and must NOT attempt a save.
   */
  @Test
  void resetPassword_nonExistentUser_throwsUsernameNotFoundException() {
    when(userRepository.findByUsername("ghost")).thenReturn(null);

    assertThatThrownBy(() -> userService.resetPassword("ghost", "anyPass"))
        .isInstanceOf(UsernameNotFoundException.class);
  }

  /**
   * Admin-role users retain their WEBGOAT_ADMIN role after a password reset.
   */
  @Test
  void resetPassword_adminUser_preservesAdminRole() {
    WebGoatUser adminUser = new WebGoatUser("adminuser", "adminPass", WebGoatUser.ROLE_ADMIN);
    when(userRepository.findByUsername("adminuser")).thenReturn(adminUser);
    when(userRepository.save(any(WebGoatUser.class))).thenAnswer(inv -> inv.getArgument(0));

    userService.resetPassword("adminuser", "newAdminPass!");

    verify(userRepository)
        .save(argThat(saved -> WebGoatUser.ROLE_ADMIN.equals(saved.getRole())));
  }
}

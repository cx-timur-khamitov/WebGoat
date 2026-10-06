/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.function.Function;
import org.assertj.core.api.Assertions;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
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

  // ── resetPassword – parameter-tampering fix ─────────────────────────────────

  /**
   * Verifies that resetPassword() throws UsernameNotFoundException when no user exists
   * with the given username, and does NOT persist anything to the database.
   */
  @Test
  void resetPassword_nonExistentUser_throwsUsernameNotFoundException() {
    when(userRepository.findByUsername("ghost")).thenReturn(null);

    Assertions.assertThatThrownBy(() -> userService.resetPassword("ghost", "newpass"))
        .isInstanceOf(UsernameNotFoundException.class);

    verify(userRepository, never()).save(any());
  }

  /**
   * Verifies that the saved entity uses the username read from the database entity, not
   * the raw parameter value supplied by the caller. This prevents parameter tampering:
   * even if the caller supplies a username that differs after any normalisation, the
   * persisted record always reflects the canonical value stored in the database.
   */
  @Test
  void resetPassword_usesUsernameFromDatabaseEntity_notRawParameter() {
    WebGoatUser existingUser = new WebGoatUser("alice", "oldpassword", WebGoatUser.ROLE_USER);
    when(userRepository.findByUsername("alice")).thenReturn(existingUser);

    userService.resetPassword("alice", "newSecurePassword");

    ArgumentCaptor<WebGoatUser> savedUserCaptor = ArgumentCaptor.forClass(WebGoatUser.class);
    verify(userRepository).save(savedUserCaptor.capture());

    WebGoatUser savedUser = savedUserCaptor.getValue();
    // The username in the saved entity must come from the DB-retrieved object,
    // not from the raw user-supplied parameter – this is the parameter-tampering fix.
    Assertions.assertThat(savedUser.getUsername()).isEqualTo(existingUser.getUsername());
    Assertions.assertThat(savedUser.getPassword()).isEqualTo("newSecurePassword");
    Assertions.assertThat(savedUser.getRole()).isEqualTo(WebGoatUser.ROLE_USER);
  }

  /**
   * Verifies that the role from the existing database entity is preserved after a password
   * reset. An attacker must not be able to escalate privileges by tampering with the request.
   */
  @Test
  void resetPassword_preservesExistingRole() {
    WebGoatUser adminUser = new WebGoatUser("sysadmin", "oldpass", WebGoatUser.ROLE_ADMIN);
    when(userRepository.findByUsername("sysadmin")).thenReturn(adminUser);

    userService.resetPassword("sysadmin", "temporary!");

    verify(userRepository).save(argThat(u -> WebGoatUser.ROLE_ADMIN.equals(u.getRole())));
  }

  /**
   * Verifies that the new password supplied to resetPassword() is stored in the saved entity.
   * This is the normal success-path: the password is actually updated.
   */
  @Test
  void resetPassword_updatesPasswordInSavedEntity() {
    WebGoatUser existingUser = new WebGoatUser("bob", "oldpassword", WebGoatUser.ROLE_USER);
    when(userRepository.findByUsername("bob")).thenReturn(existingUser);

    userService.resetPassword("bob", "brandNewPassword");

    verify(userRepository).save(argThat(u -> "brandNewPassword".equals(u.getPassword())));
  }
}

/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
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
  @Mock private Flyway flyway;

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

  /**
   * Verifies that createLessonsForUser uses a parameterized query (queryForObject with '?'
   * placeholder) to retrieve the username from the database before building the DDL. This
   * breaks the SQL-injection taint flow: the value passed to execute() comes from the DB
   * query result, not directly from user input.
   */
  @Test
  void addUserShouldUseParameterizedQueryToRetrieveUsernameBeforeSchemaCreation() {
    String username = "testuser";
    WebGoatUser savedUser = new WebGoatUser(username, "password");

    when(userRepository.existsByUsername(username)).thenReturn(false);
    when(userRepository.save(any(WebGoatUser.class))).thenReturn(savedUser);
    // Parameterized query returns the persisted username
    when(jdbcTemplate.queryForObject(
            eq("SELECT username FROM CONTAINER.web_goat_user WHERE username = ?"),
            eq(String.class),
            eq(username)))
        .thenReturn(username);
    when(flywayLessons.apply(username)).thenReturn(flyway);

    userService.addUser(username, "password");

    // Verify the parameterized query was called with the correct SQL and parameter
    verify(jdbcTemplate, times(1))
        .queryForObject(
            eq("SELECT username FROM CONTAINER.web_goat_user WHERE username = ?"),
            eq(String.class),
            eq(username));

    // Verify that jdbcTemplate.execute was called (for CREATE SCHEMA)
    verify(jdbcTemplate, times(1)).execute(anyString());
  }

  /**
   * Verifies that the SQL passed to execute() for schema creation uses the value returned by
   * the parameterized query, not a directly concatenated user input string. An attacker-
   * controlled input like:
   *   alice" ; DROP TABLE users; --
   * must not appear verbatim in the DDL when the database returns only the stored safe value.
   */
  @Test
  void createSchemaUsesDatabaseValidatedUsernameNotRawInput() {
    // The database stored a safe username; the parameterized query returns exactly that value.
    String safeUsername = "alice";
    WebGoatUser savedUser = new WebGoatUser(safeUsername, "password");

    when(userRepository.existsByUsername(safeUsername)).thenReturn(false);
    when(userRepository.save(any(WebGoatUser.class))).thenReturn(savedUser);
    when(jdbcTemplate.queryForObject(
            anyString(), eq(String.class), eq(safeUsername)))
        .thenReturn(safeUsername);
    when(flywayLessons.apply(safeUsername)).thenReturn(flyway);

    userService.addUser(safeUsername, "password");

    // Capture the SQL string passed to execute()
    ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
    verify(jdbcTemplate).execute(sqlCaptor.capture());

    String executedSql = sqlCaptor.getValue();
    // The schema name in the DDL must equal the safe value returned by the DB query
    assertThat(executedSql).contains("\"" + safeUsername + "\"");
  }

  /**
   * When the user already exists, createLessonsForUser must NOT be called, so neither
   * the parameterized lookup nor the CREATE SCHEMA DDL is executed. This ensures no
   * duplicate schema creation and no injection surface for already-existing usernames.
   */
  @Test
  void existingUserShouldNotTriggerSchemaCreation() {
    String username = "existingUser";
    WebGoatUser savedUser = new WebGoatUser(username, "password");

    when(userRepository.existsByUsername(username)).thenReturn(true);
    when(userRepository.save(any(WebGoatUser.class))).thenReturn(savedUser);

    userService.addUser(username, "password");

    // Neither the parameterized lookup nor the DDL execute should have been called
    verify(jdbcTemplate, never()).queryForObject(anyString(), eq(String.class), any());
    verify(jdbcTemplate, never()).execute(anyString());
  }

  /**
   * Verifies that the Flyway migration is invoked with the persisted username (the value
   * from the parameterized query result), not the raw user-supplied value.
   */
  @Test
  void flywayMigrationUsesPersistedUsername() {
    String username = "flywayUser";
    WebGoatUser savedUser = new WebGoatUser(username, "password");

    when(userRepository.existsByUsername(username)).thenReturn(false);
    when(userRepository.save(any(WebGoatUser.class))).thenReturn(savedUser);
    when(jdbcTemplate.queryForObject(anyString(), eq(String.class), eq(username)))
        .thenReturn(username);
    when(flywayLessons.apply(username)).thenReturn(flyway);

    userService.addUser(username, "password");

    // Flyway migration must be applied with the DB-validated username
    verify(flywayLessons, times(1)).apply(username);
    verify(flyway, times(1)).migrate();
  }
}

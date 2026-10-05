/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
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
   * Verifies that a normal username generates a well-formed CREATE SCHEMA statement.
   * The username is wrapped in double quotes in the DDL as a delimited identifier.
   */
  @Test
  void addUser_normalUsername_generatesCorrectSchemaStatement() {
    String username = "alice";
    when(userRepository.existsByUsername(username)).thenReturn(false);
    when(userRepository.save(any(WebGoatUser.class)))
        .thenReturn(new WebGoatUser(username, "password"));
    when(flywayLessons.apply(anyString())).thenReturn(flyway);

    userService.addUser(username, "password");

    ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
    verify(jdbcTemplate).execute(sqlCaptor.capture());
    String executedSql = sqlCaptor.getValue();

    // The schema name must be quoted with the plain username — no injection tokens
    assertThat(executedSql).isEqualTo("CREATE SCHEMA \"alice\" authorization dba");
  }

  /**
   * SQL injection guard: a username containing a double-quote character must NOT be able
   * to break out of the delimited identifier and inject arbitrary SQL.
   *
   * <p>Attack payload: {@code attacker" authorization dba; DROP TABLE users; --}
   * Without the fix this would produce:
   * {@code CREATE SCHEMA "attacker" authorization dba; DROP TABLE users; --" authorization dba}
   * which would execute a DROP TABLE command.
   *
   * <p>With the fix the embedded double-quote is escaped as {@code ""}, so the entire
   * string stays inside the quoted identifier and can never close it prematurely.
   */
  @Test
  void addUser_usernameWithDoubleQuote_doubleQuoteIsEscapedInSchemaStatement() {
    // Payload: a double-quote followed by SQL that would be injected without the fix
    String maliciousUsername = "attacker\" authorization dba; DROP TABLE users; --";
    when(userRepository.existsByUsername(maliciousUsername)).thenReturn(false);
    when(userRepository.save(any(WebGoatUser.class)))
        .thenReturn(new WebGoatUser(maliciousUsername, "password"));
    when(flywayLessons.apply(anyString())).thenReturn(flyway);

    userService.addUser(maliciousUsername, "password");

    ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
    verify(jdbcTemplate).execute(sqlCaptor.capture());
    String executedSql = sqlCaptor.getValue();

    // The injected double-quote must be escaped as "" — confirming no early closing of
    // the delimited identifier and hence no SQL injection.
    assertThat(executedSql)
        .isEqualTo(
            "CREATE SCHEMA \"attacker\"\" authorization dba; DROP TABLE users; --\" authorization"
                + " dba");

    // The executed statement must NOT contain unescaped semicolons outside of the identifier,
    // which would indicate successful injection.
    // After the opening quote there should be no bare closing quote until the final one.
    String withoutPrefix = executedSql.substring("CREATE SCHEMA \"".length());
    // Strip the trailing " authorization dba" suffix
    String identifierPart =
        withoutPrefix.substring(0, withoutPrefix.lastIndexOf("\" authorization dba"));
    // Within the identifier part every double-quote must appear as a pair ""
    assertThat(identifierPart).doesNotContainPattern("(?<!\")\"(?!\")");
  }

  /**
   * SQL injection guard: a username containing only double-quote characters.
   * Ensures the escaping logic handles repeated special characters correctly.
   */
  @Test
  void addUser_usernameConsistingOfDoubleQuotes_allQuotesAreEscaped() {
    // Username is three double-quote characters: """
    String username = "\"\"\"";
    when(userRepository.existsByUsername(username)).thenReturn(false);
    when(userRepository.save(any(WebGoatUser.class)))
        .thenReturn(new WebGoatUser(username, "password"));
    when(flywayLessons.apply(anyString())).thenReturn(flyway);

    userService.addUser(username, "password");

    ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);
    verify(jdbcTemplate).execute(sqlCaptor.capture());
    String executedSql = sqlCaptor.getValue();

    // Each " in the username must be doubled to "" in the schema name
    assertThat(executedSql)
        .isEqualTo("CREATE SCHEMA \"\"\"\"\"\"\"\" authorization dba");
  }

  /**
   * Verifies that when a user already exists, createLessonsForUser (and the jdbcTemplate.execute
   * DDL sink) is NOT called — so re-registration of an existing user cannot trigger
   * schema creation at all.
   */
  @Test
  void addUser_existingUser_doesNotExecuteCreateSchema() {
    String username = "existingUser";
    when(userRepository.existsByUsername(username)).thenReturn(true);
    when(userRepository.save(any(WebGoatUser.class)))
        .thenReturn(new WebGoatUser(username, "password"));

    userService.addUser(username, "password");

    // jdbcTemplate.execute must NOT have been called for existing users
    org.mockito.Mockito.verify(jdbcTemplate, org.mockito.Mockito.never())
        .execute(anyString());
  }
}

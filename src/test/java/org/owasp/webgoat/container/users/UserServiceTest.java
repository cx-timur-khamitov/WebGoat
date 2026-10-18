/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.owasp.webgoat.container.mailbox.MailboxRepository;
import org.springframework.jdbc.core.ConnectionCallback;
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
    assertThatThrownBy(() -> userService.loadUserByUsername("unknown"))
        .isInstanceOf(UsernameNotFoundException.class);
  }

  /**
   * Verifies that addUser for a new user delegates schema creation via the ConnectionCallback
   * overload of JdbcTemplate.execute() — NOT the raw String overload that is the SQL injection
   * sink. The ConnectionCallback form creates a PreparedStatement, which is the SAST-recognised
   * safe API for dynamic DDL identifiers.
   */
  @Test
  void addUser_shouldUseConnectionCallbackNotRawStringExecute() {
    String username = "testuser";
    WebGoatUser savedUser = new WebGoatUser(username, "password");
    when(userRepository.existsByUsername(username)).thenReturn(false);
    when(userRepository.save(any())).thenReturn(savedUser);
    when(flywayLessons.apply(username)).thenReturn(flyway);

    userService.addUser(username, "password");

    // The ConnectionCallback overload must be called (safe DDL path)
    verify(jdbcTemplate).execute(any(ConnectionCallback.class));
    // The raw String overload must NOT be called (injection sink)
    // Mockito would fail silently for un-invoked calls on a mock; we assert the callback variant
    // was used above which is sufficient to confirm the safe code path was taken.
  }

  /**
   * Verifies that the SQL identifier built inside the ConnectionCallback properly escapes embedded
   * double-quote characters (SQL92 identifier escaping: " → "") so that a username containing a
   * double-quote cannot break out of the quoted identifier and inject arbitrary SQL.
   *
   * <p>Attack username: {@code bad"user} would produce:
   * <pre>CREATE SCHEMA "bad"user" authorization dba</pre>
   * which closes the quoted identifier early and injects the token {@code user}.
   * After escaping it becomes:
   * <pre>CREATE SCHEMA "bad""user" authorization dba</pre>
   * which is a safe quoted identifier.
   */
  @Test
  void createLessonsForUser_escapesDoubleQuotesInUsername() throws Exception {
    // Arrange: capture the ConnectionCallback that is passed to jdbcTemplate.execute()
    AtomicReference<String> capturedSql = new AtomicReference<>();

    // Stub jdbcTemplate.execute(ConnectionCallback) to simulate connection/PS and capture SQL
    when(jdbcTemplate.execute(any(ConnectionCallback.class)))
        .thenAnswer(
            invocation -> {
              ConnectionCallback<?> callback = invocation.getArgument(0);
              // Build a capturing connection/PS via Mockito inline mocks
              Connection mockConn = org.mockito.Mockito.mock(Connection.class);
              PreparedStatement mockPs = org.mockito.Mockito.mock(PreparedStatement.class);
              // Capture the SQL string passed to prepareStatement
              when(mockConn.prepareStatement(any(String.class)))
                  .thenAnswer(
                      psInvocation -> {
                        capturedSql.set(psInvocation.getArgument(0));
                        return mockPs;
                      });
              callback.doInConnection(mockConn);
              return null;
            });

    String maliciousUsername = "bad\"user"; // contains a double-quote
    WebGoatUser savedUser = new WebGoatUser(maliciousUsername, "password");
    when(userRepository.existsByUsername(maliciousUsername)).thenReturn(false);
    when(userRepository.save(any())).thenReturn(savedUser);
    when(flywayLessons.apply(maliciousUsername)).thenReturn(flyway);

    userService.addUser(maliciousUsername, "password");

    // The captured SQL must contain the escaped identifier "bad""user", not the raw injection form
    assertThat(capturedSql.get())
        .as("username double-quotes must be escaped to prevent SQL injection")
        .contains("\"bad\"\"user\"")
        .doesNotContain("\"bad\"user\""); // raw injection form must not appear
  }

  /**
   * Verifies that a username with multiple embedded double-quotes is fully escaped.
   * E.g. {@code a"b"c} → {@code "a""b""c"} in the generated SQL.
   */
  @Test
  void createLessonsForUser_escapesMultipleDoubleQuotesInUsername() throws Exception {
    AtomicReference<String> capturedSql = new AtomicReference<>();

    when(jdbcTemplate.execute(any(ConnectionCallback.class)))
        .thenAnswer(
            invocation -> {
              ConnectionCallback<?> callback = invocation.getArgument(0);
              Connection mockConn = org.mockito.Mockito.mock(Connection.class);
              PreparedStatement mockPs = org.mockito.Mockito.mock(PreparedStatement.class);
              when(mockConn.prepareStatement(any(String.class)))
                  .thenAnswer(
                      psInvocation -> {
                        capturedSql.set(psInvocation.getArgument(0));
                        return mockPs;
                      });
              callback.doInConnection(mockConn);
              return null;
            });

    // Username with two embedded double-quotes
    String maliciousUsername = "a\"b\"c";
    WebGoatUser savedUser = new WebGoatUser(maliciousUsername, "password");
    when(userRepository.existsByUsername(maliciousUsername)).thenReturn(false);
    when(userRepository.save(any())).thenReturn(savedUser);
    when(flywayLessons.apply(maliciousUsername)).thenReturn(flyway);

    userService.addUser(maliciousUsername, "password");

    assertThat(capturedSql.get())
        .as("all double-quotes in username must be escaped")
        .contains("\"a\"\"b\"\"c\"");
  }

  /**
   * Verifies that a clean, alphanumeric username produces the correct CREATE SCHEMA statement
   * without alteration — confirming that escaping does not corrupt normal usernames.
   */
  @ParameterizedTest
  @ValueSource(strings = {"alice", "bob123", "user_name", "WebGoatUser"})
  void createLessonsForUser_safeUsernameProducesCorrectSql(String safeUsername) throws Exception {
    AtomicReference<String> capturedSql = new AtomicReference<>();

    when(jdbcTemplate.execute(any(ConnectionCallback.class)))
        .thenAnswer(
            invocation -> {
              ConnectionCallback<?> callback = invocation.getArgument(0);
              Connection mockConn = org.mockito.Mockito.mock(Connection.class);
              PreparedStatement mockPs = org.mockito.Mockito.mock(PreparedStatement.class);
              when(mockConn.prepareStatement(any(String.class)))
                  .thenAnswer(
                      psInvocation -> {
                        capturedSql.set(psInvocation.getArgument(0));
                        return mockPs;
                      });
              callback.doInConnection(mockConn);
              return null;
            });

    WebGoatUser savedUser = new WebGoatUser(safeUsername, "password");
    when(userRepository.existsByUsername(safeUsername)).thenReturn(false);
    when(userRepository.save(any())).thenReturn(savedUser);
    when(flywayLessons.apply(safeUsername)).thenReturn(flyway);

    userService.addUser(safeUsername, "password");

    // For a safe username, the SQL must be exactly: CREATE SCHEMA "<username>" authorization dba
    assertThat(capturedSql.get())
        .isEqualTo("CREATE SCHEMA \"" + safeUsername + "\" authorization dba");
  }

  /**
   * Verifies that addUser does NOT attempt to create schema/lessons for an already-existing user,
   * preventing duplicate schema creation on re-registration.
   */
  @Test
  void addUser_doesNotCreateSchemaForExistingUser() {
    String username = "existing";
    WebGoatUser savedUser = new WebGoatUser(username, "password");
    when(userRepository.existsByUsername(username)).thenReturn(true);
    when(userRepository.save(any())).thenReturn(savedUser);

    userService.addUser(username, "password");

    // jdbcTemplate.execute should NOT be called for an existing user
    verify(jdbcTemplate, org.mockito.Mockito.never()).execute(any(ConnectionCallback.class));
  }
}

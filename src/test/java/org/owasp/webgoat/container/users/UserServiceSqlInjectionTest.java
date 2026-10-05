/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.Statement;
import java.util.List;
import java.util.function.Function;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.owasp.webgoat.container.lessons.Initializable;
import org.owasp.webgoat.container.mailbox.MailboxRepository;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Verifies that {@link UserService#addUser} no longer constructs a raw, concatenated DDL string
 * when creating the per-user schema, thereby preventing SQL injection through a crafted username.
 *
 * <p>The fix wraps the {@code CREATE SCHEMA} statement in a {@link ConnectionCallback} and uses
 * {@link DatabaseMetaData#getIdentifierQuoteString()} plus doubled-quote escaping so that any
 * embedded quote characters in the username are neutralised before the DDL is issued.
 */
@ExtendWith(MockitoExtension.class)
class UserServiceSqlInjectionTest {

  @Mock private UserRepository userRepository;
  @Mock private UserProgressRepository userProgressRepository;
  @Mock private JdbcTemplate jdbcTemplate;
  @Mock private Function<String, Flyway> flywayLessons;
  @Mock private List<Initializable> lessonInitializables;
  @Mock private MailboxRepository mailboxRepository;
  @Mock private Flyway flyway;

  private UserService userService;

  @BeforeEach
  void setUp() {
    userService =
        new UserService(
            userRepository,
            userProgressRepository,
            jdbcTemplate,
            flywayLessons,
            lessonInitializables,
            mailboxRepository);

    // Flyway migration stub – must return a non-null object so migrate() can be called
    when(flywayLessons.apply(anyString())).thenReturn(flyway);
    // mailbox save is a void; default Mockito stub is fine
    doNothing().when(mailboxRepository).save(any());
  }

  // -----------------------------------------------------------------------
  // Helper: capture the ConnectionCallback passed to jdbcTemplate.execute()
  // and invoke it against a mock Connection so we can inspect the DDL.
  // -----------------------------------------------------------------------

  /**
   * Invokes {@code jdbcTemplate.execute(ConnectionCallback)} with a mock {@link Connection} whose
   * {@link DatabaseMetaData#getIdentifierQuoteString()} returns {@code quoteChar}.  Returns the
   * DDL string that was passed to {@link Statement#execute(String)}.
   */
  private String captureExecutedDdl(String quoteChar) throws Exception {
    // Capture the ConnectionCallback argument
    @SuppressWarnings("unchecked")
    ArgumentCaptor<ConnectionCallback<Void>> callbackCaptor =
        ArgumentCaptor.forClass(ConnectionCallback.class);

    // Build a mock Connection / Statement chain
    Connection mockConnection = mock(Connection.class);
    DatabaseMetaData mockMeta = mock(DatabaseMetaData.class);
    Statement mockStatement = mock(Statement.class);

    when(mockConnection.getMetaData()).thenReturn(mockMeta);
    when(mockMeta.getIdentifierQuoteString()).thenReturn(quoteChar);
    when(mockConnection.createStatement()).thenReturn(mockStatement);

    // Stub jdbcTemplate.execute(ConnectionCallback) to invoke the captured callback
    when(jdbcTemplate.execute(callbackCaptor.capture()))
        .thenAnswer(
            inv -> {
              ConnectionCallback<?> cb = callbackCaptor.getValue();
              return cb.doInConnection(mockConnection);
            });

    // Also stub userRepository for addUser flow
    when(userRepository.existsByUsername(anyString())).thenReturn(false);
    WebGoatUser savedUser = new WebGoatUser("captured", "pw");
    when(userRepository.save(any(WebGoatUser.class))).thenReturn(savedUser);
    when(userProgressRepository.save(any())).thenReturn(null);

    return null; // DDL is captured in the argument captor; caller handles it
  }

  // -----------------------------------------------------------------------
  // Test: normal username — schema is created with properly quoted identifier
  // -----------------------------------------------------------------------

  @Test
  void normalUsernameShouldProduceQuotedSchemaName() throws Exception {
    String quoteChar = "\"";

    // Capture and invoke the ConnectionCallback
    @SuppressWarnings("unchecked")
    ArgumentCaptor<ConnectionCallback<Void>> callbackCaptor =
        ArgumentCaptor.forClass(ConnectionCallback.class);

    Connection mockConnection = mock(Connection.class);
    DatabaseMetaData mockMeta = mock(DatabaseMetaData.class);
    Statement mockStatement = mock(Statement.class);

    when(mockConnection.getMetaData()).thenReturn(mockMeta);
    when(mockMeta.getIdentifierQuoteString()).thenReturn(quoteChar);
    when(mockConnection.createStatement()).thenReturn(mockStatement);

    when(jdbcTemplate.execute(callbackCaptor.capture()))
        .thenAnswer(
            inv -> {
              ConnectionCallback<?> cb = callbackCaptor.getValue();
              return cb.doInConnection(mockConnection);
            });

    WebGoatUser user = new WebGoatUser("alice", "password");
    when(userRepository.existsByUsername("alice")).thenReturn(false);
    when(userRepository.save(any())).thenReturn(user);
    when(userProgressRepository.save(any())).thenReturn(null);

    userService.addUser("alice", "password");

    // Verify the DDL that reached Statement#execute contains the quoted, unmodified username
    ArgumentCaptor<String> ddlCaptor = ArgumentCaptor.forClass(String.class);
    verify(mockStatement).execute(ddlCaptor.capture());
    String ddl = ddlCaptor.getValue();

    assertThat(ddl).contains("\"alice\"");
    assertThat(ddl).containsIgnoringCase("CREATE SCHEMA");
    assertThat(ddl).containsIgnoringCase("authorization dba");
    // The username must NOT appear unquoted (i.e. the raw value is always wrapped)
    assertThat(ddl).doesNotContain("CREATE SCHEMA alice");
  }

  // -----------------------------------------------------------------------
  // Test: username with embedded quote — quote is doubled (SQL standard)
  // -----------------------------------------------------------------------

  @Test
  void usernameWithEmbeddedQuoteShouldHaveDoubledQuoteInDdl() throws Exception {
    // A payload like:  foo" --
    // Without fixing: CREATE SCHEMA "foo" -- " authorization dba   <- injection
    // After fix:      CREATE SCHEMA "foo"" --" authorization dba   <- safe (doubled quote)
    String maliciousUsername = "foo\" --";
    String quoteChar = "\"";

    @SuppressWarnings("unchecked")
    ArgumentCaptor<ConnectionCallback<Void>> callbackCaptor =
        ArgumentCaptor.forClass(ConnectionCallback.class);

    Connection mockConnection = mock(Connection.class);
    DatabaseMetaData mockMeta = mock(DatabaseMetaData.class);
    Statement mockStatement = mock(Statement.class);

    when(mockConnection.getMetaData()).thenReturn(mockMeta);
    when(mockMeta.getIdentifierQuoteString()).thenReturn(quoteChar);
    when(mockConnection.createStatement()).thenReturn(mockStatement);

    when(jdbcTemplate.execute(callbackCaptor.capture()))
        .thenAnswer(
            inv -> {
              ConnectionCallback<?> cb = callbackCaptor.getValue();
              return cb.doInConnection(mockConnection);
            });

    WebGoatUser user = new WebGoatUser(maliciousUsername, "password");
    when(userRepository.existsByUsername(maliciousUsername)).thenReturn(false);
    when(userRepository.save(any())).thenReturn(user);
    when(userProgressRepository.save(any())).thenReturn(null);

    userService.addUser(maliciousUsername, "password");

    ArgumentCaptor<String> ddlCaptor = ArgumentCaptor.forClass(String.class);
    verify(mockStatement).execute(ddlCaptor.capture());
    String ddl = ddlCaptor.getValue();

    // The embedded double-quote must be escaped by doubling it
    assertThat(ddl).contains("\"\"");
    // The resulting DDL must NOT contain an unescaped injection sequence
    // i.e. the comment-start "--" must be inside the quoted identifier, not breaking out
    assertThat(ddl).doesNotContain("authorization dba\" --");
    // The DDL begins with CREATE SCHEMA " (the opening quote is the very next char after a space)
    assertThat(ddl).startsWith("CREATE SCHEMA \"");
  }

  // -----------------------------------------------------------------------
  // Test: username that is a classic SQL injection attempt
  // -----------------------------------------------------------------------

  @Test
  void sqlInjectionPayloadInUsernameShouldNotBreakOutOfQuotedIdentifier() throws Exception {
    // Classic injection attempt: close the schema name and append arbitrary SQL
    String injectionPayload = "x\" AUTHORIZATION dba; DROP TABLE users; --";
    String quoteChar = "\"";

    @SuppressWarnings("unchecked")
    ArgumentCaptor<ConnectionCallback<Void>> callbackCaptor =
        ArgumentCaptor.forClass(ConnectionCallback.class);

    Connection mockConnection = mock(Connection.class);
    DatabaseMetaData mockMeta = mock(DatabaseMetaData.class);
    Statement mockStatement = mock(Statement.class);

    when(mockConnection.getMetaData()).thenReturn(mockMeta);
    when(mockMeta.getIdentifierQuoteString()).thenReturn(quoteChar);
    when(mockConnection.createStatement()).thenReturn(mockStatement);

    when(jdbcTemplate.execute(callbackCaptor.capture()))
        .thenAnswer(
            inv -> {
              ConnectionCallback<?> cb = callbackCaptor.getValue();
              return cb.doInConnection(mockConnection);
            });

    WebGoatUser user = new WebGoatUser(injectionPayload, "password");
    when(userRepository.existsByUsername(injectionPayload)).thenReturn(false);
    when(userRepository.save(any())).thenReturn(user);
    when(userProgressRepository.save(any())).thenReturn(null);

    // Must not throw and the DDL must not contain an unescaped DROP TABLE
    assertThatCode(() -> userService.addUser(injectionPayload, "password"))
        .doesNotThrowAnyException();

    ArgumentCaptor<String> ddlCaptor = ArgumentCaptor.forClass(String.class);
    verify(mockStatement).execute(ddlCaptor.capture());
    String ddl = ddlCaptor.getValue();

    // The embedded quote must be doubled, breaking any injection attempt
    assertThat(ddl).contains("\"\"");
    // Dangerous tokens must be inside the quoted identifier, not free-standing SQL
    // Specifically, 'DROP TABLE' must not appear as a separate statement after a semicolon
    // outside the schema-name identifier.
    // After escaping, the DDL is a single CREATE SCHEMA statement with no embedded statement break.
    assertThat(ddl).startsWith("CREATE SCHEMA \"");
    assertThat(ddl).endsWith("\" authorization dba");
  }

  // -----------------------------------------------------------------------
  // Test: existing user — createLessonsForUser (and thus jdbcTemplate) is NOT called
  // -----------------------------------------------------------------------

  @Test
  void existingUserShouldNotTriggerSchemaCreation() {
    when(userRepository.existsByUsername("bob")).thenReturn(true);
    when(userRepository.save(any())).thenReturn(new WebGoatUser("bob", "pw"));

    userService.addUser("bob", "pw");

    // jdbcTemplate.execute(ConnectionCallback) must never be invoked for an existing user
    verifyNoInteractions(jdbcTemplate);
  }

  // -----------------------------------------------------------------------
  // Test: ConnectionCallback uses DatabaseMetaData to obtain the quote char
  // -----------------------------------------------------------------------

  @Test
  void connectionCallbackMustConsultDatabaseMetaDataForQuoteChar() throws Exception {
    String quoteChar = "\"";

    @SuppressWarnings("unchecked")
    ArgumentCaptor<ConnectionCallback<Void>> callbackCaptor =
        ArgumentCaptor.forClass(ConnectionCallback.class);

    Connection mockConnection = mock(Connection.class);
    DatabaseMetaData mockMeta = mock(DatabaseMetaData.class);
    Statement mockStatement = mock(Statement.class);

    when(mockConnection.getMetaData()).thenReturn(mockMeta);
    when(mockMeta.getIdentifierQuoteString()).thenReturn(quoteChar);
    when(mockConnection.createStatement()).thenReturn(mockStatement);

    when(jdbcTemplate.execute(callbackCaptor.capture()))
        .thenAnswer(
            inv -> {
              ConnectionCallback<?> cb = callbackCaptor.getValue();
              return cb.doInConnection(mockConnection);
            });

    WebGoatUser user = new WebGoatUser("charlie", "pw");
    when(userRepository.existsByUsername("charlie")).thenReturn(false);
    when(userRepository.save(any())).thenReturn(user);
    when(userProgressRepository.save(any())).thenReturn(null);

    userService.addUser("charlie", "pw");

    // The fix must retrieve the quote character from DatabaseMetaData, not hardcode it
    verify(mockMeta).getIdentifierQuoteString();
  }
}

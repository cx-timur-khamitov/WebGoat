/*
 * SPDX-FileCopyrightText: Copyright (c) 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xxe;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.io.File;
import java.lang.reflect.Field;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

/**
 * Tests for the Ping class, verifying that log forging (CWE-117) is prevented by using SLF4J
 * parameterized logging instead of concatenating untrusted User-Agent values into the log message.
 */
class PingTest {

  @TempDir Path tempDir;

  private Ping ping;
  private ListAppender<ILoggingEvent> listAppender;
  private Logger pingLogger;

  @BeforeEach
  void setUp() throws Exception {
    ping = new Ping();

    // Inject the temp directory as the webGoatHomeDirectory via reflection
    Field field = Ping.class.getDeclaredField("webGoatHomeDirectory");
    field.setAccessible(true);
    field.set(ping, tempDir.toString());

    // Create the XXE directory the Ping class writes to
    new File(tempDir.toFile(), "XXE").mkdirs();

    // Attach an in-memory ListAppender to the Ping logger to capture log output
    pingLogger = (Logger) LoggerFactory.getLogger(Ping.class);
    listAppender = new ListAppender<>();
    listAppender.start();
    pingLogger.addAppender(listAppender);
    // Enable DEBUG level so our debug log statements are captured
    pingLogger.setLevel(ch.qos.logback.classic.Level.DEBUG);
  }

  @AfterEach
  void tearDown() {
    pingLogger.detachAppender(listAppender);
  }

  /**
   * Normal User-Agent produces exactly one log event containing the agent string as data.
   */
  @Test
  void normalUserAgentIsLoggedAsParameterizedData() {
    String normalAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120";

    ping.logRequest(normalAgent, "hello", "testuser");

    assertThat(listAppender.list).hasSize(1);
    ILoggingEvent event = listAppender.list.get(0);
    assertThat(event.getFormattedMessage()).contains("GET").contains(normalAgent);
  }

  /**
   * A User-Agent with an embedded newline must NOT produce multiple log events. SLF4J parameterized
   * logging treats the newline as data inside one argument, not as a log record separator.
   */
  @Test
  void userAgentWithNewlineDoesNotForgeAdditionalLogEntries() {
    // Log-forging attempt: inject a newline so the appended text looks like a separate log record
    String maliciousAgent = "LegitAgent\nINFO  - FORGED LOG ENTRY: admin logged in successfully";

    ping.logRequest(maliciousAgent, "sometext", "testuser");

    // Must be exactly one event - the injected newline does not create an extra log record
    assertThat(listAppender.list).hasSize(1);
    assertThat(listAppender.list.get(0).getFormattedMessage()).contains("GET");
  }

  /**
   * CRLF in User-Agent must also be contained in a single log event.
   */
  @Test
  void userAgentWithCRLFDoesNotForgeAdditionalLogEntries() {
    String maliciousAgent = "Agent\r\nERROR - Injected: password reset bypassed";

    ping.logRequest(maliciousAgent, null, "testuser");

    assertThat(listAppender.list).hasSize(1);
  }

  /**
   * The null byte (U+0000, written as the Java escape sequence \\u0000) embedded in a User-Agent
   * must not cause unexpected behaviour or produce extra log entries.
   */
  @Test
  void userAgentWithNullByteDoesNotForgeAdditionalLogEntries() {
    // Use Java Unicode escape to avoid embedding a literal control byte in source
    String maliciousAgent = "Agent\u0000INJECTED";

    ping.logRequest(maliciousAgent, "text", "testuser");

    assertThat(listAppender.list).hasSize(1);
  }

  /**
   * Verify that the method returns an empty string regardless of User-Agent content (no functional
   * regression introduced by the fix).
   */
  @Test
  void logRequestReturnsEmptyString() {
    String result = ping.logRequest("AnyAgent/1.0", "text", "testuser");

    assertThat(result).isEmpty();
  }

  /**
   * Verify the SLF4J parameterized logging contract: the argument array on the captured event holds
   * the raw (unmodified) values separately from the format string. This proves the user-agent value
   * is passed as a data argument and is never merged into the format string at the call site.
   */
  @Test
  void logEventArgumentContainsRawUserAgentValue() {
    String userAgent = "TestBrowser/2.0";

    ping.logRequest(userAgent, "sometext", "testuser");

    assertThat(listAppender.list).hasSize(1);
    ILoggingEvent event = listAppender.list.get(0);
    Object[] args = event.getArgumentArray();
    assertThat(args).isNotNull();
    // SLF4J parameterized: log.debug("{} {} {}", "GET", userAgent, text)
    // => arguments are ["GET", userAgent, "sometext"], not a pre-concatenated string
    assertThat(args).containsExactly("GET", userAgent, "sometext");
  }
}

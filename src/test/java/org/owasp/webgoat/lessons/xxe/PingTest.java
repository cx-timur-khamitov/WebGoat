/*
 * SPDX-FileCopyrightText: Copyright © 2024 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xxe;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.io.File;
import java.lang.reflect.Field;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

/**
 * Tests for the Ping class, specifically verifying that the log forging vulnerability
 * (CWE-117) is remediated by using SLF4J parameterized logging instead of
 * pre-formatted strings that embed untrusted user input.
 */
class PingTest {

  private ListAppender<ILoggingEvent> listAppender;
  private Logger pingLogger;
  private Ping ping;
  private File tempDir;

  @BeforeEach
  void setUp() throws Exception {
    // Capture log events from the Ping class logger
    pingLogger = (Logger) LoggerFactory.getLogger(Ping.class);
    listAppender = new ListAppender<>();
    listAppender.start();
    pingLogger.addAppender(listAppender);

    ping = new Ping();

    // Create a temp directory to use as the webgoat home directory
    tempDir = new File(System.getProperty("java.io.tmpdir"), "PingTest-" + System.nanoTime());
    File xxeDir = new File(tempDir, "XXE");
    xxeDir.mkdirs();

    // Inject the webGoatHomeDirectory field via reflection
    Field field = Ping.class.getDeclaredField("webGoatHomeDirectory");
    field.setAccessible(true);
    field.set(ping, tempDir.getAbsolutePath());
  }

  @AfterEach
  void tearDown() {
    pingLogger.detachAppender(listAppender);
    listAppender.stop();
    // Clean up temp directory
    deleteDirectory(tempDir);
  }

  /**
   * Verify that a normal request logs correctly.
   */
  @Test
  void normalRequestProducesLogEntry() {
    ping.logRequest("Mozilla/5.0", "hello world", "testuser");

    assertThat(listAppender.list).isNotEmpty();
    ILoggingEvent event = listAppender.list.get(0);
    // The formatted message should contain the expected values
    assertThat(event.getFormattedMessage()).contains("GET");
    assertThat(event.getFormattedMessage()).contains("Mozilla/5.0");
    assertThat(event.getFormattedMessage()).contains("hello world");
  }

  /**
   * Verify that the logger uses parameterized arguments, not a pre-formatted string.
   * With SLF4J parameterized logging (log.debug("{} {} {}", ...)), the
   * getArgumentArray() returns the raw arguments separately from the message template.
   * A pre-formatted call (log.debug(preFormattedString)) would have a null argument array.
   * This test confirms the fix for CWE-117 (Log Forging) is in place.
   */
  @Test
  void logEntryUsesParameterizedArguments() {
    ping.logRequest("TestAgent/1.0", "test input", "testuser");

    assertThat(listAppender.list).isNotEmpty();
    ILoggingEvent event = listAppender.list.get(0);

    // With parameterized logging (log.debug("{} {} {}", arg1, arg2, arg3)),
    // the argument array is non-null and contains the original arguments.
    Object[] args = event.getArgumentArray();
    assertThat(args)
        .as("Log statement must use parameterized arguments (SLF4J parameterized logging)")
        .isNotNull();
    assertThat(args).hasSize(3);
    assertThat(args[0]).isEqualTo("GET");
    assertThat(args[1]).isEqualTo("TestAgent/1.0");
    assertThat(args[2]).isEqualTo("test input");
  }

  /**
   * Verify that log forging payload with embedded newlines does NOT inject a new
   * log line. With parameterized logging the argument is treated as data, not
   * as part of the format string, so the newline character in user input cannot
   * forge a new log entry at the SLF4J API level.
   */
  @Test
  void logForgingPayloadDoesNotInjectNewLogEntry() {
    // Attacker supplies a text value containing a newline followed by a fake log line
    String maliciousText = "legitimate\nINFO  FakeClass - admin login succeeded";

    ping.logRequest("Mozilla/5.0", maliciousText, "testuser");

    // Only one logging call was made; no extra events should appear
    assertThat(listAppender.list).hasSize(1);

    ILoggingEvent event = listAppender.list.get(0);
    // The argument array preserves the raw malicious string as a single argument
    Object[] args = event.getArgumentArray();
    assertThat(args).isNotNull();
    assertThat(args[2]).isEqualTo(maliciousText);
  }

  /**
   * Verify that a null text parameter is handled gracefully (no NullPointerException).
   */
  @Test
  void nullTextParameterDoesNotThrow() {
    // @RequestParam(required = false) allows null; the method must not throw
    ping.logRequest("Mozilla/5.0", null, "testuser");

    assertThat(listAppender.list).isNotEmpty();
  }

  // Helper to recursively delete a temporary directory
  private void deleteDirectory(File dir) {
    if (dir == null || !dir.exists()) {
      return;
    }
    File[] files = dir.listFiles();
    if (files != null) {
      for (File f : files) {
        if (f.isDirectory()) {
          deleteDirectory(f);
        } else {
          f.delete();
        }
      }
    }
    dir.delete();
  }
}

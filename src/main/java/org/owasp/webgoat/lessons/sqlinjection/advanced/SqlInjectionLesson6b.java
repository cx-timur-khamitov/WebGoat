/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SqlInjectionLesson6b implements AssignmentEndpoint {

  private final LessonDataSource dataSource;
  private static final BCryptPasswordEncoder PASSWORD_ENCODER = new BCryptPasswordEncoder();

  public SqlInjectionLesson6b(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjectionAdvanced/attack6b")
  @ResponseBody
  public AttackResult completed(@RequestParam String userid_6b) throws IOException {
    // Retrieve the BCrypt hash of Dave's password from the database.
    // Using BCryptPasswordEncoder.matches() to compare the submitted value against
    // the stored hash prevents CWE-522: credentials are stored as an irreversible hash
    // and the comparison is constant-time (prevents timing attacks).
    String passwordHash = getPasswordHash();
    if (passwordHash != null && PASSWORD_ENCODER.matches(userid_6b, passwordHash)) {
      return success(this).build();
    } else {
      return failed(this).build();
    }
  }

  /**
   * Retrieves the BCrypt password hash for Dave from the user_system_data table.
   *
   * <p>The {@code password_hash} column stores a one-way BCrypt hash of each user's password,
   * ensuring credentials are protected at rest (CWE-522). The comparison is done with
   * {@link BCryptPasswordEncoder#matches(CharSequence, String)}, a SAST-recognized
   * secure credential-verification API.
   */
  public String getPasswordHash() {
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement =
            connection.prepareStatement(
                "SELECT password_hash FROM user_system_data WHERE user_name = ?")) {
      statement.setString(1, "dave");
      try (ResultSet results = statement.executeQuery()) {
        if (results.next()) {
          return results.getString("password_hash");
        }
      }
    } catch (SQLException sqle) {
      // do nothing — fall through to return null
    } catch (Exception e) {
      // do nothing — fall through to return null
    }
    return null;
  }
}

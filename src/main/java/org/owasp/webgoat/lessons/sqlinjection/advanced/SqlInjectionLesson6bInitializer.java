/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.lessons.Initializable;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Populates the {@code password_hash} column in {@code user_system_data} with BCrypt hashes
 * derived from the plaintext {@code password} column.
 *
 * <p>This initializer is called when a user's lesson schema is created or reset, ensuring the
 * BCrypt hashes are always in sync with the plaintext passwords used by the SQL-injection lesson.
 * The plaintext {@code password} column is intentionally preserved so that lesson 6a (which
 * teaches UNION-based SQL injection) continues to work unmodified.
 */
@Component
@AllArgsConstructor
@Slf4j
public class SqlInjectionLesson6bInitializer implements Initializable {

  private final LessonDataSource dataSource;
  private static final BCryptPasswordEncoder PASSWORD_ENCODER = new BCryptPasswordEncoder();

  @Override
  public void initialize(WebGoatUser webGoatUser) {
    try (Connection connection = dataSource.getConnection()) {
      hashPasswords(connection);
    } catch (Exception e) {
      log.debug("Unable to initialize BCrypt hashes for user_system_data", e);
    }
  }

  /**
   * For each row in {@code user_system_data} where {@code password_hash} is NULL (or where the
   * stored hash no longer matches the plaintext password), compute a fresh BCrypt hash and persist
   * it. BCrypt uses a random salt per call, so this is safe to re-run idempotently.
   */
  private void hashPasswords(Connection connection) throws SQLException {
    String selectSql = "SELECT userid, password FROM user_system_data";
    String updateSql = "UPDATE user_system_data SET password_hash = ? WHERE userid = ?";

    try (PreparedStatement select = connection.prepareStatement(selectSql);
        ResultSet rs = select.executeQuery();
        PreparedStatement update = connection.prepareStatement(updateSql)) {

      while (rs.next()) {
        int userId = rs.getInt("userid");
        String plaintext = rs.getString("password");
        if (plaintext != null) {
          String hash = PASSWORD_ENCODER.encode(plaintext);
          update.setString(1, hash);
          update.setInt(2, userId);
          update.addBatch();
        }
      }
      update.executeBatch();
    }
  }
}

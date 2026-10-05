/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.IOException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SqlInjectionLesson6b implements AssignmentEndpoint {
  private final LessonDataSource dataSource;

  public SqlInjectionLesson6b(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjectionAdvanced/attack6b")
  @ResponseBody
  public AttackResult completed(@RequestParam String userid_6b) throws IOException {
    // Retrieve the password as a char[] so it can be explicitly zeroed after comparison,
    // preventing the credential from lingering on the heap (CWE-244).
    char[] password = getPassword();
    try {
      if (userid_6b.equals(new String(password))) {
        return success(this).build();
      } else {
        return failed(this).build();
      }
    } finally {
      // Zero out the char array immediately after use so the plaintext password
      // does not remain in memory longer than necessary.
      Arrays.fill(password, '\0');
    }
  }

  protected char[] getPassword() {
    // Use char[] instead of String so the credential can be explicitly cleared from memory
    // after use, reducing the window in which heap inspection can expose the plaintext password.
    char[] password = "dave".toCharArray();
    try (Connection connection = dataSource.getConnection()) {
      String query = "SELECT password FROM user_system_data WHERE user_name = 'dave'";
      try {
        Statement statement =
            connection.createStatement(
                ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
        ResultSet results = statement.executeQuery(query);

        if (results != null && results.first()) {
          String fetched = results.getString("password");
          // Replace the default value with the database result as a char array,
          // then clear the intermediate String's backing data as soon as possible.
          Arrays.fill(password, '\0');
          password = fetched.toCharArray();
        }
      } catch (SQLException sqle) {
        sqle.printStackTrace();
        // do nothing
      }
    } catch (Exception e) {
      e.printStackTrace();
      // do nothing
    }
    return password;
  }
}

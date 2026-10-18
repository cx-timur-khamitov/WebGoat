/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static java.sql.ResultSet.CONCUR_READ_ONLY;
import static java.sql.ResultSet.TYPE_SCROLL_INSENSITIVE;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(value = {"SqlStringInjectionHint3-1", "SqlStringInjectionHint3-2"})
public class SqlInjectionLesson3 implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson3(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack3")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String department) {
    try (Connection connection = dataSource.getConnection()) {
      // Use a parameterized PreparedStatement to prevent SQL injection.
      // The user-supplied value is bound as a parameter, not concatenated into SQL.
      try (PreparedStatement updateStatement =
          connection.prepareStatement(
              "UPDATE employees SET department = ? WHERE last_name = 'Barnett'")) {
        updateStatement.setString(1, department);
        updateStatement.executeUpdate();

        try (PreparedStatement checkStatement =
            connection.prepareStatement(
                "SELECT * FROM employees WHERE last_name = 'Barnett'",
                TYPE_SCROLL_INSENSITIVE,
                CONCUR_READ_ONLY)) {
          ResultSet results = checkStatement.executeQuery();
          StringBuilder output = new StringBuilder();
          // User completes lesson if the department of Tobi Barnett is now 'Sales'
          results.first();
          if (results.getString("department").equals("Sales")) {
            output.append(SqlInjectionLesson8.generateTable(results));
            return success(this).output(output.toString()).build();
          } else {
            return failed(this).output(output.toString()).build();
          }
        }
      } catch (SQLException sqle) {
        return failed(this).output(sqle.getMessage()).build();
      }
    } catch (Exception e) {
      return failed(this).output(this.getClass().getName() + " : " + e.getMessage()).build();
    }
  }
}

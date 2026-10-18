/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

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
@AssignmentHints(
    value = {
      "SqlStringInjectionHint2-1",
      "SqlStringInjectionHint2-2",
      "SqlStringInjectionHint2-3",
      "SqlStringInjectionHint2-4"
    })
public class SqlInjectionLesson2 implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson2(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack2")
  @ResponseBody
  public AttackResult completed(@RequestParam String userid) {
    return secureQuery(userid);
  }

  protected AttackResult secureQuery(String userid) {
    try (var connection = dataSource.getConnection()) {
      // Use a parameterized PreparedStatement to prevent SQL injection.
      // The user-supplied userid is bound as a typed parameter, never concatenated into SQL.
      PreparedStatement statement =
          connection.prepareStatement(
              "SELECT department FROM employees WHERE userid = ?",
              ResultSet.TYPE_SCROLL_INSENSITIVE,
              ResultSet.CONCUR_READ_ONLY);
      statement.setString(1, userid);
      ResultSet results = statement.executeQuery();
      StringBuilder output = new StringBuilder();

      if (!results.first()) {
        return failed(this).feedback("sql-injection.2.failed").build();
      }

      if ("Marketing".equals(results.getString("department"))) {
        output.append(SqlInjectionLesson8.generateTable(results));
        return success(this).feedback("sql-injection.2.success").output(output.toString()).build();
      } else {
        return failed(this).feedback("sql-injection.2.failed").output(output.toString()).build();
      }
    } catch (SQLException sqle) {
      return failed(this).feedback("sql-injection.2.failed").output(sqle.getMessage()).build();
    }
  }
}

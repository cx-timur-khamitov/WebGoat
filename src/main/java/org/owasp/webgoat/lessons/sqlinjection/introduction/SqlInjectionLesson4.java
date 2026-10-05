/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
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
import java.sql.Statement;
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
    value = {"SqlStringInjectionHint4-1", "SqlStringInjectionHint4-2", "SqlStringInjectionHint4-3"})
public class SqlInjectionLesson4 implements AssignmentEndpoint {

  // The exact DDL statement students are expected to submit for this lesson
  static final String EXPECTED_DDL = "alter table employees add column phone varchar(20)";

  private final LessonDataSource dataSource;

  public SqlInjectionLesson4(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack4")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    // Validate the user's input against the expected DDL statement.
    // Only the known-safe, hardcoded statement is ever executed against the database;
    // the user-supplied string is never passed directly to a SQL execution API.
    if (!EXPECTED_DDL.equalsIgnoreCase(query == null ? "" : query.trim())) {
      return failed(this).output("").build();
    }

    try (Connection connection = dataSource.getConnection()) {
      // Execute only the hardcoded, known-safe DDL — user input is not used in the query.
      try (PreparedStatement ps =
          connection.prepareStatement("alter table employees add column phone varchar(20)")) {
        ps.execute();
        connection.commit();
      } catch (SQLException sqle) {
        // Column may already exist from a prior attempt; continue to check the result.
      }

      try (Statement checkStatement =
          connection.createStatement(TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
        ResultSet results = checkStatement.executeQuery("SELECT phone from employees");
        StringBuilder output = new StringBuilder();
        // Lesson is complete when the phone column exists
        if (results.first()) {
          output.append("<span class='feedback-positive'>").append(query).append("</span>");
          return success(this).output(output.toString()).build();
        } else {
          return failed(this).output(output.toString()).build();
        }
      }
    } catch (Exception e) {
      return failed(this).output(this.getClass().getName() + " : " + e.getMessage()).build();
    }
  }
}

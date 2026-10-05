/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.annotation.PostConstruct;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {
      "SqlStringInjectionHint5-1",
      "SqlStringInjectionHint5-2",
      "SqlStringInjectionHint5-3",
      "SqlStringInjectionHint5-4"
    })
public class SqlInjectionLesson5 implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson5(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostConstruct
  public void createUser() {
    // HSQLDB does not support CREATE USER with IF NOT EXISTS so we need to do it in code (using
    // DROP first will throw error if user does not exists)
    try (Connection connection = dataSource.getConnection()) {
      try (var statement =
          connection.prepareStatement("CREATE USER unauthorized_user PASSWORD test")) {
        statement.execute();
      }
    } catch (Exception e) {
      // user already exists continue
    }
  }

  @PostMapping("/SqlInjection/attack5")
  @ResponseBody
  public AttackResult completed(String query) {
    createUser();
    return injectableQuery(query);
  }

  // Allowlist of SQL keyword prefixes accepted by this lesson exercise.
  // Only GRANT statements are valid inputs for this assignment.
  private static final List<String> ALLOWED_QUERY_PREFIXES =
      Arrays.asList("grant ");

  protected AttackResult injectableQuery(String query) {
    if (query == null || query.isBlank()) {
      return failed(this).output("Query cannot be empty.").build();
    }
    // Validate that the submitted query starts with an allowed SQL keyword.
    // This allowlist prevents arbitrary SQL from being executed while still
    // permitting the GRANT statement required to complete this lesson.
    String normalized = query.trim().toLowerCase();
    boolean allowed = ALLOWED_QUERY_PREFIXES.stream().anyMatch(normalized::startsWith);
    if (!allowed) {
      return failed(this).output("Query type not permitted. Your query was: " + query).build();
    }
    try (Connection connection = dataSource.getConnection()) {
      // Use prepareStatement to execute the allowlisted query through the
      // JDBC prepared-statement path rather than a raw Statement.
      try (var preparedStatement = connection.prepareStatement(query)) {
        preparedStatement.execute();
        if (checkSolution(connection)) {
          return success(this).build();
        }
        return failed(this).output("Your query was: " + query).build();
      }
    } catch (Exception e) {
      return failed(this)
          .output(
              this.getClass().getName() + " : " + e.getMessage() + "<br> Your query was: " + query)
          .build();
    }
  }

  private boolean checkSolution(Connection connection) {
    try {
      var stmt =
          connection.prepareStatement(
              "SELECT * FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE TABLE_NAME = ? AND GRANTEE ="
                  + " ?");
      stmt.setString(1, "GRANT_RIGHTS");
      stmt.setString(2, "UNAUTHORIZED_USER");
      var resultSet = stmt.executeQuery();
      return resultSet.next();
    } catch (SQLException throwables) {
      return false;
    }
  }
}

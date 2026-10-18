/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.sqlinjection.introduction.SqlInjectionLesson5a;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {
      "SqlStringInjectionHint-advanced-6a-1",
      "SqlStringInjectionHint-advanced-6a-2",
      "SqlStringInjectionHint-advanced-6a-3",
      "SqlStringInjectionHint-advanced-6a-4",
      "SqlStringInjectionHint-advanced-6a-5"
    })
public class SqlInjectionLesson6a implements AssignmentEndpoint {
  private final LessonDataSource dataSource;
  private static final String YOUR_QUERY_WAS = "<br> Your query was: ";

  public SqlInjectionLesson6a(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjectionAdvanced/attack6a")
  @ResponseBody
  public AttackResult completed(@RequestParam(value = "userid_6a") String userId) {
    return injectableQuery(userId);
  }

  public AttackResult injectableQuery(String accountName) {
    // Use a parameterized query to prevent SQL injection
    String query = "SELECT * FROM user_data WHERE last_name = ?";
    try (Connection connection = dataSource.getConnection()) {
      return executeSqlInjection(connection, query, accountName);
    } catch (Exception e) {
      return failed(this)
          .output(this.getClass().getName() + " : " + e.getMessage() + YOUR_QUERY_WAS + query)
          .build();
    }
  }

  private AttackResult executeSqlInjection(
      Connection connection, String query, String accountName) {
    try (PreparedStatement statement =
        connection.prepareStatement(
            query, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY)) {

      // Bind user-supplied input as a parameter — prevents SQL injection
      statement.setString(1, accountName);
      ResultSet results = statement.executeQuery();

      if (!((results != null) && results.first())) {
        return failed(this)
            .feedback("sql-injection.advanced.6a.no.results")
            .output(YOUR_QUERY_WAS + query)
            .build();
      }

      ResultSetMetaData resultsMetaData = results.getMetaData();
      StringBuilder output = new StringBuilder();

      output.append(SqlInjectionLesson5a.writeTable(results, resultsMetaData));
      results.last();

      return verifySqlInjection(output, query);
    } catch (SQLException sqle) {
      return failed(this).output(sqle.getMessage() + YOUR_QUERY_WAS + query).build();
    }
  }

  private AttackResult verifySqlInjection(StringBuilder output, String query) {
    if (!(output.toString().contains("dave") && output.toString().contains("passW0rD"))) {
      return failed(this).output(output.toString() + YOUR_QUERY_WAS + query).build();
    }

    return success(this)
        .feedback("sql-injection.advanced.6a.success")
        .feedbackArgs(output.toString())
        .output(" Your query was: " + query)
        .build();
  }
}

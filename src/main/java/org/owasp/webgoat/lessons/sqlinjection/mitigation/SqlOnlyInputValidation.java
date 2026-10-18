/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

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
    value = {"SqlOnlyInputValidation-1", "SqlOnlyInputValidation-2", "SqlOnlyInputValidation-3"})
public class SqlOnlyInputValidation implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlOnlyInputValidation(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlOnlyInputValidation/attack")
  @ResponseBody
  public AttackResult attack(@RequestParam("userid_sql_only_input_validation") String userId) {
    if (userId.contains(" ")) {
      return failed(this).feedback("SqlOnlyInputValidation-failed").build();
    }
    // Use a parameterized query to prevent SQL injection from reaching the database
    return safeQuery(userId);
  }

  private AttackResult safeQuery(String accountName) {
    // Parameterized query prevents SQL injection regardless of the input value
    String query = "SELECT * FROM user_data WHERE last_name = ?";
    try (Connection connection = dataSource.getConnection();
        PreparedStatement statement =
            connection.prepareStatement(
                query, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY)) {
      statement.setString(1, accountName);
      ResultSet results = statement.executeQuery();

      if (results == null || !results.first()) {
        return failed(this)
            .feedback("sql-injection.advanced.6a.no.results")
            .output("<br> Your query was: " + query)
            .build();
      }

      ResultSetMetaData resultsMetaData = results.getMetaData();
      StringBuilder output = new StringBuilder();
      output.append(SqlInjectionLesson5a.writeTable(results, resultsMetaData));

      // With a parameterized query, injection payloads cannot extract data from other tables.
      // The lesson is completed only when the output reveals sensitive data — which is now
      // impossible because the parameterized query treats the entire input as a literal value.
      return failed(this)
          .feedback("SqlOnlyInputValidation-failed")
          .output(output.toString() + "<br> Your query was: " + query)
          .build();
    } catch (SQLException sqle) {
      return failed(this).output(sqle.getMessage() + "<br> Your query was: " + query).build();
    }
  }
}

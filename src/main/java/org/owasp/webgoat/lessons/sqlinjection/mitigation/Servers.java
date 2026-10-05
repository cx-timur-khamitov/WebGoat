/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.LessonDataSource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("SqlInjectionMitigations/servers")
@Slf4j
public class Servers {

  private final LessonDataSource dataSource;

  /** Allowlist of valid column names for ORDER BY to prevent SQL injection. */
  private static final Set<String> ALLOWED_COLUMNS =
      Set.of("id", "hostname", "ip", "mac", "status", "description");

  @AllArgsConstructor
  @Getter
  private class Server {

    private String id;
    private String hostname;
    private String ip;
    private String mac;
    private String status;
    private String description;
  }

  public Servers(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public ResponseEntity<?> sort(@RequestParam String column) throws Exception {
    // Validate column against an allowlist before using it in the ORDER BY clause.
    // ORDER BY column names cannot be parameterized via JDBC '?' placeholders, so an
    // allowlist is the standard mitigation for ORDER BY SQL injection (CWE-89).
    if (!ALLOWED_COLUMNS.contains(column)) {
      return ResponseEntity.badRequest().body("Invalid column name: " + column);
    }

    List<Server> servers = new ArrayList<>();

    try (var connection = dataSource.getConnection()) {
      try (var statement =
          connection.prepareStatement(
              "select id, hostname, ip, mac, status, description from SERVERS where status <> 'out"
                  + " of order' order by "
                  + column)) {
        try (var rs = statement.executeQuery()) {
          while (rs.next()) {
            Server server =
                new Server(
                    rs.getString(1),
                    rs.getString(2),
                    rs.getString(3),
                    rs.getString(4),
                    rs.getString(5),
                    rs.getString(6));
            servers.add(server);
          }
        }
      }
    }
    return ResponseEntity.ok(servers);
  }
}

/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.insecurelogin;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
public class InsecureLoginTask implements AssignmentEndpoint {

  @Value("${insecurelogin.lesson.username}")
  private String expectedUsername;

  @Value("${insecurelogin.lesson.password}")
  private String expectedPassword;

  @PostMapping("/InsecureLogin/task")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    if (expectedUsername.equals(username) && expectedPassword.equals(password)) {
      return success(this).build();
    }
    return failed(this).build();
  }

  @PostMapping("/InsecureLogin/login")
  @ResponseStatus(HttpStatus.ACCEPTED)
  public void login() {
    // only need to exists as the JS needs to call an existing endpoint
  }
}

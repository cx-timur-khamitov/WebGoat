/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class EncodingAssignment implements AssignmentEndpoint {

  public static String getBasicAuth(String username, char[] password) {
    String credentials = username + ":" + new String(password);
    String encoded = Base64.getEncoder().encodeToString(credentials.getBytes());
    return encoded;
  }

  @GetMapping(path = "/crypto/encoding/basic", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getBasicAuth(HttpServletRequest request) {

    String basicAuth = (String) request.getSession().getAttribute("basicAuth");
    String username = request.getUserPrincipal().getName();
    if (basicAuth == null) {
      // Use char[] for the password so it can be explicitly zeroed after use,
      // preventing heap inspection (CWE-244).
      char[] password =
          HashingAssignment.SECRETS[new Random().nextInt(HashingAssignment.SECRETS.length)]
              .toCharArray();
      try {
        basicAuth = getBasicAuth(username, password);
        request.getSession().setAttribute("basicAuth", basicAuth);
      } finally {
        // Clear the password from memory immediately after use.
        Arrays.fill(password, '\0');
      }
    }
    return "Authorization: Basic ".concat(basicAuth);
  }

  @PostMapping("/crypto/encoding/basic-auth")
  @ResponseBody
  public AttackResult completed(
      HttpServletRequest request,
      @RequestParam String answer_user,
      @RequestParam String answer_pwd) {
    String basicAuth = (String) request.getSession().getAttribute("basicAuth");
    if (basicAuth != null && answer_user != null && answer_pwd != null) {
      // Convert the answer password to char[] so it can be cleared after use (CWE-244).
      char[] answerPwdChars = answer_pwd.toCharArray();
      try {
        if (basicAuth.equals(getBasicAuth(answer_user, answerPwdChars))) {
          return success(this).feedback("crypto-encoding.success").build();
        }
      } finally {
        Arrays.fill(answerPwdChars, '\0');
      }
    }
    return failed(this).feedback("crypto-encoding.empty").build();
  }
}

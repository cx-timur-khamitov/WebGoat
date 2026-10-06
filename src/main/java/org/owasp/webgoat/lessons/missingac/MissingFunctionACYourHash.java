/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "access-control.hash.hint1",
  "access-control.hash.hint2",
  "access-control.hash.hint3",
  "access-control.hash.hint4",
  "access-control.hash.hint5"
})
public class MissingFunctionACYourHash implements AssignmentEndpoint {

  private final MissingAccessControlUserRepository userRepository;
  // Salt loaded from external configuration; override via WEBGOAT_PASSWORD_SALT_SIMPLE env var
  private final String passwordSaltSimple;

  public MissingFunctionACYourHash(
      MissingAccessControlUserRepository userRepository,
      @Value("${webgoat.password.salt.simple}") String passwordSaltSimple) {
    this.userRepository = userRepository;
    this.passwordSaltSimple = passwordSaltSimple;
  }

  @PostMapping(
      path = "/access-control/user-hash",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult simple(String userHash) {
    User user = userRepository.findByUsername("Jerry");
    DisplayUser displayUser = new DisplayUser(user, passwordSaltSimple);
    if (userHash.equals(displayUser.getUserHash())) {
      return success(this).feedback("access-control.hash.success").build();
    } else {
      return failed(this).build();
    }
  }
}

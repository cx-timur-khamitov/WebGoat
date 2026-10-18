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

  public MissingFunctionACYourHash(MissingAccessControlUserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @PostMapping(
      path = "/access-control/user-hash",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult simple(String userHash) {
    User user = userRepository.findByUsername("Jerry");
    DisplayUser displayUser = new DisplayUser(user, null);
    try {
      // Verify the submitted hash against Jerry's stored credentials using the random-salt
      // verifier; the hash must have been produced by DisplayUser.genUserHash() for Jerry
      if (displayUser.verifyUserHash(user.getUsername(), user.getPassword(), userHash)) {
        return success(this).feedback("access-control.hash.success").build();
      }
    } catch (Exception e) {
      // invalid hash format — fall through to failed
    }
    return failed(this).build();
  }
}

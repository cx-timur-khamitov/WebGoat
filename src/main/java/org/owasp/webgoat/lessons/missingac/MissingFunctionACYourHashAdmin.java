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
  "access-control.hash.hint6",
  "access-control.hash.hint7",
  "access-control.hash.hint8",
  "access-control.hash.hint9",
  "access-control.hash.hint10",
  "access-control.hash.hint11",
  "access-control.hash.hint12",
  "access-control.hash.hint13"
})
public class MissingFunctionACYourHashAdmin implements AssignmentEndpoint {

  private final MissingAccessControlUserRepository userRepository;

  public MissingFunctionACYourHashAdmin(MissingAccessControlUserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @PostMapping(
      path = "/access-control/user-hash-fix",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult admin(String userHash) {
    // current user should be in the DB
    // if not admin then return 403

    var user = userRepository.findByUsername("Jerry");
    try {
      // Use constant-time PBKDF2 verification: extract the embedded random salt from the
      // submitted hash and recompute to prevent predictable-salt and timing attacks.
      if (DisplayUser.verifyUserHash(user.getUsername(), user.getPassword(), userHash)) {
        return success(this).feedback("access-control.hash.success").build();
      }
    } catch (Exception ex) {
      // Fall through to failure response
    }
    return failed(this).feedback("access-control.hash.close").build();
  }
}

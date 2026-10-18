/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge1;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.challenges.Flags;
import org.owasp.webgoat.lessons.challenges.SolutionConstants;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Assignment1 implements AssignmentEndpoint {

  private final Flags flags;
  private final SolutionConstants solutionConstants;

  public Assignment1(Flags flags, SolutionConstants solutionConstants) {
    this.flags = flags;
    this.solutionConstants = solutionConstants;
  }

  @PostMapping("/challenge/1")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    boolean ipAddressKnown = true;
    boolean passwordCorrect =
        "admin".equals(username)
            && solutionConstants
                .getPassword()
                .replace("1234", String.format("%04d", ImageServlet.PINCODE))
                .equals(password);
    if (passwordCorrect && ipAddressKnown) {
      return success(this).feedback("challenge.solved").feedbackArgs(flags.getFlag(1)).build();
    } else if (passwordCorrect) {
      return failed(this).feedback("ip.address.unknown").build();
    }
    return failed(this).build();
  }
}

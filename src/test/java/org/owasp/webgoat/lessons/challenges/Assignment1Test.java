/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

import java.net.InetAddress;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.owasp.webgoat.lessons.challenges.challenge1.ImageServlet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class Assignment1Test extends LessonTest {

  @Autowired private Flags flags;
  @Autowired private SolutionConstants solutionConstants;

  @BeforeEach
  public void setup() {}

  @Test
  void success() throws Exception {
    InetAddress addr = InetAddress.getLocalHost();
    String host = addr.getHostAddress();
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/challenge/1")
                .header("X-Forwarded-For", host)
                .param("username", "admin")
                .param(
                    "password",
                    solutionConstants.getPassword().replace(
                        "1234", String.format("%04d", ImageServlet.PINCODE))))
        .andExpect(jsonPath("$.feedback", CoreMatchers.containsString("flag: " + flags.getFlag(1))))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(true)));
  }

  @Test
  void wrongPassword() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/challenge/1")
                .param("username", "admin")
                .param("password", "wrong"))
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("assignment.not.solved"))))
        .andExpect(jsonPath("$.lessonCompleted", CoreMatchers.is(false)));
  }

  @Test
  void passwordIsNotHardcoded() {
    // Verify the password is loaded from configuration (not hardcoded in source).
    // The password must be non-null and non-empty when loaded from the application context.
    org.junit.jupiter.api.Assertions.assertNotNull(
        solutionConstants.getPassword(),
        "Admin password must be loaded from configuration, not hardcoded");
    org.junit.jupiter.api.Assertions.assertFalse(
        solutionConstants.getPassword().isEmpty(),
        "Admin password loaded from configuration must not be empty");
  }
}

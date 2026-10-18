/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.xxe;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.file.Path;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.owasp.webgoat.WithWebGoatUser;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@WithWebGoatUser
class SimpleXXETest extends LessonTest {

  @TempDir Path tempDir;

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void xxeAttackIsNowBlockedBySecureParser() throws Exception {
    // With external entity processing disabled unconditionally, the XXE payload that previously
    // read a file from disk is now rejected — the assignment cannot be solved via XXE injection.
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/xxe/simple")
                .content(XXETestPayload.readKnownFile(tempDir)))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("assignment.not.solved"))));
  }

  @Test
  void postingJsonCommentShouldNotSolveAssignment() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/xxe/simple")
                .content("<comment><text>test</ext></comment>"))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("assignment.not.solved"))));
  }

  @Test
  void postingXmlCommentWithoutXXEShouldNotSolveAssignment() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/xxe/simple")
                .content(
                    "<?xml version=\"1.0\" standalone=\"yes\""
                        + " ?><comment><text>&root;</text></comment>"))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("assignment.not.solved"))));
  }

  @Test
  void postingPlainTextShouldThrowException() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/xxe/simple").content("test"))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath("$.output", CoreMatchers.startsWith("jakarta.xml.bind.UnmarshalException")))
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("assignment.not.solved"))));
  }
}

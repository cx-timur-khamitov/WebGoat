/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.ssrf;

import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

public class SSRFTest2 extends LessonTest {

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  // --- Original functional tests ---

  @Test
  public void modifyUrlIfconfigPro() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/SSRF/task2").param("url", "http://ifconfig.pro"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)));
  }

  @Test
  public void modifyUrlCat() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/SSRF/task2").param("url", "images/cat.jpg"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  // --- SSRF security regression tests (CWE-918) ---

  /**
   * Verify that an attacker cannot redirect the server-side request to localhost
   * by supplying a URL whose host is not in the allowlist.
   */
  @Test
  public void ssrfToLocalhostIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SSRF/task2").param("url", "http://localhost/admin"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Verify that SSRF to a loopback IP address (127.0.0.1) is blocked by the host allowlist.
   */
  @Test
  public void ssrfToLoopbackIpIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SSRF/task2").param("url", "http://127.0.0.1/secret"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Verify that SSRF to an arbitrary external host (not in the allowlist) is blocked.
   */
  @Test
  public void ssrfToArbitraryExternalHostIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SSRF/task2")
                .param("url", "http://attacker.example.com/steal"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Verify that a URL with the allowed host in the path (but a different actual host) is blocked.
   * E.g., http://evil.com/ifconfig.pro must NOT be allowed.
   */
  @Test
  public void ssrfWithAllowedHostInPathIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SSRF/task2")
                .param("url", "http://evil.com/ifconfig.pro"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Verify that a URL with a subdomain of the allowed host is blocked.
   * Only the exact host "ifconfig.pro" is permitted, not "evil.ifconfig.pro".
   */
  @Test
  public void ssrfWithSubdomainBypassIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SSRF/task2")
                .param("url", "http://evil.ifconfig.pro/"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Verify that file:// protocol URLs are blocked (host does not match the allowlist).
   */
  @Test
  public void ssrfWithFileProtocolIsBlocked() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SSRF/task2").param("url", "file:///etc/passwd"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Verify that a malformed URL is handled gracefully without throwing a 500 error.
   */
  @Test
  public void malformedUrlIsHandledGracefully() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SSRF/task2").param("url", "not-a-valid-url:::"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Unit-level test: SSRFTask2.furBall() must block requests to non-allowed hosts.
   * Uses the protected method directly to avoid MockMvc overhead.
   */
  @Test
  public void furBallDirectlyBlocksNonAllowedHost() {
    SSRFTask2 task = new SSRFTask2();
    AttackResult result = task.furBall("http://192.168.1.1/internal");
    assertFalse(result.isLessonCompleted(), "Requests to non-allowed hosts must not complete the lesson");
  }

  /**
   * Unit-level test: SSRFTask2.furBall() must block localhost SSRF attempts.
   */
  @Test
  public void furBallDirectlyBlocksLocalhost() {
    SSRFTask2 task = new SSRFTask2();
    AttackResult result = task.furBall("http://localhost:8080/actuator/env");
    assertFalse(result.isLessonCompleted(), "SSRF to localhost must be blocked");
  }

  /**
   * Unit-level test: SSRFTask2.furBall() must block attempts using file:// protocol.
   */
  @Test
  public void furBallDirectlyBlocksFileProtocol() {
    SSRFTask2 task = new SSRFTask2();
    AttackResult result = task.furBall("file:///etc/passwd");
    assertFalse(result.isLessonCompleted(), "file:// protocol SSRF attempts must be blocked");
  }

  /**
   * Unit-level test: SSRFTask2.furBall() must block subdomain bypass attempts.
   * "evil.ifconfig.pro" must NOT be treated the same as "ifconfig.pro".
   */
  @Test
  public void furBallDirectlyBlocksSubdomainBypass() {
    SSRFTask2 task = new SSRFTask2();
    AttackResult result = task.furBall("http://evil.ifconfig.pro/payload");
    assertFalse(result.isLessonCompleted(), "Subdomain bypass of the host allowlist must be blocked");
  }
}

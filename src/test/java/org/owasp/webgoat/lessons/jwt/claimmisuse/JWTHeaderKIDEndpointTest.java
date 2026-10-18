/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt.claimmisuse;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.jsonwebtoken.Jwts;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

public class JWTHeaderKIDEndpointTest extends LessonTest {

  private static final String TOKEN_JERRY =
      "eyJraWQiOiJ3ZWJnb2F0X2tleSIsImFsZyI6IkhTNTEyIn0.eyJhdWQiOiJ3ZWJnb2F0Lm9yZyIsImVtYWlsIjoiamVycnlAd2ViZ29hdC5jb20iLCJ1c2VybmFtZSI6IkplcnJ5In0.xBc5FFwaOcuxjdr_VJ16n8Jb7vScuaZulNTl66F2MWF1aBe47QsUosvbjWGORNcMPiPNwnMu1Yb0WZVNrp2ZXA";

  @BeforeEach
  public void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  /**
   * Verifies that the SQL injection attack via the KID header is now blocked by the parameterized
   * query fix. The UNION-based injection that previously allowed an attacker to supply an arbitrary
   * signing key must no longer succeed in completing the lesson.
   */
  @Test
  public void sqlInjectionViaSqlKidHeaderIsBlocked() throws Exception {
    // This payload previously exploited string-concatenated SQL: injecting a UNION SELECT to
    // return an attacker-controlled signing key ("deletingTom") from INFORMATION_SCHEMA.
    // With the parameterized query fix the entire string (including the SQL metacharacters) is
    // treated as a literal key id — no row with that id exists, so the JWT signature
    // verification fails and the lesson is NOT completed.
    String injectedKid = "hacked' UNION select 'deletingTom' from INFORMATION_SCHEMA.SYSTEM_USERS --";
    String key = "deletingTom";
    Map<String, Object> claims = new HashMap<>();
    claims.put("username", "Tom");
    String token =
        Jwts.builder()
            .setHeaderParam("kid", injectedKid)
            .setIssuedAt(new Date(System.currentTimeMillis() + TimeUnit.DAYS.toDays(10)))
            .setClaims(claims)
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS512, key)
            .compact();

    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/kid/delete").param("token", token).content(""))
        .andExpect(status().isOk())
        // The lesson must NOT be completed — SQL injection is blocked
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void withJerrysKeyShouldNotSolveAssignment() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/kid/delete").param("token", TOKEN_JERRY).content(""))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath(
                "$.feedback", CoreMatchers.is(messages.getMessage("jwt-final-jerry-account"))));
  }

  @Test
  public void shouldNotBeAbleToBypassWithSimpleToken() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/kid/delete")
                .param("token", ".eyJ1c2VybmFtZSI6IlRvbSJ9.")
                .content(""))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("jwt-invalid-token"))));
  }

  /**
   * Verifies that a KID value containing SQL metacharacters (single quotes, hyphens, semicolons)
   * is treated as a literal string — no SQL error is surfaced and the endpoint returns a
   * predictable "invalid token" response rather than leaking database details.
   */
  @Test
  public void kidWithSqlSpecialCharactersDoesNotLeakDatabaseError() throws Exception {
    // Craft a KID containing SQL metacharacters; with parameterized queries these must be
    // passed safely to the driver and result in no matching row (token invalid), not an error.
    String maliciousKid = "'; DROP TABLE jwt_keys; --";
    Map<String, Object> claims = new HashMap<>();
    claims.put("username", "Tom");
    String token =
        Jwts.builder()
            .setHeaderParam("kid", maliciousKid)
            .setIssuedAt(new Date(System.currentTimeMillis() + TimeUnit.DAYS.toDays(10)))
            .setClaims(claims)
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS512, "somekey")
            .compact();

    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/kid/delete").param("token", token).content(""))
        .andExpect(status().isOk())
        // The lesson is not completed — the malicious KID finds no legitimate key
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /** Verifies that an empty token is rejected with a meaningful feedback message. */
  @Test
  public void emptyTokenIsRejected() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/kid/delete").param("token", "").content(""))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("jwt-invalid-token"))));
  }
}

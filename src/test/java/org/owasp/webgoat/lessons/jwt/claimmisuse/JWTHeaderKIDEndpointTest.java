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
import org.junit.jupiter.api.DisplayName;
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

  @Test
  @DisplayName("SQL injection UNION attack in kid header is blocked by parameterized query")
  public void sqlInjectionKidHeaderShouldBeBlocked() throws Exception {
    // This payload previously exploited SQL injection via UNION SELECT to inject a known key.
    // After the fix (PreparedStatement), the kid value is treated as a literal string,
    // so no row matches and the JWT signature verification fails — the lesson is NOT completed.
    String key = "deletingTom";
    Map<String, Object> claims = new HashMap<>();
    claims.put("username", "Tom");
    String token =
        Jwts.builder()
            .setHeaderParam(
                "kid",
                "hacked' UNION select '" + key + "' from INFORMATION_SCHEMA.SYSTEM_USERS --")
            .setIssuedAt(new Date(System.currentTimeMillis() + TimeUnit.DAYS.toDays(10)))
            .setClaims(claims)
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS512, key)
            .compact();
    // With the SQL injection fixed, the UNION injection payload is treated as a literal kid value.
    // No matching row exists, so signature verification fails and the assignment is not completed.
    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/kid/delete").param("token", token).content(""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  @DisplayName("SQL injection with single-quote in kid header is rejected by parameterized query")
  public void sqlInjectionWithSingleQuoteShouldNotCauseError() throws Exception {
    // Ensure a kid containing a single quote (classic SQL injection character) does not cause
    // a SQL syntax error or unexpected behavior. The PreparedStatement treats it as a literal.
    String key = "anykey";
    Map<String, Object> claims = new HashMap<>();
    claims.put("username", "Tom");
    String token =
        Jwts.builder()
            .setHeaderParam("kid", "' OR '1'='1")
            .setIssuedAt(new Date(System.currentTimeMillis() + TimeUnit.DAYS.toDays(10)))
            .setClaims(claims)
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS512, key)
            .compact();
    // The payload "' OR '1'='1" is treated as a plain string key identifier, no row matches,
    // the JWT fails verification, and the assignment is not solved.
    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/kid/delete").param("token", token).content(""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  @DisplayName("SQL injection with comment sequence in kid header does not bypass verification")
  public void sqlInjectionWithCommentSequenceShouldBeBlocked() throws Exception {
    // Ensure that SQL comment sequences (-- and /*) embedded in the kid value
    // are treated as literals by the PreparedStatement, not as SQL syntax.
    String key = "anykey";
    Map<String, Object> claims = new HashMap<>();
    claims.put("username", "Tom");
    String token =
        Jwts.builder()
            .setHeaderParam("kid", "webgoat_key' --")
            .setIssuedAt(new Date(System.currentTimeMillis() + TimeUnit.DAYS.toDays(10)))
            .setClaims(claims)
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS512, key)
            .compact();
    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/kid/delete").param("token", token).content(""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  @DisplayName("Jerry's pre-signed token should not solve the assignment")
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
  @DisplayName("A simple unsigned/tampered token should be rejected as invalid")
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

  @Test
  @DisplayName("Empty token should return an invalid token error")
  public void emptyTokenShouldReturnInvalidTokenError() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/kid/delete").param("token", "").content(""))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("jwt-invalid-token"))));
  }
}

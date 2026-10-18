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
   * Verifies that a SQL injection payload in the JWT 'kid' header no longer bypasses
   * authentication after the fix to use a parameterized PreparedStatement.
   *
   * Before the fix, a crafted kid such as:
   *   hacked' UNION select 'deletingTom' from INFORMATION_SCHEMA.SYSTEM_USERS --
   * would inject a UNION clause into the query, allowing an attacker to supply any
   * arbitrary key value.  With the parameterized query the entire string is treated
   * as a literal lookup value; no row is found, the JWT signature cannot be verified,
   * and the request is rejected.
   */
  @Test
  public void sqlInjectionInKidHeaderShouldBeRejected() throws Exception {
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

    // The parameterized query treats the injection payload as a plain string; no matching
    // key is found in jwt_keys, so JWT signature verification fails and the request must
    // be rejected (lessonCompleted must be false).
    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/kid/delete").param("token", token).content(""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Verifies that a token with a kid containing only SQL metacharacters (single-quote,
   * double-dash comment sequence) does not cause a SQL error or succeed with
   * authentication.  With a PreparedStatement the payload is harmless.
   */
  @Test
  public void kidWithSqlMetacharactersShouldNotCauseSqlError() throws Exception {
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

    // The server should not return a 500 / SQL error; it should return 200 with a
    // jwt-invalid-token feedback message (key not found → signature verification fails).
    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/kid/delete").param("token", token).content(""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * A UNION-based injection attempting to retrieve data from another table must
   * also be blocked after the fix.
   */
  @Test
  public void unionBasedInjectionInKidShouldNotSucceed() throws Exception {
    String unionPayload = "x' UNION SELECT password FROM users WHERE '1'='1";
    Map<String, Object> claims = new HashMap<>();
    claims.put("username", "Tom");
    String token =
        Jwts.builder()
            .setHeaderParam("kid", unionPayload)
            .setIssuedAt(new Date(System.currentTimeMillis() + TimeUnit.DAYS.toDays(10)))
            .setClaims(claims)
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS512, "anykey")
            .compact();

    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/kid/delete").param("token", token).content(""))
        .andExpect(status().isOk())
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

  @Test
  public void emptyTokenShouldReturnInvalidTokenFeedback() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/kid/delete").param("token", "").content(""))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("jwt-invalid-token"))));
  }
}

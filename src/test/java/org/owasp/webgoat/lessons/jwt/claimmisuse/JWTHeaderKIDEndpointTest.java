/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt.claimmisuse;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.TextCodec;
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
   * Verifies the assignment can be solved legitimately: the token uses kid=webgoat_key, and is
   * signed with the key looked up from the database via a parameterized query. The SQL injection
   * path is no longer available after the fix.
   */
  @Test
  public void solveAssignmentWithLegitimateKey() throws Exception {
    // The database stores key='qwertyqwerty1234' for id='webgoat_key'.
    // The endpoint does TextCodec.BASE64.decode(rs.getString(1)) to obtain the signing bytes.
    byte[] signingKey = TextCodec.BASE64.decode("qwertyqwerty1234");

    Map<String, Object> claims = new HashMap<>();
    claims.put("username", "Tom");
    String token =
        Jwts.builder()
            .setHeaderParam("kid", "webgoat_key")
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(10)))
            .setClaims(claims)
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS512, signingKey)
            .compact();

    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/kid/delete").param("token", token).content(""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)));
  }

  /**
   * Verifies that a SQL injection payload in the kid header no longer works. Before the fix,
   * a UNION-based injection could return an arbitrary signing key. After the fix with a
   * parameterized prepared statement, the injection payload is treated as a literal string
   * and no matching row is found, causing JWT verification to fail.
   */
  @Test
  public void sqlInjectionInKidHeaderShouldNotSucceed() throws Exception {
    // This is the classic kid SQL injection payload: a UNION SELECT that would return an
    // attacker-controlled key. After the parameterized-query fix the literal string
    // "hacked' UNION ..." is used as the key id and finds no row → JWT verification fails.
    String injectedKid = "hacked' UNION select 'deletingTom' from INFORMATION_SCHEMA.SYSTEM_USERS --";
    String attackerKey = "deletingTom";

    Map<String, Object> claims = new HashMap<>();
    claims.put("username", "Tom");
    String token =
        Jwts.builder()
            .setHeaderParam("kid", injectedKid)
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(10)))
            .setClaims(claims)
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS512, attackerKey)
            .compact();

    // The injection no longer influences the query; the endpoint should return a failure
    // because no key is returned from the database (null signing key) or the JWT is invalid.
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
  public void emptyTokenShouldFail() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/kid/delete").param("token", "").content(""))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("jwt-invalid-token"))));
  }
}

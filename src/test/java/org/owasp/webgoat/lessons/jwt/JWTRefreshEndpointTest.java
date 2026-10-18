/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import static org.hamcrest.Matchers.is;
import static org.owasp.webgoat.lessons.jwt.JWTRefreshEndpoint.PASSWORD;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import java.util.HashMap;
import java.util.Map;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.WithWebGoatUser;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@WithWebGoatUser
public class JWTRefreshEndpointTest extends LessonTest {

  @BeforeEach
  void setup() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();
  }

  @Test
  void solveAssignment() throws Exception {
    ObjectMapper objectMapper = new ObjectMapper();

    // First login to obtain tokens for Jerry
    var loginJson = Map.of("user", "Jerry", "password", PASSWORD);
    MvcResult result =
        mockMvc
            .perform(
                MockMvcRequestBuilders.post("/JWT/refresh/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(loginJson)))
            .andExpect(status().isOk())
            .andReturn();
    Map<String, String> tokens =
        objectMapper.readValue(result.getResponse().getContentAsString(), Map.class);
    String refreshToken = tokens.get("refresh_token");

    // Now create a new refresh token for Tom based on Toms old access token and send the refresh
    // token of Jerry
    String accessTokenTom =
        "eyJhbGciOiJIUzUxMiJ9.eyJpYXQiOjE1MjYxMzE0MTEsImV4cCI6MTUyNjIxNzgxMSwiYWRtaW4iOiJmYWxzZSIsInVzZXIiOiJUb20ifQ.DCoaq9zQkyDH25EcVWKcdbyVfUL4c9D4jRvsqOqvi9iAd4QuqmKcchfbU8FNzeBNF9tLeFXHZLU4yRkq-bjm7Q";
    Map<String, Object> refreshJson = new HashMap<>();
    refreshJson.put("refresh_token", refreshToken);
    result =
        mockMvc
            .perform(
                MockMvcRequestBuilders.post("/JWT/refresh/newToken")
                    .contentType(MediaType.APPLICATION_JSON)
                    .header("Authorization", "Bearer " + accessTokenTom)
                    .content(objectMapper.writeValueAsString(refreshJson)))
            .andExpect(status().isOk())
            .andReturn();
    tokens = objectMapper.readValue(result.getResponse().getContentAsString(), Map.class);
    accessTokenTom = tokens.get("access_token");

    // Now checkout with the new token from Tom
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/checkout")
                .header("Authorization", "Bearer " + accessTokenTom))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)));
  }

  @Test
  void algNoneTokenShouldBeRejected() throws Exception {
    // After fixing JWT_No_Signature_Verification (CWE-347), tokens with alg=none must be
    // rejected by parseClaimsJws(). The old parse() accepted unsigned tokens; the fix does not.
    String tokenWithNoneAlgorithm =
        Jwts.builder()
            .setHeaderParam("alg", "none")
            .addClaims(Map.of("admin", "true", "user", "Tom"))
            .compact();

    // Unsigned (alg=none) token must now be rejected as invalid
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/checkout")
                .header("Authorization", "Bearer " + tokenWithNoneAlgorithm))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("jwt-invalid-token"))));
  }

  @Test
  void checkoutWithTomsTokenFromAccessLogShouldFail() throws Exception {
    String accessTokenTom =
        "eyJhbGciOiJIUzUxMiJ9.eyJpYXQiOjE1MjYxMzE0MTEsImV4cCI6MTUyNjIxNzgxMSwiYWRtaW4iOiJmYWxzZSIsInVzZXIiOiJUb20ifQ.DCoaq9zQkyDH25EcVWKcdbyVfUL4c9D4jRvsqOqvi9iAd4QuqmKcchfbU8FNzeBNF9tLeFXHZLU4yRkq-bjm7Q";
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/checkout")
                .header("Authorization", "Bearer " + accessTokenTom))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.output", CoreMatchers.containsString("JWT expired at")));
  }

  @Test
  void checkoutWitRandomTokenShouldFail() throws Exception {
    String accessTokenTom =
        "eyJhbGciOiJIUzUxMiJ9.eyJpLXQiOjE1MjYxMzE0MTEsImV4cCI6MTUyNjIxNzgxMSwiYWRtaW4iOiJmYWxzZSIsInVzZXIiOiJUb20ifQ.DCoaq9zQkyDH25EcVWKcdbyVfUL4c9D4jRvsqOqvi9iAd4QuqmKcchfbU8FNzeBNF9tLeFXHZLU4yRkq-bjm7Q";
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/checkout")
                .header("Authorization", "Bearer " + accessTokenTom))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("jwt-invalid-token"))));
  }

  @Test
  void flowForJerryAlwaysWorks() throws Exception {
    ObjectMapper objectMapper = new ObjectMapper();

    var loginJson = Map.of("user", "Jerry", "password", PASSWORD);
    MvcResult result =
        mockMvc
            .perform(
                MockMvcRequestBuilders.post("/JWT/refresh/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(loginJson)))
            .andExpect(status().isOk())
            .andReturn();
    Map<String, String> tokens =
        objectMapper.readValue(result.getResponse().getContentAsString(), Map.class);
    String accessToken = tokens.get("access_token");

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/checkout")
                .header("Authorization", "Bearer " + accessToken))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.feedback", is("User is not Tom but Jerry, please try again")));
  }

  @Test
  void loginShouldNotWorkForJerryWithWrongPassword() throws Exception {
    ObjectMapper objectMapper = new ObjectMapper();

    var loginJson = Map.of("user", "Jerry", "password", PASSWORD + "wrong");
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginJson)))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void loginShouldNotWorkForTom() throws Exception {
    ObjectMapper objectMapper = new ObjectMapper();

    var loginJson = Map.of("user", "Tom", "password", PASSWORD);
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginJson)))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void newTokenShouldWorkForJerry() throws Exception {
    ObjectMapper objectMapper = new ObjectMapper();
    Map<String, Object> loginJson = new HashMap<>();
    loginJson.put("user", "Jerry");
    loginJson.put("password", PASSWORD);
    MvcResult result =
        mockMvc
            .perform(
                MockMvcRequestBuilders.post("/JWT/refresh/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(loginJson)))
            .andExpect(status().isOk())
            .andReturn();
    Map<String, String> tokens =
        objectMapper.readValue(result.getResponse().getContentAsString(), Map.class);
    String accessToken = tokens.get("access_token");
    String refreshToken = tokens.get("refresh_token");

    var refreshJson = Map.of("refresh_token", refreshToken);
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/newToken")
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + accessToken)
                .content(objectMapper.writeValueAsString(refreshJson)))
        .andExpect(status().isOk());
  }

  @Test
  void unknownRefreshTokenShouldGiveUnauthorized() throws Exception {
    ObjectMapper objectMapper = new ObjectMapper();
    Map<String, Object> loginJson = new HashMap<>();
    loginJson.put("user", "Jerry");
    loginJson.put("password", PASSWORD);
    MvcResult result =
        mockMvc
            .perform(
                MockMvcRequestBuilders.post("/JWT/refresh/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(loginJson)))
            .andExpect(status().isOk())
            .andReturn();
    Map<String, String> tokens =
        objectMapper.readValue(result.getResponse().getContentAsString(), Map.class);
    String accessToken = tokens.get("access_token");

    var refreshJson = Map.of("refresh_token", "wrong_refresh_token");
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/newToken")
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + accessToken)
                .content(objectMapper.writeValueAsString(refreshJson)))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void noTokenWhileCheckoutShouldReturn401() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/refresh/checkout"))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void noTokenWhileRequestingNewTokenShouldReturn401() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/refresh/newToken"))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void noTokenWhileLoginShouldReturn401() throws Exception {
    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/refresh/login"))
        .andExpect(status().isUnauthorized());
  }

  /**
   * Regression test for CWE-347 / JWT_No_Signature_Verification.
   *
   * <p>A token whose signature is forged (signed with the wrong key) must be rejected. Prior to
   * the fix, {@code Jwts.parser().parse()} would accept unsigned tokens; the corrected code uses
   * {@code parseClaimsJws()} which enforces signature validation.
   */
  @Test
  void tokenSignedWithWrongKeyShouldBeRejectedAtCheckout() throws Exception {
    // Build a "Tom" token signed with a different, unknown key — simulates a forged token
    String forgedToken =
        Jwts.builder()
            .addClaims(Map.of("admin", "true", "user", "Tom"))
            .signWith(
                io.jsonwebtoken.SignatureAlgorithm.HS512,
                "completely-wrong-secret-key-that-is-not-the-jwt-password")
            .compact();

    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/checkout")
                .header("Authorization", "Bearer " + forgedToken))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)))
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("jwt-invalid-token"))));
  }

  /** A validly-signed token for a non-Tom user must not grant access. */
  @Test
  void validlySignedTokenForWrongUserShouldNotSucceed() throws Exception {
    // Jerry logs in and gets a valid, properly-signed access token
    ObjectMapper objectMapper = new ObjectMapper();
    var loginJson = Map.of("user", "Jerry", "password", PASSWORD);
    MvcResult result =
        mockMvc
            .perform(
                MockMvcRequestBuilders.post("/JWT/refresh/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(loginJson)))
            .andExpect(status().isOk())
            .andReturn();
    Map<String, String> tokens =
        objectMapper.readValue(result.getResponse().getContentAsString(), Map.class);
    String jerryAccessToken = tokens.get("access_token");

    // Jerry's validly-signed token should be rejected at checkout (user is not Tom)
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/checkout")
                .header("Authorization", "Bearer " + jerryAccessToken))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }
}

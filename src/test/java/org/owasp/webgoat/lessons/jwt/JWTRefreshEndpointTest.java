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
  void solutionWithAlgNone() throws Exception {
    String tokenWithNoneAlgorithm =
        Jwts.builder()
            .setHeaderParam("alg", "none")
            .addClaims(Map.of("admin", "true", "user", "Tom"))
            .compact();

    // Now checkout with the new token from Tom
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/checkout")
                .header("Authorization", "Bearer " + tokenWithNoneAlgorithm))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)))
        .andExpect(
            jsonPath("$.feedback", CoreMatchers.is(messages.getMessage("jwt-refresh-alg-none"))));
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
   * Security regression test for CWE-201 / JWT_Sensitive_Information_Exposure.
   *
   * <p>An attacker may craft a JWT whose "user" claim contains an arbitrary value (not a known
   * user) and supply a valid refresh token obtained from a legitimate login. Before the fix, the
   * raw JWT body value would be embedded verbatim in a new token's claims. After the fix, the
   * user is validated against the KNOWN_USERS allowlist and the request must be rejected with
   * 401 Unauthorized when the user value is not in that list.
   */
  @Test
  void newTokenRequestWithUnknownUserInJwtShouldBeRejected() throws Exception {
    ObjectMapper objectMapper = new ObjectMapper();

    // Obtain a valid refresh token by logging in as Jerry
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

    // Craft a JWT whose "user" claim is an arbitrary unknown value (not in the allowlist).
    // This simulates an attacker injecting unexpected data into the token claim.
    // The token is unsigned / alg=none so parsing will likely throw JwtException, but even if
    // an attacker somehow supplies a token with an unknown user that passes parsing, the
    // allowlist check must reject it.
    String forgedToken =
        Jwts.builder()
            .setHeaderParam("alg", "none")
            .addClaims(Map.of("admin", "true", "user", "UnknownAttacker"))
            .compact();

    Map<String, Object> refreshJson = new HashMap<>();
    refreshJson.put("refresh_token", refreshToken);

    // The request must be rejected — either 401 (allowlist blocks unknown user) or 200 with a
    // failure result (e.g., invalid token).  A 200 success with lessonCompleted=true would
    // indicate the attack succeeded, which must never happen.
    MvcResult newTokenResult =
        mockMvc
            .perform(
                MockMvcRequestBuilders.post("/JWT/refresh/newToken")
                    .contentType(MediaType.APPLICATION_JSON)
                    .header("Authorization", "Bearer " + forgedToken)
                    .content(objectMapper.writeValueAsString(refreshJson)))
            .andReturn();

    int status = newTokenResult.getResponse().getStatus();
    // Either rejected outright (401) or returned a failure AttackResult (200 without success)
    if (status == 200) {
      // If 200, the lesson must NOT be marked as completed for the attacker
      String body = newTokenResult.getResponse().getContentAsString();
      org.junit.jupiter.api.Assertions.assertFalse(
          body.contains("\"lessonCompleted\":true"),
          "New token endpoint must not grant a successful token to an unknown user");
    } else {
      org.junit.jupiter.api.Assertions.assertEquals(
          401, status, "New token endpoint should return 401 for unknown users");
    }
  }

  /**
   * Verifies that a JWT whose "user" claim is in the allowlist (Tom) still receives a new token
   * when a valid refresh token is provided, ensuring the fix does not break the intended lesson
   * flow.
   */
  @Test
  void newTokenRequestForKnownUserTomWithValidRefreshTokenSucceeds() throws Exception {
    ObjectMapper objectMapper = new ObjectMapper();

    // Login as Jerry to obtain a valid refresh token
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

    // Use Tom's known (expired) access token — the lesson specifically allows an expired token
    // to be refreshed; only the refresh token validity is checked for the token exchange.
    String accessTokenTom =
        "eyJhbGciOiJIUzUxMiJ9.eyJpYXQiOjE1MjYxMzE0MTEsImV4cCI6MTUyNjIxNzgxMSwiYWRtaW4iOiJmYWxzZSIsInVzZXIiOiJUb20ifQ.DCoaq9zQkyDH25EcVWKcdbyVfUL4c9D4jRvsqOqvi9iAd4QuqmKcchfbU8FNzeBNF9tLeFXHZLU4yRkq-bjm7Q";

    Map<String, Object> refreshJson = new HashMap<>();
    refreshJson.put("refresh_token", refreshToken);

    // "Tom" is a known user — the allowlist check must pass and a new token pair is returned
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/JWT/refresh/newToken")
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + accessTokenTom)
                .content(objectMapper.writeValueAsString(refreshJson)))
        .andExpect(status().isOk());
  }
}

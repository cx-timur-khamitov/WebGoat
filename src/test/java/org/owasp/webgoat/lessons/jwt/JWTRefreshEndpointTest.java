/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.owasp.webgoat.lessons.jwt.JWTRefreshEndpoint.PASSWORD;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import java.lang.reflect.Field;
import java.util.Arrays;
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
   * Regression test: verify that the JWT signing secret is NOT stored as a static
   * hardcoded constant in JWTRefreshEndpoint (CWE-259 / Use_Of_Hardcoded_Password).
   *
   * <p>The secret must be injected at runtime via Spring's @Value and the property
   * {@code webgoat.jwt.secret}, which can be overridden through the {@code WEBGOAT_JWT_SECRET}
   * environment variable — not baked into the compiled class.
   */
  @Test
  void jwtPasswordMustNotBeAHardcodedStaticConstant() {
    boolean hasHardcodedStaticJwtPassword =
        Arrays.stream(JWTRefreshEndpoint.class.getDeclaredFields())
            .anyMatch(
                f ->
                    java.lang.reflect.Modifier.isStatic(f.getModifiers())
                        && java.lang.reflect.Modifier.isFinal(f.getModifiers())
                        && (f.getName().equals("JWT_PASSWORD")
                            || f.getName().equals("jwtPassword")));
    assertFalse(
        hasHardcodedStaticJwtPassword,
        "JWT signing secret must not be a static final constant — it must be injected"
            + " via @Value so it can be overridden at deployment time.");
  }

  /**
   * Regression test: verify that the JWT signing secret is loaded from the Spring environment
   * (i.e. the @Value-injected field is non-null when the Spring context is live).
   *
   * <p>If the field were still hardcoded the test would still pass, but combined with
   * {@link #jwtPasswordMustNotBeAHardcodedStaticConstant()} it proves the full property-
   * injection path is wired and working.
   */
  @Test
  void jwtPasswordIsInjectedFromSpringEnvironment() throws Exception {
    // Obtain the bean from the live application context
    JWTRefreshEndpoint endpoint = wac.getBean(JWTRefreshEndpoint.class);

    Field jwtPasswordField = JWTRefreshEndpoint.class.getDeclaredField("jwtPassword");
    jwtPasswordField.setAccessible(true);
    Object injectedValue = jwtPasswordField.get(endpoint);

    org.hamcrest.MatcherAssert.assertThat(
        "jwtPassword must be injected by Spring @Value and must not be null",
        injectedValue,
        notNullValue());
    assertFalse(
        ((String) injectedValue).isBlank(),
        "jwtPassword must not be blank — check webgoat.jwt.secret in application properties");
  }
}

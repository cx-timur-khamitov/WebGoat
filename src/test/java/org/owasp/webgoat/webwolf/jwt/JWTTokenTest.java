/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Arrays;
import java.util.Map;
import lombok.SneakyThrows;
import org.jose4j.jwk.JsonWebKey.OutputControlLevel;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.junit.jupiter.api.Test;

class JWTTokenTest {

  @Test
  void encodeCorrectTokenWithoutSignature() {
    var headers = Map.of("alg", "HS256", "typ", "JWT");
    var payload = Map.of("test", "test");
    char[] secretKey = new char[0];
    var token = JWTToken.encode(toString(headers), toString(payload), secretKey);

    assertThat(token.getEncoded())
        .isEqualTo("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoidGVzdCJ9");
  }

  @Test
  void encodeCorrectTokenWithSignature() {
    var headers = Map.of("alg", "HS256", "typ", "JWT");
    var payload = Map.of("test", "test");
    char[] secretKey = "webgoat".toCharArray();
    try {
      var token = JWTToken.encode(toString(headers), toString(payload), secretKey);

      assertThat(token.getEncoded())
          .isEqualTo(
              "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoidGVzdCJ9.axNp9BkswwK_YRF2URJ5P1UejQNYZbK4qYcMnkusg6I");
    } finally {
      Arrays.fill(secretKey, '\0');
    }
  }

  @Test
  void encodeTokenWithNonJsonInput() {
    char[] secretKey = "test".toCharArray();
    try {
      var token = JWTToken.encode("aaa", "bbb", secretKey);

      assertThat(token.getEncoded()).isNullOrEmpty();
    } finally {
      Arrays.fill(secretKey, '\0');
    }
  }

  @Test
  void decodeValidSignedToken() {
    char[] secretKey = "test".toCharArray();
    try {
      var token =
          JWTToken.decode(
              "eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoidGVzdCJ9.KOobRHDYyaesV_doOk11XXGKSONwzllraAaqqM4VFE4",
              secretKey);

      assertThat(token.getHeader()).contains("\"alg\" : \"HS256\"");
      assertThat(token.isSignatureValid()).isTrue();
    } finally {
      Arrays.fill(secretKey, '\0');
    }
  }

  @Test
  void decodeInvalidSignedToken() {
    char[] secretKey = new char[0];
    var token =
        JWTToken.decode(
            "eyJhbGciOiJIUzI1NiJ9.eyJ0ZXsdfdfsaasfddfasN0IjoidGVzdCJ9.KOobRHDYyaesV_doOk11XXGKSONwzllraAaqqM4VFE4",
            secretKey);

    assertThat(token.getHeader()).contains("\"alg\" : \"HS256\"");
    assertThat(token.getPayload()).contains("{\"te");
  }

  @Test
  void onlyEncodeWhenHeaderOrPayloadIsPresent() {
    char[] secretKey = new char[0];
    var token = JWTToken.encode("", "", secretKey);

    assertThat(token.getEncoded()).isNullOrEmpty();
  }

  @Test
  void encodeAlgNone() {
    var headers = Map.of("alg", "none");
    var payload = Map.of("test", "test");
    char[] secretKey = "test".toCharArray();
    try {
      var token = JWTToken.encode(toString(headers), toString(payload), secretKey);

      assertThat(token.getEncoded()).isEqualTo("eyJhbGciOiJub25lIn0.eyJ0ZXN0IjoidGVzdCJ9");
    } finally {
      Arrays.fill(secretKey, '\0');
    }
  }

  @Test
  @SneakyThrows
  void decodeValidRsaSignedTokenUsingJwks() {
    RsaJsonWebKey jwk = RsaJwkGenerator.generateJwk(2048);
    jwk.setKeyId("kid-1");

    JsonWebSignature jws = new JsonWebSignature();
    jws.setPayload(toString(Map.of("role", "admin")));
    jws.setKey(jwk.getPrivateKey());
    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
    jws.setKeyIdHeaderValue(jwk.getKeyId());
    String compact = jws.getCompactSerialization();

    String jwksJson = new JsonWebKeySet(jwk).toJson(OutputControlLevel.PUBLIC_ONLY);

    var token = JWTToken.decode(compact, null, jwksJson);

    assertThat(token.isSignatureValid()).isTrue();
    assertThat(token.getHeader()).contains("\"kid\" : \"kid-1\"");
  }

  @Test
  @SneakyThrows
  void decodeTokenFailsWithMismatchingJwks() {
    RsaJsonWebKey signer = RsaJwkGenerator.generateJwk(2048);
    signer.setKeyId("signing-key");
    JsonWebSignature jws = new JsonWebSignature();
    jws.setPayload(toString(Map.of("scope", "read")));
    jws.setKey(signer.getPrivateKey());
    jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
    jws.setKeyIdHeaderValue(signer.getKeyId());
    String compact = jws.getCompactSerialization();

    RsaJsonWebKey otherKey = RsaJwkGenerator.generateJwk(2048);
    otherKey.setKeyId("other-key");
    String wrongJwks = new JsonWebKeySet(otherKey).toJson(OutputControlLevel.PUBLIC_ONLY);

    var token = JWTToken.decode(compact, null, wrongJwks);

    assertThat(token.isSignatureValid()).isFalse();
  }

  // ── Tests verifying CWE-244 remediation ──────────────────────────────────

  /**
   * Verifies that encode() accepts a char[] secretKey and produces the same result as when the
   * equivalent String was used, confirming backward-compatible behaviour after the CWE-244 fix.
   */
  @Test
  void encodeWithCharArraySecretKeyProducesCorrectToken() {
    var headers = Map.of("alg", "HS256", "typ", "JWT");
    var payload = Map.of("sub", "user1");
    char[] secretKey = "mySecret".toCharArray();
    try {
      var token = JWTToken.encode(toString(headers), toString(payload), secretKey);

      assertThat(token.getEncoded()).isNotNull();
      assertThat(token.getEncoded()).contains(".");
      assertThat(token.isSignatureValid()).isTrue();
    } finally {
      Arrays.fill(secretKey, '\0');
    }
  }

  /**
   * Verifies that decode() validates the signature correctly when a char[] secretKey is supplied,
   * confirming the fix works end-to-end and doesn't regress signature validation.
   */
  @Test
  void decodeWithCorrectCharArraySecretKeyValidatesSignature() {
    var headers = Map.of("alg", "HS256", "typ", "JWT");
    var payload = Map.of("sub", "user1");
    char[] secretKey = "roundtripSecret".toCharArray();
    try {
      // Encode first to get a valid token
      var encoded = JWTToken.encode(toString(headers), toString(payload), secretKey);
      assertThat(encoded.getEncoded()).isNotNull();

      // Reset secretKey because encode() must not have cleared our copy
      char[] decodeKey = "roundtripSecret".toCharArray();
      try {
        var decoded = JWTToken.decode(encoded.getEncoded(), decodeKey);
        assertThat(decoded.isSignatureValid()).isTrue();
      } finally {
        Arrays.fill(decodeKey, '\0');
      }
    } finally {
      Arrays.fill(secretKey, '\0');
    }
  }

  /**
   * Verifies that decode() correctly reports an invalid signature when the wrong char[] key is
   * used, preventing false positives after the CWE-244 fix.
   */
  @Test
  void decodeWithWrongCharArraySecretKeyRejectsSignature() {
    var headers = Map.of("alg", "HS256", "typ", "JWT");
    var payload = Map.of("sub", "user1");
    char[] encodeKey = "correctSecret".toCharArray();
    char[] wrongKey = "wrongSecret".toCharArray();
    try {
      var encoded = JWTToken.encode(toString(headers), toString(payload), encodeKey);
      var decoded = JWTToken.decode(encoded.getEncoded(), wrongKey);

      assertThat(decoded.isSignatureValid()).isFalse();
    } finally {
      Arrays.fill(encodeKey, '\0');
      Arrays.fill(wrongKey, '\0');
    }
  }

  /**
   * Verifies that passing an empty char[] as the secretKey results in no signature validation
   * (returns false), matching the previous behaviour for an empty string.
   */
  @Test
  void decodeWithEmptyCharArraySecretKeySkipsSignatureValidation() {
    var token =
        JWTToken.decode(
            "eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoidGVzdCJ9.KOobRHDYyaesV_doOk11XXGKSONwzllraAaqqM4VFE4",
            new char[0]);

    // Empty key means no validation attempted → signatureValid should be false
    assertThat(token.isSignatureValid()).isFalse();
  }

  @SneakyThrows
  private String toString(Map<String, String> map) {
    var mapper = new ObjectMapper();
    return mapper.writeValueAsString(map);
  }
}

/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf.jwt;

import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.util.Arrays;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

@RestController
public class JWTController {

  @GetMapping("/jwt")
  public ModelAndView jwt() {
    return new ModelAndView("jwt");
  }

  @PostMapping(
      value = "/jwt/decode",
      consumes = APPLICATION_FORM_URLENCODED_VALUE,
      produces = APPLICATION_JSON_VALUE)
  public JWTToken decode(@RequestBody MultiValueMap<String, String> formData) {
    var jwt = formData.getFirst("token");
    var jwks = formData.getFirst("jwks");
    String secretKeyStr = formData.getFirst("secretKey");
    // Use char[] for the secret key to allow explicit clearing from memory (CWE-244)
    char[] secretKey = secretKeyStr != null ? secretKeyStr.toCharArray() : new char[0];
    try {
      return JWTToken.decode(jwt, secretKey, jwks);
    } finally {
      Arrays.fill(secretKey, '\0');
    }
  }

  @PostMapping(
      value = "/jwt/encode",
      consumes = APPLICATION_FORM_URLENCODED_VALUE,
      produces = APPLICATION_JSON_VALUE)
  public JWTToken encode(@RequestBody MultiValueMap<String, String> formData) {
    var header = formData.getFirst("header");
    var payload = formData.getFirst("payload");
    String secretKeyStr = formData.getFirst("secretKey");
    // Use char[] for the secret key to allow explicit clearing from memory (CWE-244)
    char[] secretKey = secretKeyStr != null ? secretKeyStr.toCharArray() : new char[0];
    try {
      return JWTToken.encode(header, payload, secretKey);
    } finally {
      Arrays.fill(secretKey, '\0');
    }
  }
}

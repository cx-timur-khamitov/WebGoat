/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.deserialization;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;
import org.dummy.insecure.framework.VulnerableTaskHolder;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

class DeserializeTest extends LessonTest {

  private static String OS = System.getProperty("os.name").toLowerCase();

  @Test
  void success() throws Exception {
    if (OS.indexOf("win") > -1) {
      mockMvc
          .perform(
              MockMvcRequestBuilders.post("/InsecureDeserialization/task")
                  .param(
                      "token",
                      SerializationHelper.toString(
                          new VulnerableTaskHolder("wait", "ping localhost -n 5"))))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.lessonCompleted", is(true)));
    } else {
      mockMvc
          .perform(
              MockMvcRequestBuilders.post("/InsecureDeserialization/task")
                  .param(
                      "token",
                      SerializationHelper.toString(new VulnerableTaskHolder("wait", "sleep 5"))))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.lessonCompleted", is(true)));
    }
  }

  @Test
  void fail() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/InsecureDeserialization/task")
                .param(
                    "token",
                    SerializationHelper.toString(new VulnerableTaskHolder("delete", "rm *"))))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  void wrongVersion() throws Exception {
    String token =
        "rO0ABXNyADFvcmcuZHVtbXkuaW5zZWN1cmUuZnJhbWV3b3JrLlZ1bG5lcmFibGVUYXNrSG9sZGVyAAAAAAAAAAECAANMABZyZXF1ZXN0ZWRFeGVjdXRpb25UaW1ldAAZTGphdmEvdGltZS9Mb2NhbERhdGVUaW1lO0wACnRhc2tBY3Rpb250ABJMamF2YS9sYW5nL1N0cmluZztMAAh0YXNrTmFtZXEAfgACeHBzcgANamF2YS50aW1lLlNlcpVdhLobIkiyDAAAeHB3DgUAAAfjCR4GIQgMLRSoeHQACmVjaG8gaGVsbG90AAhzYXlIZWxsbw";
    mockMvc
        .perform(MockMvcRequestBuilders.post("/InsecureDeserialization/task").param("token", token))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath(
                "$.feedback",
                CoreMatchers.is(messages.getMessage("insecure-deserialization.invalidversion"))))
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  void expiredTask() throws Exception {
    String token =
        "rO0ABXNyADFvcmcuZHVtbXkuaW5zZWN1cmUuZnJhbWV3b3JrLlZ1bG5lcmFibGVUYXNrSG9sZGVyAAAAAAAAAAICAANMABZyZXF1ZXN0ZWRFeGVjdXRpb25UaW1ldAAZTGphdmEvdGltZS9Mb2NhbERhdGVUaW1lO0wACnRhc2tBY3Rpb250ABJMamF2YS9sYW5nL1N0cmluZztMAAh0YXNrTmFtZXEAfgACeHBzcgANamF2YS50aW1lLlNlcpVdhLobIkiyDAAAeHB3DgUAAAfjCR4IDC0YfvNIeHQACmVjaG8gaGVsbG90AAhzYXlIZWxsbw";
    mockMvc
        .perform(MockMvcRequestBuilders.post("/InsecureDeserialization/task").param("token", token))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath(
                "$.feedback",
                CoreMatchers.is(messages.getMessage("insecure-deserialization.expired"))))
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  void checkOtherObject() throws Exception {
    String token =
        "rO0ABXQAVklmIHlvdSBkZXNlcmlhbGl6ZSBtZSBkb3duLCBJIHNoYWxsIGJlY29tZSBtb3JlIHBvd2VyZnVsIHRoYW4geW91IGNhbiBwb3NzaWJseSBpbWFnaW5l";
    mockMvc
        .perform(MockMvcRequestBuilders.post("/InsecureDeserialization/task").param("token", token))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath(
                "$.feedback",
                CoreMatchers.is(messages.getMessage("insecure-deserialization.stringobject"))))
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Security regression test: verifies that the ObjectInputFilter allowlist rejects serialized
   * objects whose class is NOT in the permitted list (CWE-502 fix).
   *
   * <p>A gadget-chain payload would typically embed a disallowed class. Here we use
   * java.util.HashMap as a stand-in for an arbitrary/gadget class that must be rejected.
   * The allowlist filter should cause readObject() to throw an exception, and the endpoint
   * must return a failure response rather than deserializing the object.
   */
  @Test
  void disallowedClassIsRejectedByFilter() throws Exception {
    // Serialize a java.util.HashMap — a class that is NOT in the allowlist.
    // This simulates a gadget-chain payload using a class outside the permitted set.
    java.util.HashMap<String, String> disallowedObject = new java.util.HashMap<>();
    disallowedObject.put("attack", "payload");
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
      oos.writeObject(disallowedObject);
    }
    String token = Base64.getEncoder().encodeToString(baos.toByteArray());

    // The filter must reject this class — the endpoint must NOT succeed.
    mockMvc
        .perform(MockMvcRequestBuilders.post("/InsecureDeserialization/task").param("token", token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  /**
   * Security regression test: verifies that a completely invalid (non-serialized) payload
   * does not cause an unhandled error and is rejected gracefully.
   */
  @Test
  void invalidSerializedPayloadIsRejected() throws Exception {
    // Raw bytes that are not a valid Java serialized stream (missing magic bytes 0xACED).
    String token = Base64.getEncoder().encodeToString("not-a-serialized-object".getBytes());

    mockMvc
        .perform(MockMvcRequestBuilders.post("/InsecureDeserialization/task").param("token", token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }
}

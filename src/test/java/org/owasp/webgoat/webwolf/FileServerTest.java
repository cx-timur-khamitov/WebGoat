/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.apache.commons.io.FileUtils;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.servlet.view.InternalResourceViewResolver;

class FileServerTest {

  private static final String USERNAME = "tweety";
  private static final Authentication AUTHENTICATION =
      new UsernamePasswordAuthenticationToken(USERNAME, "n/a");

  @TempDir private Path fileServerLocation;

  private MockMvc mockMvc;

  @BeforeEach
  void setupFileServer() throws IOException {
    var fileServer = new FileServer();
    ReflectionTestUtils.setField(fileServer, "fileLocation", fileServerLocation.toString());
    ReflectionTestUtils.setField(fileServer, "server", "127.0.0.1");
    ReflectionTestUtils.setField(fileServer, "contextPath", "/WebWolf");
    ReflectionTestUtils.setField(fileServer, "port", 9090);

    // the view names ('files') are resolved by Thymeleaf at runtime, without a prefix/suffix the
    // standalone setup would forward '/files' onto itself and fail with a circular view path
    mockMvc =
        MockMvcBuilders.standaloneSetup(fileServer)
            .setViewResolvers(new InternalResourceViewResolver("/webwolf/templates/", ".html"))
            .build();
  }

  @Test
  @DisplayName("The configured file server location is exposed as plain text")
  void shouldReturnFileServerLocation() throws Exception {
    mockMvc
        .perform(get("/file-server-location"))
        .andExpect(status().isOk())
        .andExpect(result -> Assertions.assertThat(result.getResponse().getContentAsString())
            .isEqualTo(fileServerLocation.toString()));
  }

  @Test
  void shouldIgnoreUploadWithoutContentAndStoreTheNextUpload() throws Exception {
    FileUtils.cleanDirectory(fileServerLocation.toFile());
    mockMvc
        .perform(multipart("/fileupload").file(emptyUpload()).principal(AUTHENTICATION))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("files?uploadSuccess=Nothing+to+upload"));

    Assertions.assertThat(uploadedFiles()).isEmpty();

    mockMvc
        .perform(multipart("/fileupload").file(testFile()).principal(AUTHENTICATION))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("files?uploadSuccess=File+uploaded+successful"));

    Assertions.assertThat(userDirectory().resolve("test.txt")).content().isEqualTo("test");
  }

  @Test
  @DisplayName("An uploaded file is listed on the files page")
  void shouldListUploadedFile() throws Exception {
    mockMvc.perform(multipart("/fileupload").file(testFile()).principal(AUTHENTICATION));

    mockMvc
        .perform(get("/files").principal(AUTHENTICATION))
        .andExpect(status().isOk())
        .andExpect(view().name("files"))
        .andExpect(model().attribute("webwolf_url", "http://127.0.0.1:9090/WebWolf"))
        .andExpect(
            result -> {
              var files = (List<?>) result.getModelAndView().getModel().get("files");
              Assertions.assertThat(files).hasSize(1);
              Assertions.assertThat(files.get(0).toString())
                  .contains("test.txt")
                  .contains("files/%s/test.txt".formatted(USERNAME));
            });
  }

  @Test
  @DisplayName("The message of the upload we are redirected from is passed on to the files page")
  void shouldShowUploadMessageFromRedirect() throws Exception {
    mockMvc
        .perform(
            get("/files")
                .param("uploadSuccess", FileServer.UPLOAD_TOO_LARGE)
                .principal(AUTHENTICATION))
        .andExpect(status().isOk())
        .andExpect(model().attribute("uploadSuccess", FileServer.UPLOAD_TOO_LARGE))
        .andExpect(model().attribute("uploadFailed", true));

    mockMvc
        .perform(
            get("/files")
                .param("uploadSuccess", FileServer.UPLOAD_SUCCESSFUL)
                .principal(AUTHENTICATION))
        .andExpect(model().attribute("uploadFailed", false));

    // no message means no alert on the files page
    mockMvc
        .perform(get("/files").principal(AUTHENTICATION))
        .andExpect(model().attributeDoesNotExist("uploadSuccess", "uploadFailed"));
  }

  // ---- Path traversal security tests ----

  @Test
  @DisplayName("A username with path traversal sequences must NOT escape the file server root")
  void shouldRejectPathTraversalInUsername() throws Exception {
    // Simulate a principal whose getName() returns a traversal payload such as "../evil".
    // The fix resolves+normalises the path and rejects it when it escapes fileLocation.
    var maliciousAuth =
        new UsernamePasswordAuthenticationToken("../evil", "n/a");

    mockMvc
        .perform(multipart("/fileupload").file(testFile()).principal(maliciousAuth))
        .andExpect(status().is3xxRedirection())
        // Traversal is silently treated as "nothing to upload" — no file must be written
        .andExpect(redirectedUrl("files?uploadSuccess=Nothing+to+upload"));

    // Confirm that no file was written outside (or inside) the temp directory under the
    // traversal path.
    try (var walk = Files.walk(fileServerLocation)) {
      Assertions.assertThat(walk.filter(Files::isRegularFile).toList()).isEmpty();
    }
  }

  @Test
  @DisplayName("A deeply nested traversal username must also be rejected")
  void shouldRejectDeepPathTraversalInUsername() throws Exception {
    var maliciousAuth =
        new UsernamePasswordAuthenticationToken("../../../../../../etc/passwd", "n/a");

    mockMvc
        .perform(multipart("/fileupload").file(testFile()).principal(maliciousAuth))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("files?uploadSuccess=Nothing+to+upload"));

    try (var walk = Files.walk(fileServerLocation)) {
      Assertions.assertThat(walk.filter(Files::isRegularFile).toList()).isEmpty();
    }
  }

  @Test
  @DisplayName("A legitimate username still stores the uploaded file under its own sub-directory")
  void shouldStoreFileForLegitimateUsername() throws Exception {
    mockMvc
        .perform(multipart("/fileupload").file(testFile()).principal(AUTHENTICATION))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("files?uploadSuccess=File+uploaded+successful"));

    Path expected = fileServerLocation.resolve(USERNAME).resolve("test.txt");
    Assertions.assertThat(expected).exists().hasContent("test");

    // The file must not have been placed outside the user's own directory
    Assertions.assertThat(expected.toAbsolutePath().normalize())
        .startsWith(fileServerLocation.toAbsolutePath().normalize());
  }

  @Test
  @DisplayName("Username with encoded traversal sequences must not escape the file server root")
  void shouldRejectEncodedPathTraversalInUsername() throws Exception {
    // Some path traversal payloads use URL-decoded sequences.  The fix normalises the path
    // after OS-level resolution, so any disguised traversal is caught at that stage.
    var maliciousAuth =
        new UsernamePasswordAuthenticationToken("..%2Fevil", "n/a");

    // Path.resolve() treats the raw string; after normalize() any remaining ".." segments
    // that escape the base will be caught by the startsWith() guard.
    mockMvc
        .perform(multipart("/fileupload").file(testFile()).principal(maliciousAuth))
        .andExpect(status().is3xxRedirection());

    // Whatever the response, no file must have escaped fileServerLocation.
    try (var walk = Files.walk(fileServerLocation)) {
      walk.filter(Files::isRegularFile)
          .forEach(
              p ->
                  Assertions.assertThat(p.toAbsolutePath().normalize())
                      .startsWith(fileServerLocation.toAbsolutePath().normalize()));
    }
  }

  // ---- end of security tests ----

  private Path userDirectory() {
    return fileServerLocation.resolve(USERNAME);
  }

  private List<Path> uploadedFiles() throws Exception {
    try (var files = Files.walk(fileServerLocation)) {
      return files.filter(Files::isRegularFile).toList();
    }
  }

  private MockMultipartFile emptyUpload() {
    return new MockMultipartFile("file", "", "application/octet-stream", new byte[0]);
  }

  private MockMultipartFile testFile() {
    return new MockMultipartFile(
        "file", "test.txt", "text/plain", "test".getBytes(StandardCharsets.UTF_8));
  }
}

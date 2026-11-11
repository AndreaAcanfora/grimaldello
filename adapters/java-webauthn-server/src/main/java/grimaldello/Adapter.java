// grimaldello adapter for java-webauthn-server (Yubico).
// Reads cases (JSON lines) on stdin, writes one verdict per line on stdout.
package grimaldello;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;

public final class Adapter {
  private static final ObjectMapper JSON = new ObjectMapper();

  /** A credential repository holding at most the one credential of the case. */
  static final class Repo implements CredentialRepository {
    final ByteArray userHandle;
    RegisteredCredential credential;

    Repo(ByteArray userHandle) {
      this.userHandle = userHandle;
    }

    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
      if (credential == null) return Set.of();
      return Set.of(PublicKeyCredentialDescriptor.builder().id(credential.getCredentialId()).build());
    }

    public Optional<ByteArray> getUserHandleForUsername(String username) {
      return "grimaldello".equals(username) ? Optional.of(userHandle) : Optional.empty();
    }

    public Optional<String> getUsernameForUserHandle(ByteArray handle) {
      return userHandle.equals(handle) ? Optional.of("grimaldello") : Optional.empty();
    }

    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray handle) {
      if (credential == null) return Optional.empty();
      return credential.getCredentialId().equals(credentialId) && credential.getUserHandle().equals(handle)
          ? Optional.of(credential)
          : Optional.empty();
    }

    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
      return credential != null && credential.getCredentialId().equals(credentialId) ? Set.of(credential) : Set.of();
    }
  }

  static ByteArray b64(String s) throws Exception {
    return ByteArray.fromBase64Url(s);
  }

  static UserVerificationRequirement uv(boolean required) {
    return required ? UserVerificationRequirement.REQUIRED : UserVerificationRequirement.PREFERRED;
  }

  static void verify(JsonNode c) throws Exception {
    JsonNode rpNode = c.get("rp");
    RelyingPartyIdentity identity =
        RelyingPartyIdentity.builder().id(rpNode.get("id").asText()).name(rpNode.get("name").asText()).build();
    ByteArray userHandle = b64(c.get("userHandle").asText());
    Repo repo = new Repo(userHandle);
    RelyingParty rp =
        RelyingParty.builder()
            .identity(identity)
            .credentialRepository(repo)
            .origins(Set.of(rpNode.get("origin").asText()))
            .build();

    List<PublicKeyCredentialParameters> params = new ArrayList<>();
    for (JsonNode a : c.get("algorithms")) {
      Optional<COSEAlgorithmIdentifier> alg = COSEAlgorithmIdentifier.fromId(a.asLong());
      alg.ifPresent(x -> params.add(PublicKeyCredentialParameters.builder().alg(x).build()));
    }
    boolean requireUv = c.get("requireUserVerification").asBoolean();
    JsonNode reg = c.get("registration");
    PublicKeyCredentialCreationOptions creation =
        PublicKeyCredentialCreationOptions.builder()
            .rp(identity)
            .user(UserIdentity.builder().name("grimaldello").displayName("grimaldello").id(userHandle).build())
            .challenge(b64(reg.get("challenge").asText()))
            .pubKeyCredParams(params)
            .authenticatorSelection(AuthenticatorSelectionCriteria.builder().userVerification(uv(requireUv)).build())
            .build();
    RegistrationResult result;
    try {
      result =
          rp.finishRegistration(
              FinishRegistrationOptions.builder()
                  .request(creation)
                  .response(PublicKeyCredential.parseRegistrationResponseJson(JSON.writeValueAsString(reg.get("response"))))
                  .build());
    } catch (Exception e) {
      if ("registration".equals(c.get("ceremony").asText())) throw e;
      throw new Exception("setup: registration failed: " + e, e);
    }
    if ("registration".equals(c.get("ceremony").asText())) return;

    JsonNode auth = c.get("authentication");
    repo.credential =
        RegisteredCredential.builder()
            .credentialId(result.getKeyId().getId())
            .userHandle(userHandle)
            .publicKeyCose(result.getPublicKeyCose())
            .signatureCount(auth.get("storedSignCount").asLong())
            .build();
    AssertionRequest request =
        AssertionRequest.builder()
            .publicKeyCredentialRequestOptions(
                PublicKeyCredentialRequestOptions.builder()
                    .challenge(b64(auth.get("challenge").asText()))
                    .rpId(identity.getId())
                    .userVerification(uv(requireUv))
                    .build())
            .username("grimaldello")
            .build();
    AssertionResult r =
        rp.finishAssertion(
            FinishAssertionOptions.builder()
                .request(request)
                .response(PublicKeyCredential.parseAssertionResponseJson(JSON.writeValueAsString(auth.get("response"))))
                .build());
    if (!r.isSuccess()) throw new Exception("isSuccess: false");
  }

  public static void main(String[] args) throws Exception {
    if (args.length > 0 && args[0].equals("--info")) {
      Properties p = new Properties();
      p.load(Adapter.class.getResourceAsStream("/adapter.properties"));
      System.out.println(
          JSON.writeValueAsString(
              Map.of("library", "java-webauthn-server", "version", p.getProperty("version"), "language", "Java")));
      return;
    }
    BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
    String line;
    while ((line = in.readLine()) != null) {
      if (line.isBlank()) continue;
      JsonNode c = JSON.readTree(line);
      ObjectNode out = JSON.createObjectNode();
      out.put("id", c.get("id").asText());
      try {
        verify(c);
        out.put("verdict", "accept");
      } catch (Exception e) {
        out.put("verdict", "reject");
        out.put("error", String.valueOf(e));
        // The documented failures are RegistrationFailedException,
        // AssertionFailedException and IOException from the JSON parsers.
        Throwable root = e.getMessage() != null && e.getMessage().startsWith("setup:") ? e.getCause() : e;
        if (!(root instanceof com.yubico.webauthn.exception.RegistrationFailedException
            || root instanceof com.yubico.webauthn.exception.AssertionFailedException
            || root instanceof java.io.IOException
            || "isSuccess: false".equals(root.getMessage()))) {
          out.put("unexpected", true);
        }
      }
      System.out.println(JSON.writeValueAsString(out));
      System.out.flush();
    }
  }
}

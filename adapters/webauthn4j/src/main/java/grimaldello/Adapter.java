// grimaldello adapter for webauthn4j.
// Reads cases (JSON lines) on stdin, writes one verdict per line on stdout.
package grimaldello;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.anchor.TrustAnchorRepository;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.verifier.attestation.statement.androidkey.AndroidKeyAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.apple.AppleAnonymousAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.packed.PackedAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.tpm.TPMAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.u2f.FIDOU2FAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessVerifier;
import java.security.cert.TrustAnchor;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.exception.WebAuthnException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;

public final class Adapter {
  private static final ObjectMapper JSON = new ObjectMapper();
  // A manager that verifies attestation statements, as an application that
  // relies on attestation would configure it. (createNonStrictWebAuthnManager()
  // skips attestation verification on purpose, so it is not used here.)
  // Self attestation is allowed; no certificate is trusted yet.
  private static final WebAuthnManager MANAGER =
      new WebAuthnManager(
          List.of(
              new NoneAttestationStatementVerifier(),
              new PackedAttestationStatementVerifier(),
              new FIDOU2FAttestationStatementVerifier(),
              new AndroidKeyAttestationStatementVerifier(),
              new TPMAttestationStatementVerifier(),
              new AppleAnonymousAttestationStatementVerifier()),
          new DefaultCertPathTrustworthinessVerifier(new TrustAnchors()),
          new DefaultSelfAttestationTrustworthinessVerifier());

  static final class TrustAnchors implements TrustAnchorRepository {
    public Set<TrustAnchor> find(AAGUID aaguid) {
      return Set.of();
    }

    public Set<TrustAnchor> find(byte[] attestationCertificateKeyIdentifier) {
      return Set.of();
    }
  }

  static byte[] b64(String s) {
    return Base64.getUrlDecoder().decode(s);
  }

  static void verify(JsonNode c) throws Exception {
    JsonNode rp = c.get("rp");
    String rpId = rp.get("id").asText();
    Origin origin = new Origin(rp.get("origin").asText());
    boolean requireUv = c.get("requireUserVerification").asBoolean();
    boolean registration = "registration".equals(c.get("ceremony").asText());

    List<PublicKeyCredentialParameters> params = new ArrayList<>();
    for (JsonNode a : c.get("algorithms")) {
      params.add(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.create(a.asLong())));
    }
    JsonNode reg = c.get("registration");
    ServerProperty regProperty = new ServerProperty(origin, rpId, new DefaultChallenge(b64(reg.get("challenge").asText())));
    RegistrationData data;
    try {
      data = MANAGER.parseRegistrationResponseJSON(JSON.writeValueAsString(reg.get("response")));
      MANAGER.verify(data, new RegistrationParameters(regProperty, params, requireUv, true));
    } catch (Exception e) {
      if (registration) throw e;
      throw new Exception("setup: registration failed: " + e, e);
    }
    if (registration) return;

    JsonNode auth = c.get("authentication");
    CredentialRecordImpl record =
        new CredentialRecordImpl(
            data.getAttestationObject(),
            data.getCollectedClientData(),
            data.getClientExtensions(),
            data.getTransports());
    record.setCounter(auth.get("storedSignCount").asLong());
    AuthenticationData assertion = MANAGER.parseAuthenticationResponseJSON(JSON.writeValueAsString(auth.get("response")));
    // What an application does: look the credential up by the id in the response.
    if (!Arrays.equals(assertion.getCredentialId(), record.getAttestedCredentialData().getCredentialId())) {
      throw new Exception("unknown credential");
    }
    ServerProperty authProperty = new ServerProperty(origin, rpId, new DefaultChallenge(b64(auth.get("challenge").asText())));
    MANAGER.verify(assertion, new AuthenticationParameters(authProperty, record, null, requireUv, true));
  }

  public static void main(String[] args) throws Exception {
    if (args.length > 0 && args[0].equals("--info")) {
      Properties p = new Properties();
      p.load(Adapter.class.getResourceAsStream("/adapter.properties"));
      System.out.println(
          JSON.writeValueAsString(Map.of("library", "webauthn4j", "version", p.getProperty("version"), "language", "Java")));
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
        // webauthn4j reports failures as WebAuthnException subclasses
        // (DataConversionException, VerificationException).
        Throwable root = e.getMessage() != null && e.getMessage().startsWith("setup:") ? e.getCause() : e;
        if (!(root instanceof WebAuthnException) && !"unknown credential".equals(root.getMessage())) {
          out.put("unexpected", true);
        }
      }
      System.out.println(JSON.writeValueAsString(out));
      System.out.flush();
    }
  }
}

// grimaldello adapter for fido2-net-lib.
// Reads cases (JSON lines) on stdin, writes one verdict per line on stdout.

using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using Fido2NetLib;
using Fido2NetLib.Objects;

if (args.Contains("--info"))
{
    var version = typeof(Fido2).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion.Split('+')[0];
    Console.WriteLine(JsonSerializer.Serialize(new { library = "fido2-net-lib", version, language = "C#" }));
    return;
}

static byte[] B64(string s) => Convert.FromBase64String(s.Replace('-', '+').Replace('_', '/') + new string('=', (4 - s.Length % 4) % 4));

static async Task Verify(JsonNode c)
{
    var rp = c["rp"]!;
    var fido2 = new Fido2(new Fido2Configuration
    {
        ServerDomain = rp["id"]!.GetValue<string>(),
        ServerName = rp["name"]!.GetValue<string>(),
        Origins = new HashSet<string> { rp["origin"]!.GetValue<string>() },
    });
    var uv = c["requireUserVerification"]!.GetValue<bool>() ? UserVerificationRequirement.Required : UserVerificationRequirement.Preferred;
    var user = new Fido2User { Id = B64(c["userHandle"]!.GetValue<string>()), Name = "grimaldello", DisplayName = "grimaldello" };
    var generated = fido2.RequestNewCredential(new RequestNewCredentialParams
    {
        User = user,
        AuthenticatorSelection = new AuthenticatorSelection { UserVerification = uv },
        PubKeyCredParams = c["algorithms"]!.AsArray().Select(a => new PubKeyCredParam((COSE.Algorithm)a!.GetValue<int>(), PublicKeyCredentialType.PublicKey)).ToList(),
    });
    var reg = c["registration"]!;
    var options = new CredentialCreateOptions
    {
        Rp = generated.Rp,
        User = generated.User,
        Challenge = B64(reg["challenge"]!.GetValue<string>()),
        PubKeyCredParams = generated.PubKeyCredParams,
        AuthenticatorSelection = generated.AuthenticatorSelection,
        Attestation = generated.Attestation,
    };
    var attestation = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(reg["response"]!.ToJsonString())!;
    var registration = c["ceremony"]!.GetValue<string>() == "registration";
    RegisteredPublicKeyCredential credential;
    try
    {
        credential = await fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = attestation,
            OriginalOptions = options,
            IsCredentialIdUniqueToUserCallback = (_, _) => Task.FromResult(true),
        });
    }
    catch (Exception e) when (!registration)
    {
        throw new SetupException(e);
    }
    if (registration) return;

    var auth = c["authentication"]!;
    var assertion = JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(auth["response"]!.ToJsonString())!;
    // What an application does: look the credential up by the id in the response.
    if (!assertion.RawId.SequenceEqual(credential.Id)) throw new InvalidOperationException("unknown credential");
    var request = new AssertionOptions
    {
        Challenge = B64(auth["challenge"]!.GetValue<string>()),
        RpId = rp["id"]!.GetValue<string>(),
        UserVerification = uv,
    };
    await fido2.MakeAssertionAsync(new MakeAssertionParams
    {
        AssertionResponse = assertion,
        OriginalOptions = request,
        StoredPublicKey = credential.PublicKey,
        StoredSignatureCounter = auth["storedSignCount"]!.GetValue<uint>(),
        IsUserHandleOwnerOfCredentialIdCallback = (p, _) => Task.FromResult(p.UserHandle.SequenceEqual(user.Id)),
    });
}

string? line;
while ((line = Console.ReadLine()) is not null)
{
    if (string.IsNullOrWhiteSpace(line)) continue;
    var c = JsonNode.Parse(line)!;
    var id = c["id"]!.GetValue<string>();
    try
    {
        await Verify(c);
        Console.WriteLine(JsonSerializer.Serialize(new { id, verdict = "accept" }));
    }
    catch (Exception e)
    {
        var root = e is SetupException s ? s.InnerException! : e;
        var message = e is SetupException ? $"setup: registration failed: {root.GetType().Name}: {root.Message}" : $"{e.GetType().Name}: {e.Message}";
        // fido2-net-lib reports verification failures as Fido2VerificationException;
        // JsonException comes from deserializing the response.
        var documented = root is Fido2VerificationException || root is JsonException || root.Message == "unknown credential";
        Console.WriteLine(documented
            ? JsonSerializer.Serialize(new { id, verdict = "reject", error = message })
            : JsonSerializer.Serialize(new { id, verdict = "reject", error = message, unexpected = true }));
    }
}

sealed class SetupException(Exception inner) : Exception("setup", inner);

# grimaldello adapter for webauthn-ruby (cedarcode).
# Reads cases (JSON lines) on stdin, writes one verdict per line on stdout.

require "bundler/setup"
require "json"
require "base64"
require "webauthn"

if ARGV.include?("--info")
  puts JSON.generate(library: "webauthn-ruby", version: Gem.loaded_specs["webauthn"].version.to_s, language: "Ruby")
  exit 0
end

ALGORITHMS = { -7 => "ES256", -8 => "EdDSA", -257 => "RS256" }.freeze

class SetupError < StandardError; end

def verify(c)
  # Default settings apart from the RP identity and the offered algorithms.
  rp = WebAuthn::RelyingParty.new(
    allowed_origins: [c["rp"]["origin"]],
    id: c["rp"]["id"],
    name: c["rp"]["name"],
    algorithms: c["algorithms"].map { |a| ALGORITHMS.fetch(a) }
  )
  uv = c["requireUserVerification"]
  reg = c["registration"]
  begin
    credential = WebAuthn::Credential.from_create(reg["response"], relying_party: rp)
    credential.verify(reg["challenge"], user_verification: uv)
  rescue StandardError => e
    raise e if c["ceremony"] == "registration"

    raise SetupError, "setup: registration failed: #{e.class}: #{e.message}"
  end
  return if c["ceremony"] == "registration"

  auth = c["authentication"]
  assertion = WebAuthn::Credential.from_get(auth["response"], relying_party: rp)
  # What an application does: look the credential up by the id in the response.
  raise "unknown credential" unless assertion.id == credential.id

  assertion.verify(
    auth["challenge"],
    public_key: credential.public_key,
    sign_count: auth["storedSignCount"],
    user_verification: uv
  )
end

$stdout.sync = true
$stdin.each_line do |line|
  next if line.strip.empty?

  c = JSON.parse(line)
  out = { id: c["id"], verdict: "accept" }
  begin
    verify(c)
  rescue StandardError => e
    out[:verdict] = "reject"
    out[:error] = "#{e.class}: #{e.message}"[0, 500]
    # webauthn-ruby reports failures as WebAuthn::Error subclasses.
    documented = e.is_a?(WebAuthn::Error) || e.is_a?(SetupError) || e.message == "unknown credential"
    out[:unexpected] = true unless documented
  end
  puts JSON.generate(out)
end

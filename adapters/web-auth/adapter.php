<?php
// grimaldello adapter for web-auth/webauthn-lib.
// Reads cases (JSON lines) on stdin, writes one verdict per line on stdout.

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Composer\InstalledVersions;
use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\EdDSA\EdDSA;
use Cose\Algorithm\Signature\RSA\RS256;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AttestationStatement\PackedAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\Exception\WebauthnException;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

if (in_array('--info', $argv, true)) {
    echo json_encode([
        'library' => 'web-auth/webauthn-lib',
        'version' => InstalledVersions::getPrettyVersion('web-auth/webauthn-lib'),
        'language' => 'PHP',
    ]), "\n";
    exit(0);
}

function b64url_decode(string $s): string
{
    return base64_decode(strtr($s, '-_', '+/') . str_repeat('=', (4 - strlen($s) % 4) % 4), true);
}

$algorithms = Manager::create()->add(ES256::create(), new EdDSA(), RS256::create());
$attestation = new AttestationStatementSupportManager([
    new NoneAttestationStatementSupport(),
    PackedAttestationStatementSupport::create($algorithms),
]);
$serializer = (new WebauthnSerializerFactory($attestation))->create();

function verify(array $c): void
{
    global $algorithms, $attestation, $serializer;
    $factory = new CeremonyStepManagerFactory();
    $factory->setAllowedOrigins([$c['rp']['origin']]);
    $factory->setAlgorithmManager($algorithms);
    $factory->setAttestationStatementSupportManager($attestation);

    $uv = $c['requireUserVerification']
        ? AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED
        : AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED;
    $userHandle = b64url_decode($c['userHandle']);
    $creation = PublicKeyCredentialCreationOptions::create(
        PublicKeyCredentialRpEntity::create($c['rp']['name'], $c['rp']['id']),
        PublicKeyCredentialUserEntity::create('grimaldello', $userHandle, 'grimaldello'),
        b64url_decode($c['registration']['challenge']),
        array_map(fn ($a) => PublicKeyCredentialParameters::createPk($a), $c['algorithms']),
        AuthenticatorSelectionCriteria::create(userVerification: $uv),
    );
    $credential = $serializer->deserialize(json_encode($c['registration']['response']), PublicKeyCredential::class, 'json');
    if (!$credential->response instanceof AuthenticatorAttestationResponse) {
        throw new RuntimeException('not an attestation response');
    }
    try {
        $record = AuthenticatorAttestationResponseValidator::create($factory->creationCeremony())
            ->check($credential->response, $creation, $c['rp']['id']);
    } catch (Throwable $e) {
        if ($c['ceremony'] === 'registration') {
            throw $e;
        }
        throw new RuntimeException('setup: registration failed: ' . $e->getMessage(), 0, $e);
    }
    if ($c['ceremony'] === 'registration') {
        return;
    }

    $a = $c['authentication'];
    $record->counter = $a['storedSignCount'];
    $assertion = $serializer->deserialize(json_encode($a['response']), PublicKeyCredential::class, 'json');
    if (!$assertion->response instanceof AuthenticatorAssertionResponse) {
        throw new RuntimeException('not an assertion response');
    }
    // What an application does: look the credential up by the id in the response.
    if ($assertion->rawId !== $record->publicKeyCredentialId) {
        throw new RuntimeException('unknown credential');
    }
    $request = PublicKeyCredentialRequestOptions::create(
        b64url_decode($a['challenge']),
        rpId: $c['rp']['id'],
        userVerification: $uv,
    );
    AuthenticatorAssertionResponseValidator::create($factory->requestCeremony())
        ->check($record, $assertion->response, $request, $c['rp']['id'], $userHandle);
}

while (($line = fgets(STDIN)) !== false) {
    if (trim($line) === '') {
        continue;
    }
    $c = json_decode($line, true, 512, JSON_THROW_ON_ERROR);
    $out = ['id' => $c['id'], 'verdict' => 'accept'];
    try {
        verify($c);
    } catch (Throwable $e) {
        $out['verdict'] = 'reject';
        $out['error'] = get_class($e) . ': ' . $e->getMessage();
        // Applications catch WebauthnException (and the serializer's exceptions
        // when decoding); anything else is an error they do not expect.
        $root = str_starts_with($e->getMessage(), 'setup:') ? $e->getPrevious() : $e;
        $documented = $root instanceof WebauthnException
            || $root instanceof Symfony\Component\Serializer\Exception\ExceptionInterface
            || $e->getMessage() === 'unknown credential';
        if (!$documented) {
            $out['unexpected'] = true;
        }
    }
    echo json_encode($out), "\n";
    fflush(STDOUT);
}

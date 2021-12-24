<?php

namespace io\billdesk\client\jose;

use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\Serializer\CompactSerializer as EncSerializer;
use Jose\Component\Signature\Serializer\CompactSerializer as SignSerializer;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\JWSBuilder;
use Monolog\Logger;
use io\billdesk\client\Logging;
use io\billdesk\client\Constants;
use Jose\Component\Signature\JWSVerifier;
use io\billdesk\client\jose\SignatureVerificationException;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Signature\Serializer\CompactSerializer as SerializerCompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;

class JoseHelper {
    protected $keyEncAlgoManager;
    protected $bodyEncAlgoManager;
    protected $signAlgoManager;
    protected $compressionMethodMaanger;
    protected $serverEncryptionJwk;
    protected $serverSigningJwk;
    protected $clientJwk;
    protected $jweBuilder;
    protected $jwsBuilder;
    protected $key;
    protected $thumbprint;
    protected $jwsVerifier;
    protected $signVerificationJwkSet;
    protected $jweDecryptor;
    protected $clientKeyThumbprint;

    private static $logger;

    public function __construct($serverEncryptionKey, $serverSigningKey, $clientKeyThumbprint, $clientKey, $clientKeyPassword = null)
    {
        self::$logger = Logging::getDefaultLogger();
        $this->keyEncAlgoManager = new AlgorithmManager([
            new RSAOAEP256()
        ]);
        $this->bodyEncAlgoManager = new AlgorithmManager([
            new A256GCM(),
            new A128GCM()
        ]);
        $this->signAlgoManager = new AlgorithmManager([
            new PS256()
        ]);
        $this->compressionMethodMaanger = new CompressionMethodManager([
            new Deflate()
        ]);

        $this->clientJwk = JWKFactory::createFromKey($clientKey, $clientKeyPassword);
        
        $this->serverEncryptionJwk = JWKFactory::createFromCertificate($serverEncryptionKey);
        $this->serverSigningJwk = JWKFactory::createFromCertificate($serverSigningKey);

        $this->jweBuilder = new JWEBuilder(
            $this->keyEncAlgoManager,
            $this->bodyEncAlgoManager,
            $this->compressionMethodMaanger
        );
        $this->jweDecryptor = new JWEDecrypter(
            $this->keyEncAlgoManager,
            $this->bodyEncAlgoManager,
            $this->compressionMethodMaanger
        );

        $this->jwsBuilder = new JWSBuilder($this->signAlgoManager);
        $this->jwsVerifier = new JWSVerifier($this->signAlgoManager);
        $this->signVerificationJwkSet = new JWKSet([
            $this->serverSigningJwk, 
            $this->clientJwk
        ]);

        $this->clientKeyThumbprint = $clientKeyThumbprint;
    }

    public function encrypt($payload, $headers = array()) {
        $jweHeaders = array_merge($headers, array(
            'alg' => 'RSA-OAEP-256',
            'enc' => 'A128GCM',
            'x5t#S256' => ''
        ));

        $jwe = $this->jweBuilder
            ->create()
            ->withPayload($payload)
            ->withSharedProtectedHeader($jweHeaders)
            ->addRecipient($this->serverEncryptionJwk)
            ->build();

        $jweSeriealizer = new EncSerializer();
        $serializedJwe = $jweSeriealizer->serialize($jwe, 0);

        return $serializedJwe;
    }

    public function encryptAndSign($payload, $headers = array()) {

        $jweHeaders = array_merge($headers, array(
            'alg' => 'RSA-OAEP-256',
            'enc' => 'A128GCM',
            'x5t#S256' => ''
        ));

        $jwe = $this->jweBuilder
            ->create()
            ->withPayload($payload)
            ->withSharedProtectedHeader($jweHeaders)
            ->addRecipient($this->serverEncryptionJwk)
            ->build();

        $jweSeriealizer = new EncSerializer();
        $serializedJwe = $jweSeriealizer->serialize($jwe, 0);

        $jwsHeaders = array_merge($headers, array(
            'alg' => 'PS256',
            'x5t#S256' => $this->clientKeyThumbprint,
        ));

        $jws = $this->jwsBuilder
                ->create()
                ->withPayload($serializedJwe)
                ->addSignature($this->clientJwk, $jwsHeaders)
                ->build();

        $jwsSerializer = new SignSerializer();
        $token = $jwsSerializer->serialize($jws, 0);

        return $token;
    }

    public function verifyAndDecrypt($token) {
        $serializerManager = new JWSSerializerManager([
            new SerializerCompactSerializer()
        ]);

        $jws =$serializerManager->unserialize($token);;

        if (!$this->jwsVerifier->verifyWithKeySet($jws, $this->signVerificationJwkSet, 0)) {
            throw new SignatureVerificationException("Failed to verify signature");
        }

        $token = $jws->getPayload();

        $serializer = new JWESerializerManager([
            new CompactSerializer()
        ]);

        $jwe = $serializer->unserialize($token);
        if (!$this->jweDecryptor->decryptUsingKeySet($jwe, $this->signVerificationJwkSet, 0)) {
            throw new SignatureVerificationException("Unable to decrypt body");
        }

        return $jwe->getPayload();
      }
}

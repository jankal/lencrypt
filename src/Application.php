<?php

namespace jankal\Lencrypt;

use AcmePhp\Ssl\CertificateRequest;
use AcmePhp\Ssl\DistinguishedName;
use AcmePhp\Ssl\Generator\KeyPairGenerator;
use AcmePhp\Ssl\KeyPair;
use AcmePhp\Ssl\ParsedCertificate;
use AcmePhp\Ssl\PublicKey;
use Carbon\Carbon;
use Ds\Vector;
use stdClass;
use Symfony\Component\Finder\Finder;

class Application {

    /**
     * @return Vector
     */
    public static function detectOld(): Vector {
        // find old certs
        $finder = new Finder();
        $finder->files()->in(getenv('CERT_DIR'));
        $info = new CertInfo($finder);
        $now = Carbon::now();
        $maxDiff = 10;
        $requireRenew = $info->find(
            /**
             * @param ParsedCertificate $cert
             * @return bool
             */
            function(ParsedCertificate $cert, stdClass $metadata) use($now, $maxDiff) {
                $date = Carbon::instance($cert->getValidTo());
                return (!$date->gte($now) || ($date->gt($now) && $date->diffInDays($now) <= $maxDiff));
            }
        );
        return $requireRenew;
    }

    /**
     * @param Vector $files
     */
    public static function generateNewRenewKeys(Vector $files) {
        $generator = new KeyPairGenerator();
        foreach ($files as list($file, $cert)) {
            $keyPair = $generator->generateKeyPair();
            file_put_contents($file, $keyPair->getPrivateKey()->getPEM());
        }
    }

    /**
     * @param string $file
     */
    public static function genKey(string $file) {
        $generator = new KeyPairGenerator();
        $keyPair = $generator->generateKeyPair();
        file_put_contents($file, $keyPair->getPrivateKey()->getPEM());
    }

    /**
     * @param Vector $files
     * @return Vector
     */
    public static function processNewKeylist(Vector $files): Vector {
        $v = new Vector();
        foreach ($files as list($file, $cert, $certfile)) {
            $meta = new Metadata($file);
            $rawKey = new \AcmePhp\Ssl\PrivateKey($meta->getContents());
            $res = $rawKey->getResource();
            $details = openssl_pkey_get_details($res);
            $rawPublicKey = new PublicKey($details['key']);
            $keypair = new KeyPair($rawPublicKey, $rawKey);
            $dn = new DistinguishedName(
                $cert->getSubject(),
                getenv('COUNTRY'),
                getenv('STATE'),
                getenv('LOCALITY'),
                getenv('ORGANIZATION'),
                getenv('ORGANIZATION_UNIT'),
                getenv('USER_EMAIL'),
                $cert->getSubjectAlternativeNames()
            );
            $req = new CertificateRequest($dn, $keypair);
            $v->push([$keypair, $req, $dn, $certfile]);
        }
        return $v;
    }
}
<?php

require_once "./vendor/autoload.php";

use AcmePhp\Ssl\KeyPair;
use AcmePhp\Ssl\PrivateKey;
use AcmePhp\Ssl\PublicKey;
use Dotenv\Dotenv;
use Ds\Vector;
use jankal\Lencrypt\Api;
use jankal\Lencrypt\User;
use Symfony\Component\Filesystem\Filesystem;

$dotenv = new Dotenv(__DIR__);
$dotenv->load();

$fs = new Filesystem();

if(!$fs->exists(getenv('DOC_ROOT'))) {
    $fs->mkdir(getenv('DOC_ROOT'));
}
$api = new Api(getenv('DOC_ROOT'));
$user = new User(getenv('USER_EMAIL'));
if($fs->exists([getenv('USER_PRIVKEY'), getenv('USER_PUBKEY')])) {
    $privateKey = new PrivateKey(file_get_contents(getenv('USER_PRIVKEY')));
    $publicKey = new PublicKey(file_get_contents(getenv('USER_PUBKEY')));
    $keypair = new KeyPair($publicKey, $privateKey);
    $user->setKeyPair($keypair);
    $user->registered = true;
} else {
    $keypair = $api->generateUserKeyPair();
    file_put_contents(getenv('USER_PRIVKEY'), $keypair->getPrivateKey()->getPEM());
    file_put_contents(getenv('USER_PUBKEY'), $keypair->getPublicKey()->getPEM());
    $user->setKeyPair($keypair);
    $user->registered = false;
}
$api->login($user);

$old = \jankal\Lencrypt\Application::detectOld();

$nKeys = new Vector();
$rKeys = new Vector();
foreach($old as list($parsedCert, $filename)) {
    $keyname = str_replace('.crt', '.key', $filename);
    $fs->remove($filename);
    $fs->remove($keyname);
    $renewPath = realpath(getenv('RENEW_DIR')) .  DIRECTORY_SEPARATOR . basename($keyname);
    if(!$fs->exists($renewPath)) {
        \jankal\Lencrypt\Application::genKey($renewPath);
    }
    $fs->copy($renewPath, $keyname);
    $fs->remove($renewPath);
    $nKeys->push([$keyname, $parsedCert, $filename]);
    $rKeys->push([$renewPath, $parsedCert]);
}

\jankal\Lencrypt\Application::generateNewRenewKeys($rKeys);

$renewKeys = \jankal\Lencrypt\Application::processNewKeylist($nKeys);
$certAndKeys = $api->reqeuestCerts($renewKeys);

foreach ($certAndKeys as list($keypair, $cert, $dn, $certname)) {
    $pem = $cert->getPEM();
    file_put_contents($certname, $pem);
}
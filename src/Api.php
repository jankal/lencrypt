<?php

namespace jankal\Lencrypt;

use AcmePhp\Core\AcmeClient;
use AcmePhp\Core\Http\Base64SafeEncoder;
use AcmePhp\Core\Http\SecureHttpClient;
use AcmePhp\Core\Http\ServerErrorHandler;
use AcmePhp\Core\Protocol\AuthorizationChallenge;
use AcmePhp\Ssl\Generator\KeyPairGenerator;
use AcmePhp\Ssl\KeyPair;
use AcmePhp\Ssl\Parser\KeyParser;
use AcmePhp\Ssl\Signer\DataSigner;
use Ds\Pair;
use Ds\Vector;
use GuzzleHttp\Client;
use jankal\Lencrypt\Service as InitService;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\PhpExecutableFinder;
use Symfony\Component\Process\Process;
use SystemCtl\Service as SystemctlService;

/**
 * @class Api
 * @author Alexander Jank <himself@alexanderjank.de>
 * @todo SFTP access
 */
class Api {

    /**
     * @var \stdClass
     */
    private $user;

    /**
     * @var string
     */
    private $documentRoot;

    /**
     * @var Filesystem
     */
    private $fs;

    /**
     * @var Vector
     */
    private $renewCerts;

    /**
     * @var AcmeClient
     */
    private $client;

    /**
     * @var bool
     */
    private $server = true;

    /**
     * Api constructor.
     * @param string $documentRoot
     * @throws \Exception
     */
    public function __construct(string $documentRoot) {
        $this->renewCerts = new Vector();
        $this->fs = new Filesystem();
        if($this->fs->exists($documentRoot)) {
            $this->documentRoot = realpath($documentRoot);
        } else {
            throw new \Exception("Document Root not found!");
        }
    }

    /**
     * @param User $user
     * @internal param string $email
     */
    public function login(User $user) {
        $this->user = $user;
        $guzzle = new Client(['verify' => 'C:\Program Files\cURL\bin\curl-ca-bundle.crt']);
        $secureHttpClient = new SecureHttpClient(
            $this->user->getPair(),
            $guzzle,
            new Base64SafeEncoder(),
            new KeyParser(),
            new DataSigner(),
            new ServerErrorHandler()
        );
        $this->client = new AcmeClient($secureHttpClient, 'https://acme-v01.api.letsencrypt.org/directory');
        if(!$this->user->registered) {
            $this->client->registerAccount('https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf', $this->user->email);
            $this->user->registered = true;
        }
    }

    /**
     * @param Vector $renewCerts
     */
    public function setRenewCerts(Vector $renewCerts) {
        $this->renewCerts = $renewCerts;
    }

    /**
     * @return Vector
     */
    public function getDomainList(): Vector {
        $list = new Vector;
        foreach($this->renewCerts as list($cert, $file)) {
            $alternatives = $cert->getSubjectAlternativeNames();
            $subject = $cert->getSubject();
            if(!in_array($subject, $alternatives)) {
                $alternatives[] = $subject;
            }
            foreach($alternatives as $domain) {
                if(!$list->contains($domain)) {
                    $list->push($domain);
                }
            }
        }
        return $list;
    }

    /**
     * @return Vector
     */
    public function getCertList(): Vector {
        $list = new Vector;
        foreach($this->renewCerts as list($cert, $file)) {
            $alternatives = $cert->getSubjectAlternativeNames();
            $subject = $cert->getSubject();
            if(!in_array($subject, $alternatives)) {
                $alternatives[] = $subject;
            }
            $pair = new Pair($subject, $alternatives);
            $list->push($pair);
        }
        return $list;
    }

    /**
     * @return KeyPair
     */
    public function generateUserKeyPair() {
        return (new KeyPairGenerator())->generateKeyPair();
    }

    /**
     * @param Vector $list
     * @return Vector
     * @throws \Exception
     */
    public function reqeuestCerts(Vector $list): Vector {
        if(!($this->user instanceof User)) {
            throw new \Exception("not logged in yet!");
        }
        $returnVector = new Vector();
        foreach($list as list($keypair, $csr, $dn, $certname)) {
            $challenges = $this->client->requestAuthorization($dn->getCommonName());
            foreach ($challenges as $challenge) {
                if ('http-01' === $challenge->getType()) {
                    $process = $this->challengeUp($challenge);
                    $check = $this->client->challengeAuthorization($challenge);
                    if($check['status'] != 'valid') {
                        throw new \Exception();
                    }
                    $this->challengeDown($challenge, $process);
                }
            }
            $response = $this->client->requestCertificate($dn->getCommonName(), $csr);
            $cert = $response->getCertificate();
            $returnVector->push([$keypair, $cert, $dn, $certname]);
        }
        return $returnVector;
    }

    public function disableTempServer() {
        $this->server = false;
    }

    /**
     * @param AuthorizationChallenge $challenge
     * @return array|null
     */
    public function challengeUp(AuthorizationChallenge $challenge) {
        if(!$this->fs->exists($this->documentRoot . DIRECTORY_SEPARATOR . '.well-known')) {
            $this->fs->mkdir($this->documentRoot . DIRECTORY_SEPARATOR . '.well-known');
        }
        if(!$this->fs->exists($this->documentRoot . DIRECTORY_SEPARATOR . '.well-known' . DIRECTORY_SEPARATOR . 'acme-challenge')) {
            $this->fs->mkdir($this->documentRoot . DIRECTORY_SEPARATOR . '.well-known' . DIRECTORY_SEPARATOR . 'acme-challenge');
        }
        file_put_contents(
            $this->documentRoot . DIRECTORY_SEPARATOR . '.well-known' . DIRECTORY_SEPARATOR . 'acme-challenge' . DIRECTORY_SEPARATOR . $challenge->getToken(),
            $challenge->getPayload()
        );
        if($this->server) {
            $down = $this->ensureWebserverDown();
            $process = $this->createServer(80);
            $process->start();
            return [$process, $down];
        } else {
            return NULL;
        }
    }

    /**
     * @param int $port
     * @return Process
     */
    public function createServer(int $port): Process {
        $listen = '0.0.0.0:' . $port;
        $finder = new PhpExecutableFinder();
        if (false === $binary = $finder->find()) {
            throw new \RuntimeException('Unable to find PHP binary to start server.');
        }
        $script = implode(
            ' ',
            array_map(
                ['Symfony\Component\Process\ProcessUtils', 'escapeArgument'],
                [
                    $binary,
                    '-S',
                    $listen,
                    '-t',
                    $this->documentRoot,
                ]
            )
        );
        return new Process('exec '.$script, $this->documentRoot, null, null, null);
    }

    /**
     * @param AuthorizationChallenge $challenge
     * @param array $process
     */
    public function challengeDown(AuthorizationChallenge $challenge, array $process = NULL) {
        if(isset($process)) {
            list($proc, $down) = $process;
            $proc->stop();
            $this->startWebservers($down);
        }
        $this->fs->remove($this->documentRoot . DIRECTORY_SEPARATOR . '.well-known' . DIRECTORY_SEPARATOR . 'acme-challenge' . DIRECTORY_SEPARATOR . $challenge->getToken());
    }

    /**
     * @return Vector
     */
    private function ensureWebserverDown(): Vector {
        $down = new Vector();
        if(`which systemctl`) {
            foreach (['apache2', "nginx", "lighthttp"] as $name) {
                $service = new SystemctlService($name);
                if ($service->isRunning()) {
                    $service->stop();
                    $down->push($name);
                }
            }
        } elseif(`which service`) {
            foreach (['apache2', "nginx", "lighthttp"] as $name) {
                $service = new InitService($name);
                if ($service->isRunning()) {
                    $service->stop();
                    $down->push($name);
                }
            }
        }
        return $down;
    }

    /**
     * @param Vector $down
     */
    private function startWebservers(Vector $down) {
        foreach($down as $service) {
            $service->start();
        }
    }
}

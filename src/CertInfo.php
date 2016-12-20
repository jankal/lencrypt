<?php

namespace jankal\Lencrypt;
use Closure;
use Ds\Vector;
use Symfony\Component\Finder\Finder;


class CertInfo {

    /**
     * @var Finder
     */
    private $dir;

    /**
     * Info constructor.
     * @param Finder $dir
     */
    public function __construct(Finder $dir) {
        $this->dir = $dir;
    }

    public function find(Closure $callback): Vector {
        $dataCollection = new Vector();
        $parser = new \AcmePhp\Ssl\Parser\CertificateParser();
        foreach($this->dir->name('*.crt') as $file) {
            $fileName = $file->getRealPath();
            $meta = new Metadata($fileName);
            $rawCertificate = new \AcmePhp\Ssl\Certificate($meta->getContents());
            $parsedCertificate = $parser->parse($rawCertificate);
            if($callback($parsedCertificate, $meta->getMeta())) {
                $dataCollection->push([$parsedCertificate, $fileName]);
            }
        }
        return $dataCollection;
    }
}
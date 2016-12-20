<?php

namespace jankal\Lencrypt;

use Closure;
use Ds\Vector;
use Symfony\Component\Finder\Finder;

class KeyInfo {
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

    /**
     * @param Closure $callback
     * @return Vector
     */
    public function find(Closure $callback): Vector {
        $dataCollection = new Vector();
        $parser = new \AcmePhp\Ssl\Parser\KeyParser();
        foreach($this->dir->name('*.key') as $file) {
            $fileName = $file->getRealPath();
            $meta = new Metadata($fileName);
            $rawKey = new \AcmePhp\Ssl\PrivateKey($meta->getContents());
            $parsedKey = $parser->parse($rawKey);
            if($callback($parsedKey, $fileName, $meta->getMeta())) {
                $dataCollection->push([$parsedKey, $fileName]);
            }
        }
        return $dataCollection;
    }

    /**
     * @return Vector
     */
    public function findAll(): Vector {
        $dataCollection = new Vector();
        $parser = new \AcmePhp\Ssl\Parser\KeyParser();
        foreach($this->dir->name('*.key') as $file) {
            $fileName = $file->getRealPath();
            $meta = new Metadata($fileName);
            $rawKey = new \AcmePhp\Ssl\PrivateKey($meta->getContents());
            $parsedKey = $parser->parse($rawKey);
            $dataCollection->push([$parsedKey, $fileName]);
        }
        return $dataCollection;
    }
}
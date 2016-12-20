<?php

namespace jankal\Lencrypt;

use AcmePhp\Ssl\KeyPair;

class User {

    /**
     * @var KeyPair
     */
    private $pair;

    /**
     * @var bool
     */
    public $registered;

    /**
     * User constructor.
     * @param string $email
     */
    public function __construct(string $email) {
        $this->email = $email;
    }

    /**
     * @param KeyPair $pair
     */
    public function setKeyPair(KeyPair $pair) {
        $this->pair = $pair;
    }

    /**
     * @return KeyPair
     */
    public function getPair(): KeyPair {
        return $this->pair;
    }
}
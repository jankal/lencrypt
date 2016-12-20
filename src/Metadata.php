<?php

namespace jankal\Lencrypt;


class Metadata {

    /**
     * @var string
     */
    private $contents;

    /**
     * @var string
     */
    private $path;

    /**
     * @var string
     */
    private $metaEnding = "---END META---";

    /**
     * @var string
     */
    private $metaStart = "---START META---";

    /**
     * Metadata constructor.
     * @param string $filename
     */
    public function __construct(string $filename) {
        $this->contents = file_get_contents($filename);
        $this->path = realpath($filename);
    }

    /**
     * @return \stdClass
     */
    public function getMeta(): \stdClass {
        $out = "";
        $i = 0;
        $started = false;
        foreach(preg_split("/((\r?\n)|(\r\n?))/", $this->contents) as $line){
            $i++;
            if(!$started && string($line)->contains($this->metaStart)) {
                $started = true;
                continue;
            }
            if($started && string($line)->contains($this->metaEnding)) {
                $started = false;
                continue;
            }
            if($started) {
                $out .= $line . PHP_EOL;
            }
        }
        $jdec = json_decode($out);
        return $jdec == NULL ? new \stdClass() : $jdec;
    }

    /**
     * @return string
     */
    public function getContents(): string {
        $out = "";
        $i = 0;
        $started = false;
        foreach(preg_split("/((\r?\n)|(\r\n?))/", $this->contents) as $line){
            $i++;
            if(!$started && string($line)->contains($this->metaStart)) {
                $started = true;
                continue;
            }
            if($started && string($line)->contains($this->metaEnding)) {
                $started = false;
                continue;
            }
            if(!$started) {
                $out .= $line . PHP_EOL;
            }
        }
        return $out;
    }
}
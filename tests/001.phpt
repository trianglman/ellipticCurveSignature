--TEST--
Elliptic Curve ED25519 public key generation
--SKIPIF--
<?php
if (!extension_loaded("ellipticCurveSignature")) die("skip");
if (!is_readable("tests/sign.input")) die("Skip: Signature input file not readable.");
?>
--FILE--
<?php
    $inputFile = fopen("tests/sign.input", "r");
    $testLine = fgets($inputFile);
    while ($testLine !== false) {
        list($skConcat, $pktest) = explode(':', $set);
        $sk = hex2bin(substr($skConcat, 0, 64));
        $pk = ec_generate_pk($sk,EC_ED25519);
        if ($pk !== hex2bin($pktest)) {
            die("Public key generation failed");
        }
        $testLine = fgets($inputFile);
    }
    echo "OK!\n";
    fclose($inputFile);
?>
--EXPECT--
OK!

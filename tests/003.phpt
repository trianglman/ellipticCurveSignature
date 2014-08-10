--TEST--
Elliptic Curve ED25519 signature validation
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
        list($skConcat, $pktest, $m, $sigConcat) = explode(':', $set);
        $pk = hex2bin($pktest);
        $msg = hex2bin($m);
        $sig = hex2bin(substr($sigConcat, 0, 128));
        if (!ec_verify($sig, $msg, $pk, EC_ED25519)) {
            die("Signature validation failed");
        }
        $testLine = fgets($inputFile);
    }
    echo "OK!\n";
    fclose($inputFile);
?>
--EXPECT--
OK!

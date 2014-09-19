--TEST--
Elliptic Curve ED25519 generate signature
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
        list($skConcat, $pktest, $m, $sigConcat) = explode(':', $testLine);
        $sk = hex2bin(substr($skConcat, 0, 64));
        $pk = hex2bin($pktest);
        $msg = hex2bin($m);
        $sig = hex2bin(substr($sigConcat, 0, 128));

        $actual = ec_sign($sk, $pk, $msg, EC_ED25519);
        if ($actual !== $sig) {
            die("Signature failed to generate");
        }
        $testLine = fgets($inputFile);
    }
    echo "OK!\n";
    fclose($inputFile);
?>
--EXPECT--
OK!

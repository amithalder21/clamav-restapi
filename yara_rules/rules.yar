rule eicar_av_test {
    meta:
        description = "This is a standard AV test, intended to verify that the Anti-Virus is working properly."
        author = "ClamTrac API"
    strings:
        $a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $a
}

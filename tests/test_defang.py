from iocextractor.defang import defang, refang


def test_refang_hxxp_and_brackets():
    assert refang("hxxp://evil[.]com/path") == "http://evil.com/path"
    assert refang("hxxps://a[.]b[.]com") == "https://a.b.com"


def test_refang_at_and_dot_words():
    assert refang("user[at]mail[dot]com") == "user@mail.com"
    assert refang("bob(at)example(dot)org") == "bob@example.org"


def test_refang_colon_and_slashes():
    assert refang("http[:]//host[//]path") == "http://host//path"


def test_defang_roundtrip_shape():
    assert defang("http://evil.com") == "hxxp://evil[.]com"
    assert defang("bob@example.com") == "bob[at]example[.]com"

from iocextractor.extract import extract


def test_ipv4_and_private_filter():
    text = "beacon 203.0.113.45 and internal 192.168.1.10 and 127.0.0.1"
    assert extract(text)["ipv4"] == ["127.0.0.1", "192.168.1.10", "203.0.113.45"]
    assert extract(text, filter_private=True)["ipv4"] == ["203.0.113.45"]


def test_ipv6():
    out = extract("c2 at 2001:db8:dead:beef::1337 today")
    assert out["ipv6"] == ["2001:db8:dead:beef::1337"]


def test_hashes_are_classified_by_length():
    md5 = "44d88612fea8a8f36de82e1278abb02f"
    sha1 = "3395856ce81f2b7382dee72602f798b642f14140"
    sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    out = extract(f"{md5} {sha1} {sha256}")
    assert out["md5"] == [md5]
    assert out["sha1"] == [sha1]
    assert out["sha256"] == [sha256]


def test_sha256_not_split_into_shorter_hashes():
    sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    out = extract(sha256)
    assert out["md5"] == [] and out["sha1"] == []


def test_urls_emails_domains():
    text = "visit https://login.evil.com/a and mail bob@evil.com"
    out = extract(text)
    assert out["urls"] == ["https://login.evil.com/a"]
    assert out["emails"] == ["bob@evil.com"]
    # domain inventory includes URL host and email domain
    assert "login.evil.com" in out["domains"]
    assert "evil.com" in out["domains"]


def test_defanged_input_is_refanged_before_matching():
    text = "hxxps://bad[.]domain[.]com and evil[at]bad[dot]com"
    out = extract(text)
    assert "https://bad.domain.com" in out["urls"]
    assert "bad.domain.com" in out["domains"]
    assert "evil@bad.com" in out["emails"]


def test_no_refang_keeps_input_literal():
    out = extract("hxxps://bad[.]com", refang=False)
    assert out["urls"] == []


def test_cve_normalised_uppercase_and_deduped():
    out = extract("exploit cve-2024-3400 and CVE-2024-3400 plus CVE-2023-23397")
    assert out["cve"] == ["CVE-2023-23397", "CVE-2024-3400"]


def test_file_names_not_treated_as_domains():
    out = extract("dropped invoice_scan.exe and report.pdf")
    assert "invoice_scan.exe" not in out["domains"]
    assert "report.pdf" not in out["domains"]


def test_results_are_sorted_and_deduped():
    out = extract("8.8.8.8 1.1.1.1 8.8.8.8 1.1.1.1")
    assert out["ipv4"] == ["1.1.1.1", "8.8.8.8"]

import json

from iocextractor.exporter import to_csv, to_json, to_table
from iocextractor.extract import extract


SAMPLE = "beacon 203.0.113.45 url https://evil.com/x hash 44d88612fea8a8f36de82e1278abb02f"


def test_json_is_valid_and_has_all_keys():
    out = json.loads(to_json(extract(SAMPLE)))
    for key in ("ipv4", "ipv6", "domains", "urls", "emails", "md5", "sha1", "sha256", "cve"):
        assert key in out
    assert out["ipv4"] == ["203.0.113.45"]


def test_csv_header_and_rows():
    csv_text = to_csv(extract(SAMPLE))
    lines = csv_text.strip().splitlines()
    assert lines[0] == "type,value"
    assert any(line == "ipv4,203.0.113.45" for line in lines)


def test_table_contains_total():
    table = to_table(extract(SAMPLE))
    assert "total indicators:" in table


def test_defang_in_json_output():
    out = json.loads(to_json(extract(SAMPLE), defang=True))
    assert out["ipv4"] == ["203[.]0[.]113[.]45"]
    assert out["urls"] == ["hxxps://evil[.]com/x"]
    # hashes stay intact
    assert out["md5"] == ["44d88612fea8a8f36de82e1278abb02f"]

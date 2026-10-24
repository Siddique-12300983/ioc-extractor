# ioc-extractor

A Python CLI that pulls indicators of compromise out of any text: IP addresses,
domains, URLs, emails, file hashes and CVE IDs. It understands defanged input
like `hxxp://evil[.]com`, can defang or refang on the way out, dedupes
everything, and exports to JSON or CSV.

I built this for the detection side of my
[purple-team-journey](https://github.com/Siddique-12300983/purple-team-journey)
lab. Threat reports and alert emails are full of indicators written in slightly
different ways, and copying them out by hand is slow and error-prone.

## What it finds

- IPv4 and IPv6 addresses
- Domains (from standalone text, URL hosts and email domains, with obvious file
  names like `report.pdf` filtered out)
- URLs (http, https, ftp)
- Email addresses
- MD5, SHA1 and SHA256 hashes (classified by length, so a SHA256 is never
  mistaken for a shorter hash)
- CVE IDs (normalised to uppercase)

## Why it matters

Analysts pull indicators out of reports to block them, search for them in logs,
or share them. The two things that make that painful are inconsistent formatting
and defanging. Defanging is when an indicator is written so it cannot be clicked
by accident, for example `hxxps://bad[.]domain[.]com` or `evil[at]bad[dot]com`.
This tool refangs that input automatically so it still matches, then lets you
defang the output again before you paste it into a ticket.

## Install

Python 3.9 or newer. It uses only the standard library.

```bash
git clone https://github.com/Siddique-12300983/ioc-extractor.git
cd ioc-extractor
```

Optionally install it as a command:

```bash
pip install .
ioc-extractor samples/threat-report.txt
```

## Usage

```bash
# Read a file and print a table
python -m iocextractor samples/threat-report.txt

# From stdin
cat alert.eml | python -m iocextractor -

# JSON or CSV
python -m iocextractor samples/threat-report.txt -f json
python -m iocextractor samples/threat-report.txt -f csv -o iocs.csv

# Drop internal IPs (RFC1918, loopback, link-local)
python -m iocextractor samples/threat-report.txt --filter-private

# Defang the output so it is safe to paste into a report
python -m iocextractor samples/threat-report.txt --defang -f json
```

```
usage: ioc-extractor [-h] [-f {table,json,csv}] [-o OUTPUT] [--filter-private]
                     [--no-refang] [--defang] [--version]
                     [input]
```

The exit code is `0` when indicators were found and `1` when none were, so it
works in a pipeline.

## Example output

Running it on the included sample report:

```
IOC extraction report
========================================

IPv4 (6)
  10.10.10.10
  127.0.0.1
  185.220.101.9
  192.168.1.50
  198.51.100.23
  203.0.113.45

Domains (4)
  cdn-update.net
  example.com
  harbour1ine-freight.com
  invoice-harbourline.com

URLs (2)
  http://185.220.101.9/gate.php
  https://invoice-harbourline.com/login

...
total indicators: 20
```

With `--defang -f json` the same indicators come back safe to paste:

```json
{
  "urls": [
    "hxxp://185[.]220[.]101[.]9/gate[.]php",
    "hxxps://invoice-harbourline[.]com/login"
  ]
}
```

## Sample data

`samples/threat-report.txt` is a short fictional threat note (Harbourline
Freight, my lab's fake company) with defanged indicators, private and public
IPs, hashes and CVEs, so the tool produces a full result out of the box.

## Running the tests

```bash
pip install pytest
pytest
```

The suite covers the defang/refang logic, each indicator type, hash
classification by length, the private-IP filter, and the JSON and CSV exporters.

## Layout

```
iocextractor/
  patterns.py   the regexes
  defang.py     refang input, defang output
  extract.py    extraction, dedupe, private-IP filter
  exporter.py   table, JSON and CSV output
  cli.py        argument parsing and entry point
samples/        a sample threat report
tests/          pytest suite
```

## License

MIT. See [LICENSE](LICENSE).

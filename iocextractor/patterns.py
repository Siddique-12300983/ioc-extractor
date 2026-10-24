"""Compiled regexes for each indicator type."""

import re

# IPv4, with each octet bounded 0-255.
IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

# IPv6: full, compressed (::) and mixed forms. Not exhaustive, but it covers the
# shapes that turn up in logs and reports without matching plain text.
IPV6 = re.compile(
    # Fuller forms first so a trailing group is not lost to the compressed "::".
    r"(?<![:.\w])(?:"
    r"(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}"
    r"|(?:[A-F0-9]{1,4}:){1,6}:[A-F0-9]{1,4}"
    r"|(?:[A-F0-9]{1,4}:){1,5}(?::[A-F0-9]{1,4}){1,2}"
    r"|(?:[A-F0-9]{1,4}:){1,4}(?::[A-F0-9]{1,4}){1,3}"
    r"|(?:[A-F0-9]{1,4}:){1,3}(?::[A-F0-9]{1,4}){1,4}"
    r"|(?:[A-F0-9]{1,4}:){1,2}(?::[A-F0-9]{1,4}){1,5}"
    r"|[A-F0-9]{1,4}:(?::[A-F0-9]{1,4}){1,6}"
    r"|:(?::[A-F0-9]{1,4}){1,7}"
    r"|(?:[A-F0-9]{1,4}:){1,7}:"
    r")(?![:\w])",
    re.IGNORECASE,
)

URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'\]\)}]+", re.IGNORECASE)

EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,24}\b", re.IGNORECASE)

DOMAIN = re.compile(
    r"\b(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,24}\b", re.IGNORECASE
)

MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)
SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)
SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)

CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Common file extensions that look like domains (name.ext) but are not. Used to
# cut obvious false positives from the domain matches.
FILE_EXTENSIONS = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jar",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf", "csv", "txt",
    "zip", "rar", "7z", "tar", "gz", "iso", "img",
    "png", "jpg", "jpeg", "gif", "bmp", "svg", "ico", "webp",
    "py", "html", "htm", "css", "php", "asp", "aspx", "json", "xml", "yml", "yaml",
    "md", "log", "conf", "ini", "dat", "bin", "dmp",
}

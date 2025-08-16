import pytest
from threat_intel.parsing import extract_iocs

def test_extract_ipv4():
    txt = "Suspicious IPs: 8.8.8.8 and 192.168.1.1; not 999.999.999.999"
    i = extract_iocs(txt)
    assert "8.8.8.8" in i["ipv4"]
    assert "192.168.1.1" in i["ipv4"]
    assert "999.999.999.999" not in i["ipv4"]

def test_extract_ipv6():
    txt = "IPv6 sample: 2001:0db8:85a3:0000:0000:8a2e:0370:7334 and FE80:0000:0000:0000:0202:B3FF:FE1E:8329"
    i = extract_iocs(txt)
    assert any(v.lower().startswith("2001:0db8") for v in i["ipv6"])
    assert any(v.lower().startswith("fe80:0000") for v in i["ipv6"])

def test_extract_domains_urls_emails_hashes():
    txt = '''
    Visit https://evil.example.com/path?q=1 and http://test.org
    Contact security@corp.co.uk
    Domains: krebsonsecurity.com, example.io
    MD5: d41d8cd98f00b204e9800998ecf8427e
    SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
    SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    '''
    i = extract_iocs(txt)
    assert "https://evil.example.com/path?q=1" in i["url"]
    assert "http://test.org" in i["url"]
    assert "security@corp.co.uk" in i["email"]
    assert "krebsonsecurity.com" in i["domain"]
    assert "example.io" in i["domain"]
    assert "d41d8cd98f00b204e9800998ecf8427e" in i["md5"]
    assert "da39a3ee5e6b4b0d3255bfef95601890afd80709" in i["sha1"]
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in i["sha256"]

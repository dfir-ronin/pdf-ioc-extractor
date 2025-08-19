import pytest
import json
from project import extract_and_refang_ips, extract_and_refang_url, output_files

def test_extract_and_refang_ips():
    text = '''The threat actor used the IP 8[.]8[.]8[.]8 and 1(dot)1(dot)1(dot)1
            and also used 192.168.1.1 which is private. '''
    result = extract_and_refang_ips(text)
    assert "8.8.8.8" in result
    assert "1.1.1.1" in result
    assert "192.168.1.1" not in result

def test_extract_and_refang_url():
    text = '''Visit hxxp://malicious[.]com/login or go to https://safe(dot)site[.]org/home. Also listed: malware.com, script(dot)js, phishing[.]site[.]xyz.'''

    result = extract_and_refang_url(text)

    assert "http://malicious.com/login" in result
    assert "https://safe.site.org/home" in result
    assert "malware.com" in result

def test_output_files(tmp_path):
    test_iocs = {
        "IP":["8.8.8.8"],
        "URL":["https://example.com"]
    }
    out_name = tmp_path/"testreport"
    output_files(test_iocs, str(out_name))

    txt_file = tmp_path/"testreport_iocs.txt"
    json_file = tmp_path/"testreport_iocs.json"

    assert txt_file.exists()
    assert json_file.exists()

    with open(json_file) as f:
        data = json.load(f)
        assert data == test_iocs




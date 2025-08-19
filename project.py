
import sys
import os
import json
from pdfminer.high_level import extract_text
import re
import ipaddress
import pyfiglet


''' Extract IOCs from PDF '''
def get_path():
     if len(sys.argv) > 1:
          return sys.argv[1]
     else:
          return input("Enter the full path of the pdf file: ")


def pdf_extract_ioc(path):
    print(f"Extract IOCs from: {path}")
    extracted_text = extract_text(path)

    print("Extracting IOCs..")
    return extracted_text

''' Extract & Refang IP Addresses from extracted_text'''
def extract_and_refang_ips(text):
    sep = r'(?:\.|\[\.]|\[dot\]|\(\.\)|\(dot\))'
    ip_pattern = rf'''
        \b
        (?:25[0-5]|2[0-4]\d|1?\d{{1,2}})
        {sep}
        (?:25[0-5]|2[0-4]\d|1?\d{{1,2}})
        {sep}
        (?:25[0-5]|2[0-4]\d|1?\d{{1,2}})
        {sep}
        (?:25[0-5]|2[0-4]\d|1?\d{{1,2}})
        \b
    '''

    def refang(ip):
        return (ip.replace("[.]", ".").replace("[dot]", ".").replace("(.)", ".").replace("(dot)", "."))

    def is_public_ip(ip):
        try:
            return ipaddress.ip_address(ip).is_global
        except ValueError:
            return False

    raw_matches = re.findall(ip_pattern, text, re.IGNORECASE | re.VERBOSE)
    refanged_ips = [refang(ip) for ip in raw_matches]
    public_ips = [ip for ip in refanged_ips if is_public_ip(ip)]
    return public_ips

def extract_and_refang_url(text):
    text = re.sub(r'\[\.\]|\(dot\)|\(\.\)', '.', text, flags=re.IGNORECASE)
    text = re.sub(r'\bhxxp(s?)://', r'http\1://', text, flags=re.IGNORECASE)
    #blocked_ext = r'(?:\.pdf|\.docx?|\.xlsx?|\.pptx?|\.exe|\.js|\.vbs|\.bat|\.scr|\.zip|\.rar|\.7z|\.dll|\.lnk)\b'
    url_pattern = r'''\b((?:https?|ftp)://[^\s/$.?#].[^\s]*|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})\b'''

    matches = re.findall(url_pattern, text, re.IGNORECASE | re.VERBOSE)

    return matches

''' Create an output txt and json file '''
def output_files(ioc_dict, out_name):
     txt_filename = out_name + "_iocs.txt"
     json_filename = out_name + "_iocs.json"

     with open(txt_filename, "w") as file:
          file.write("Extracted IOCs:\n")
          for ioc_type, ioc_list in ioc_dict.items():
               file.write(f"{ioc_type}:\n")
               for ioc in ioc_list:
                    file.write(f"{ioc}\n")
               file.write("\n")
          print(f"\n\nText report saved to: {txt_filename}")

     with open(json_filename, "w") as file:
          json.dump(ioc_dict, file, indent=2)
          print(f"JSON report saved to {json_filename}")

''' Main Function '''

def main():
    banner = pyfiglet.figlet_format("PDF IOC Extractor v1.0")
    print(banner)

    path = get_path()
    if not os.path.isfile(path):
        print(f"File not found!")
        sys.exit(1)

    extracted_text = pdf_extract_ioc(path)

    result_ip = extract_and_refang_ips(extracted_text)
    result_ip = sorted(set(result_ip))
    print("\n***IP Addresses***\n")
    for ip in result_ip:
          print(f"{ip}")

    result_url = extract_and_refang_url(extracted_text)
    result_url = sorted(set(result_url))
    print("\n***Domains & URLs***\n")
    for url in result_url:
         print(f"{url}")

    ioc_dict = {"IP":result_ip,"URL":result_url}

    out_name = os.path.splitext(os.path.basename(path))[0]
    output_files(ioc_dict, out_name)

if __name__ == "__main__":
        main()

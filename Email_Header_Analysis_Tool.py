import os
from email.parser import BytesParser
import pyfiglet
import re
import colorama
from colorama import Fore, Style
import hashlib
import requests
from langdetect import detect
colorama.init(autoreset=True)

API_KEY = input("Please Enter VT API :")


def extract_sender_ip(received_header):
    if received_header:
        ip_pattern = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|\[?(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\]?'
        ip_matches = re.findall(ip_pattern, received_header)
        if ip_matches:
            return ip_matches[0]
    return None


def parse_email_headers(file_path):
    with open(file_path, 'rb') as f:
        parser = BytesParser()
        msg = parser.parse(f)
    return msg


def analyze_email_headers(msg):
    reply_to_email_header = msg.get("Reply-To")
    received_email_header = extract_sender_ip(msg.get("Received"))
    to_email_header = msg.get("To")
    subject_email_header = msg.get("Subject")
    from_email_header = msg.get("From")
    return_path_email_header = msg.get("Return-Path")

    print("=== Email Header Analysis ===")
    print(
        f"{Fore.BLUE}Subject:{Style.RESET_ALL} {subject_email_header}\n\t{Fore.GREEN}- Refers to the title the sender has indicated in the subject line of the email.")
    print(
        f"{Fore.BLUE}From:{Style.RESET_ALL} {from_email_header}\n\t{Fore.GREEN}- Indicates the sender’s information, such as the address.")
    print(
        f"{Fore.BLUE}To:{Style.RESET_ALL} {to_email_header}\n\t{Fore.GREEN}- Displays the primary and secondary (CC, BCC) recipients’ email addresses and optional names.")
    print(
        f"{Fore.BLUE}Reply-To:{Style.RESET_ALL} {reply_to_email_header}\n\t{Fore.GREEN} - is an optional field, containing the address to which a recipient responds to.")

    print(
        f"{Fore.BLUE}Sender IP:{Style.RESET_ALL} {received_email_header}\n\t{Fore.GREEN}- Refers to the IP address from which the email was sent.")
    authentication_results_header = msg.get("Authentication-Results")
    print(
        f"{Fore.BLUE}Return-Path:{Style.RESET_ALL} {return_path_email_header}\n\t{Fore.GREEN}- Specifies the email address to which bounce notifications and other messages are to be sent.")

    if authentication_results_header:
        if "dkim=pass" in authentication_results_header.lower():
            dkim_status = f"{Fore.GREEN}Passed (Based on Authentication-Results header){Style.RESET_ALL}"
        else:
            dkim_status = f"{Fore.RED}fail (Based on Authentication-Results header){Style.RESET_ALL}"
        print(f"{Fore.BLUE}DKIM Validation:{Style.RESET_ALL} {dkim_status}")

        if "spf=pass" in authentication_results_header.lower():
            spf_status = f"{Fore.GREEN}Passed (Based on Authentication-Results header){Style.RESET_ALL}"
        else:
            spf_status = f"{Fore.RED}fail (Based on Authentication-Results header){Style.RESET_ALL}"
            print(f"{Fore.BLUE}SPF Validation:{Style.RESET_ALL} {spf_status}")

        if "dmarc=pass" in authentication_results_header.lower():
            dmarc_status = f"{Fore.GREEN}Passed (Based on Authentication-Results header){Style.RESET_ALL}"
        else:
            dmarc_status = f"{Fore.RED}fail (Based on Authentication-Results header){Style.RESET_ALL}"
            print(f"{Fore.BLUE}DMARC Validation:{Style.RESET_ALL} {dmarc_status}")
    else:
        dkim_header = msg.get("DKIM-Signature")
        if dkim_header:
            if "dkim=pass" in dkim_header.lower():
                dkim_status = f"{Fore.GREEN}pass (Based on Authentication-Results header){Style.RESET_ALL}"
            else:
                dkim_status = f"{Fore.RED}fail (Based on Authentication-Results header){Style.RESET_ALL}"
            print(f"{Fore.BLUE}DKIM Validation:{Style.RESET_ALL} {dkim_status}")
        else:
            print(f"{Fore.BLUE}DKIM Validation:{Style.RESET_ALL} Not found")
            print(f"{Fore.BLUE}SPF Validation:{Style.RESET_ALL} Not found")
            print(f"{Fore.BLUE}DMARC Validation:{Style.RESET_ALL} Not found")

    print(f"{Fore.LIGHTGREEN_EX}=== Additional X-Headers ==={Style.RESET_ALL}")
    for key, value in msg.items():
        if key.startswith("X-"):
            print(f"{Fore.YELLOW}{key}:{Style.RESET_ALL} {value}")
    print(f"{Fore.LIGHTGREEN_EX}=== Additional Header Information ==={Style.RESET_ALL}")
    for key, value in msg.items():
        if key.startswith("X-"):
            continue
        else:
            print(f"{Fore.YELLOW}{key}:{Style.RESET_ALL} {value}")

    print(f"{Fore.LIGHTGREEN_EX}=== Attachments and links information ==={Style.RESET_ALL}")
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == 'application' and part.get('Content-Disposition') is not None:
                filename = part.get_filename()
                print(f"{Fore.RED}Attachment Detected:{Style.RESET_ALL} {filename}")

                # Calculate hash of the attachment
                attachment_data = part.get_payload(decode=True)
                attachment_hash = hashlib.sha256(attachment_data).hexdigest()

                # Scan the hash on VirusTotal
                vt_result = scan_on_virustotal(attachment_hash, filename)
                if vt_result['found']:
                    if vt_result['malicious']:
                        print(f"{Fore.RED}Malicious Attachment Detected on VirusTotal:{Style.RESET_ALL} {filename}, {attachment_hash}")
                else:
                    print(f"{Fore.YELLOW}Attachment not found on VirusTotal:{Style.RESET_ALL} {filename}")

    for part in msg.walk():
        if part.get_content_maintype() == 'text':
            email_content = part.get_payload(decode=True).decode()
            links = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email_content)
            for link in links:
                print(f"{Fore.RED}Link was found : {link}")

            print(f"{Fore.LIGHTGREEN_EX}=== Language Information ==={Style.RESET_ALL}")
            language = detect(email_content)
            print(f"{Fore.BLUE}Language Detected:{Style.RESET_ALL} {language}")

    print("=== End of Email Analysis ===")


def scan_on_virustotal(hash, filename):
    url = f"https://www.virustotal.com/api/v3/files/{hash}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        if 'data' in data:
            attributes = data['data']['attributes']
            if 'last_analysis_stats' in attributes:
                stats = attributes['last_analysis_stats']
                malicious = stats['malicious']
                return {'found': True, 'malicious': malicious}
    return {'found': False}



def initialize():
    welcome_message = "Welcome To Email Header Analysis"
    ASCII_art_1 = pyfiglet.figlet_format(welcome_message)
    print(ASCII_art_1)

    print("🖨️ Hello, and thank you for choosing my tool! This tool is designed to provide you with relevant insights into email headers, "
      "attachments, and links contained within your emails. It's your all-in-one solution for comprehensive email analysis. 📧")
    target_file = input("Enter the path to the email file: ")
    target_file = os.path.abspath(target_file)

    if not os.path.exists(target_file):
        print("Error: The specified file does not exist.")
        return

    msg = parse_email_headers(target_file)
    analyze_email_headers(msg)


if __name__ == "__main__":
    initialize()

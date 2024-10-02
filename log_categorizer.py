import os
import re
import csv
import subprocess
import sys
from colorama import init, Fore, Style

# Initialize Colorama
init()

# Function to check and install required package
def install_package(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Check for Colorama package
try:
    import colorama
except ImportError:
    print(Fore.YELLOW + "Colorama not found. Installing..." + Style.RESET_ALL)
    install_package("colorama")
    import colorama

def categorize_attacks(log_line, patterns):
    matched_patterns = {}
    for attack_name, regex in patterns.items():
        if re.search(regex, log_line):
            matched_patterns[attack_name] = matched_patterns.get(attack_name, 0) + 1
    return matched_patterns

def extract_log_details(log_line):
    # Extract timestamp, source IP, and URL/URI from the log line
    timestamp_match = re.search(r'\[([^\]]+)\]', log_line)
    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log_line)
    url_match = re.search(r'(GET|POST|PUT|DELETE) (\S+)', log_line)

    timestamp = timestamp_match.group(1) if timestamp_match else "N/A"
    src_ip = ip_match.group(1) if ip_match else "N/A"
    url = url_match.group(2) if url_match else "N/A"

    return timestamp, src_ip, url

def analyze_logs(log_file, patterns):
    total_logs = 0
    multiple_matches = 0
    unrecognized_patterns_count = 0
    matched_entries = []
    unrecognized_patterns = []
    categorized_summary = {}

    with open(log_file, 'r') as file:
        logs = file.readlines()

    for log in logs:
        total_logs += 1
        matched_patterns = categorize_attacks(log, patterns)

        if matched_patterns:
            timestamp, src_ip, url = extract_log_details(log)
            for attack in matched_patterns:
                categorized_summary[attack] = categorized_summary.get(attack, 0) + 1
                matched_entries.append((timestamp, src_ip, url, attack))  # Store details

            if len(matched_patterns) > 1:
                multiple_matches += 1
        else:
            unrecognized_patterns_count += 1
            unrecognized_patterns.append(log.strip())

    return matched_entries, total_logs, multiple_matches, unrecognized_patterns_count, unrecognized_patterns, categorized_summary

def write_summary(matched_entries, categorized_summary, total_logs, multiple_matches, unrecognized_patterns_count, unrecognized_patterns):
    # Write to text file
    with open('attack_summary.txt', 'w') as txt_file:
        txt_file.write("Analysis Summary:\n")
        for attack, count in categorized_summary.items():
            txt_file.write(f"{attack}: {count}\n")
        txt_file.write(f"\nUnrecognized patterns found: {unrecognized_patterns_count}\n")
        for unrec_log in unrecognized_patterns:
            txt_file.write(f"Unrecognized Log Entry: {unrec_log}\n")
        txt_file.write(f"\nTotal logs analyzed: {total_logs}\n")
        txt_file.write(f"Total logs with multiple attack patterns matched: {multiple_matches}\n")
        
        # Include matched entries
        txt_file.write("\nMatched Entries:\n")
        for entry in matched_entries:
            txt_file.write(f"Timestamp: {entry[0]}, Source IP: {entry[1]}, URL: {entry[2]}, Attack Pattern: {entry[3]}\n")

    # Write to CSV file
    with open('attack_summary.csv', 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(['Timestamp', 'Source IP', 'URL', 'Matched Attack Pattern'])
        for entry in matched_entries:
            writer.writerow([entry[0], entry[1], entry[2], entry[3]])  # Write relevant details

def main():
    print(Fore.GREEN + "Welcome to the Log Analysis Tool!" + Style.RESET_ALL)
    print(Fore.GREEN + "This script analyzes log files for potential attack patterns." + Style.RESET_ALL)
    print(Fore.GREEN + "You can use built-in patterns or provide your own custom regex patterns." + Style.RESET_ALL)
    print(Fore.GREEN + "Let's get started!" + Style.RESET_ALL)

    # Description of pattern matching
    print(Fore.YELLOW + "\nHow Pattern Matching Works:" + Style.RESET_ALL)
    print(Fore.YELLOW + "The script uses regular expressions (regex) to identify specific patterns in log entries." + Style.RESET_ALL)
    print(Fore.YELLOW + "In this script, we define several common attack patterns as regex." + Style.RESET_ALL)
    print(Fore.YELLOW + "When analyzing the logs, the script checks each log entry against these patterns." + Style.RESET_ALL)
    print(Fore.YELLOW + "Multiple patterns can match the same log entry." + Style.RESET_ALL)

    # Available attack patterns
    attack_patterns = {
        "SQL Injection": r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE)\b)",
        "Cross-Site Scripting (XSS)": r"(<script|%3Cscript)",
        "Remote File Inclusion (RFI)": r"(http://|https://)",
        "Local File Inclusion (LFI)": r"(\.\./|%2E%2E)",
        "Command Injection": r"(\b(?:;|&|`||$)\b)",
        "Path Traversal": r"(\.\./|%2E%2E)",
        "Directory Traversal": r"(/etc/passwd|/proc/self/environ)",
        "Denial of Service (DoS)": r"(slowloris|flood|ping of death)",
        "Brute Force Attack": r"(login|password|user|pass)",
        "Malicious File Upload": r"(\.(php|jsp|asp|exe|sh)$)",
        "Malware Download": r"(eval\(|base64_decode|gzinflate|system|exec)",
    }

    print(Fore.BLUE + "Available Attack Patterns:" + Style.RESET_ALL)
    for name in attack_patterns:
        print(Fore.CYAN + f"- {name}" + Style.RESET_ALL)

    # Prompt for log file name
    log_file = input(Fore.YELLOW + "Please enter the name of the log file to analyze: " + Style.RESET_ALL)

    # Prompt for using built-in patterns or custom regex
    use_builtin = input(Fore.YELLOW + "Do you want to use the built-in patterns? (yes/no): " + Style.RESET_ALL)

    if use_builtin.lower() == 'yes':
        patterns = attack_patterns
    else:
        print(Fore.MAGENTA + "Please enter your custom regex pattern." + Style.RESET_ALL)
        custom_pattern = input(Fore.YELLOW + "Enter your custom regex pattern: " + Style.RESET_ALL)
        patterns = {"Custom Pattern": custom_pattern}

    # Analyze logs and categorize patterns
    matched_entries, total_logs, multiple_matches, unrecognized_patterns_count, unrecognized_patterns, categorized_summary = analyze_logs(log_file, patterns)

    # Write summary and results to files
    write_summary(matched_entries, categorized_summary, total_logs, multiple_matches, unrecognized_patterns_count, unrecognized_patterns)

    # Print analysis summary in console
    print(Fore.GREEN + "\nAnalysis Summary:" + Style.RESET_ALL)
    for attack, count in categorized_summary.items():
        print(Fore.GREEN + f"{attack}: {count}" + Style.RESET_ALL)

    print(Fore.RED + f"\nUnrecognized patterns found: {unrecognized_patterns_count}" + Style.RESET_ALL)
    for unrec_log in unrecognized_patterns:
        print(Fore.YELLOW + f"- {unrec_log}" + Style.RESET_ALL)

    print(Fore.BLUE + f"\nTotal logs analyzed: {total_logs}" + Style.RESET_ALL)
    print(Fore.BLUE + f"Total logs with multiple attack patterns matched: {multiple_matches}" + Style.RESET_ALL)
    print(Fore.GREEN + "\nResults have been written to 'attack_summary.csv' and 'attack_summary.txt'." + Style.RESET_ALL)

if __name__ == "__main__":
    main()


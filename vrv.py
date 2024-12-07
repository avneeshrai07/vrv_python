import re
from collections import defaultdict, Counter
import csv

# Function which parses the log file and extracts IPs, endpoints, and failed login attempts
def parse_log_file(log_file_path):
    ip_requests = defaultdict(int)
    endpoint_requests = defaultdict(int)
    failed_logins = defaultdict(int)

    # Regex patterns for parsing log file
    ip_pattern = r'(\d{1,3}(?:\.\d{1,3}){3})'
    endpoint_pattern = r'"[A-Z]+\s(/[^ ]*)'
    failed_login_pattern = r'(401|Invalid credentials)'

    with open(log_file_path, 'r') as file:
        for line in file:
            # Extract IP address
            ip_match = re.search(ip_pattern, line)
            if ip_match:
                ip = ip_match.group(1)
                ip_requests[ip] += 1

            # Extract endpoint
            endpoint_match = re.search(endpoint_pattern, line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_requests[endpoint] += 1

            # Check for failed login attempts
            if re.search(failed_login_pattern, line):
                if ip_match:
                    failed_logins[ip] += 1

    return ip_requests, endpoint_requests, failed_logins


# Function which analyzes and sorts IP requests by count
def analyze_requests(ip_requests):
    sorted_ip_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)
    return sorted_ip_requests


# Function which identifies the most accessed endpoint
def find_most_accessed_endpoint(endpoint_requests):
    if endpoint_requests:
        most_accessed_endpoint = max(endpoint_requests.items(), key=lambda x: x[1])
        return most_accessed_endpoint
    return None, 0


# Function which flags IPs exceeding the failed login threshold
def detect_suspicious_activity(log_file_path, threshold=3):
    failed_login_attempts = defaultdict(int)
    suspicious_ips = {}

    with open(log_file_path, 'r') as log_file:
        for line in log_file:
            if '401' in line or re.search(r"Invalid credentials", line, re.IGNORECASE):
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    ip_address = ip_match.group(1)
                    failed_login_attempts[ip_address] += 1

                    # Flag IPs exceeding the threshold
                    if failed_login_attempts[ip_address] > threshold:
                        suspicious_ips[ip_address] = failed_login_attempts[ip_address]

    return suspicious_ips


# Function which writes analysis results to a CSV file
def save_results_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP
        writer.writerow(["Requests per IP:"])
        for ip, count in ip_requests:
            writer.writerow([f"{ip:<20} {count}"])

        # Add a blank line for spacing
        writer.writerow([])

        # Write Most Frequently Accessed Endpoint
        writer.writerow(["Most Frequently Accessed Endpoint:"])
        writer.writerow([f"{most_accessed_endpoint[0]:<20} (Accessed {most_accessed_endpoint[1]} times)"])

        # Add a blank line for spacing
        writer.writerow([])

        # Write Suspicious Activity Detected
        writer.writerow(["Suspicious Activity Detected:"])
        writer.writerow(["IP Address           Failed Login Attempts"])
        for ip, count in suspicious_activity.items():
            writer.writerow([f"{ip:<20} {count}"])

        # Add a blank line for spacing at the end (optional)
        writer.writerow([])


# Function which runs the log analysis process
def main():
    log_file_path = input("Enter the path to the log file: ")

    output_file = "log_analysis_results.csv"

    # Parse log file
    ip_requests, endpoint_requests, failed_logins = parse_log_file(log_file_path)

    # Analyze requests
    sorted_ip_requests = analyze_requests(ip_requests)
    most_accessed_endpoint = find_most_accessed_endpoint(endpoint_requests)

    # Now pass the correct log file path to detect suspicious activity
    suspicious_activity = detect_suspicious_activity(log_file_path)

    # Display results with formatted output for suspicious activity
    print("\nRequests per IP:")
    for ip, count in sorted_ip_requests:
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts'}")
    for ip, count in suspicious_activity.items():
        print(f"{ip:<20} {count}")

    # Save results to CSV
    save_results_to_csv(sorted_ip_requests, most_accessed_endpoint, suspicious_activity, output_file)
    print(f"\nResults saved to {output_file}")


if __name__ == "__main__":
    main()

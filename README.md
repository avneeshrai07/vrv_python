# Log Analysis Script

This Python script analyzes web server log files to provide insights into user activity, endpoint access patterns, and potential security threats. It parses logs, analyzes activity, detects suspicious behavior, and exports results to a structured CSV file.

## Key Features

1. **Log Parsing**  
   Extracts key information from log files, including:
   - **IP Addresses:** Tracks request counts for each IP.
   - **Endpoints:** Identifies which endpoints (e.g., `/login`, `/home`) were accessed and their frequency.
   - **Failed Logins:** Detects failed login attempts using HTTP 401 errors or "Invalid credentials."

2. **Activity Analysis**  
   - Sorts IPs by the number of requests made.
   - Identifies the most frequently accessed endpoint.

3. **Suspicious Activity Detection**  
   Flags IPs exceeding a configurable threshold (default: 3) for failed login attempts.

4. **CSV Reporting**  
   Saves analysis results to a CSV file, including:
   - Requests per IP address.
   - The most frequently accessed endpoint.
   - Details of flagged suspicious activity.

5. **Dynamic Log File Input**  
   Accepts any log file path provided by the user, making the script reusable for different datasets.

## How It Works

1. **Log Parsing:**  
   The script reads the log file line by line and uses regex to extract relevant data like IP addresses, endpoints, and error messages.

2. **Analysis:**  
   It computes request counts per IP, determines the most accessed endpoints, and tracks failed login attempts.

3. **Detection:**  
   Any IP address with failed login attempts exceeding the threshold is flagged as suspicious.

4. **Exporting Results:**  
   Analysis results are saved to a `log_analysis_results.csv` file for offline review.

## Usage Instructions

1. Clone this repository and navigate to the script's directory.  
2. Run the script using Python:  
   ```bash
   python script_name.py
   ```
3. When prompted, provide the full path to the server log file.  
4. View the analysis in the terminal or check the `log_analysis_results.csv` for detailed results.

## Requirements

- Python 3.x
- Standard Python libraries: `re`, `collections`, `csv`

## Example Output

### Console Output:
```
Requests per IP:
192.168.0.1         120
10.0.0.2            85

Most Frequently Accessed Endpoint:
/login (Accessed 150 times)

Suspicious Activity Detected:
IP Address           Failed Login Attempts
192.168.0.5          5
```

### CSV File:
The results are saved in `log_analysis_results.csv` with the following structure:
- Requests per IP
- Most frequently accessed endpoint
- Suspicious activity (IP addresses and failed login attempts)

## License
This project is open-source and licensed under the MIT License.

---

This script is a practical tool for analyzing server logs, understanding user behavior, and identifying potential security threats.

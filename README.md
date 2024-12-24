# JenkinsVulnsFinder.py

## Overview
**JenkinsVulnsFinder** is a Python-based tool designed to scan Jenkins servers for common security vulnerabilities. It performs various security checks, including authentication methods, plugin details, job visibility, node details, anonymous access, and much more. The tool also supports brute-forcing credentials and directory/path enumeration.

## Features
- Detect Jenkins authentication type (RBAC, Matrix-based Security, or OAuth).
- Identify Jenkins version.
- Check for anonymous access and CSRF protection.
- Retrieve job visibility, node details, and stored credentials.
- Check plugin versions and updates.
- Brute-force Jenkins credentials using custom username and password lists.
- Perform directory/path enumeration with a wordlist.
- Generate results in CSV format for easy reporting.

## Usage

Run the script with the following options:

### General Options:
- `--url`: Jenkins Base URL (e.g., `http://localhost:8080`).
- `--urls`: File containing a list of Jenkins URLs to check.
- `--cred`: Credentials in the format `username:password`.
- `--nocred`: Use anonymous access (no credentials required).
- `--output`: Specify an output CSV file to save the results (optional).

### Brute-force Options:
- `--brute`: Enable brute-force credential checking.
- `--users`: File containing a list of usernames for brute-force.
- `--pass`: File containing a list of passwords for brute-force.

### Directory Search Options:
- `--dirb`: Directory or path brute-force wordlist file.

### Example Commands:

1. **Run the scanner with anonymous access:**
   ```bash
   python JenkinsVulnsFinder.py --url http://172.19.107.32:8080 --nocred
   ```

2. **Run the scanner with credentials:**
   ```bash
   python JenkinsVulnsFinder.py --url http://172.19.107.32:8080 --cred admin:password
   ```

3. **Run the scanner with brute-force enabled:**
   ```bash
   python JenkinsVulnsFinder.py --url http://172.19.107.32:8080 --nocred --brute --users users.txt --pass pass.txt
   ```

4. **Run the scanner with directory/path search:**
   ```bash
   python JenkinsVulnsFinder.py --url http://172.19.107.32:8080 --nocred --dirb wordlist.txt
   python JenkinsVulnsFinder.py --url http://172.19.107.32:8080 --cred --dirb wordlist.txt
   ```

## Output
The tool generates a CSV file with the following fields:
- URL
- Version
- Auth Type
- Anonymous Access
- CSRF Protection
- Job Visibility
- Script Console
- Node Details
- Uses HTTP
- Stored Credentials
- Log Access
- Audit Logs Enabled
- API Access
- CLI Access
- Anonymous Node Access
- Signup Allowed
- Plugins
- UnAuth Endpoints
- Brute-force Credentials
- Accessible Paths

Example of generated CSV:
```csv
URL,Version,Auth Type,Anonymous Access,CSRF Protection,Job Visibility,...
http://localhost:8080,2.361.1,RBAC,True,True,MyJob (url: http://localhost:8080/job/MyJob),...
```


# JenkinsScanner.sh

`JenkinsScanner.sh`, scans a list of IP addresses for open ports associated with Jenkins, identifies potential Jenkins instances, and saves the results for further analysis. It automates the following tasks:

1. **Check and Install Dependencies**: Ensures the necessary tools (`masscan`, `httpx`, and `jq`) are installed on your system.
2. **Masscan for Port Scanning**: Scans a list of IPs for open ports (defined by the user) using `masscan` to find potential Jenkins service endpoints.
3. **Httpx for URL Validation**: Uses `httpx` to filter out Jenkins instances by matching specific strings in HTTP/HTTPS responses.
4. **Extract Jenkins URLs**: Extracts URLs with "Jenkins" in the response and checks for login page titles like `Sign in [Jenkins]`.
5. **Output Results**: Saves a list of identified Jenkins instances to a file.

## Usage

```bash
./JenkinsScanner.sh -i <ip_list_file> -p <ports> [-o <output_file>]
```

### Options:

- `-i <ip_list_file>`: A file containing a list of IPs to scan (required).
- `-p <ports>`: The ports to scan (comma-separated or 'all') (required).
- `-o <output_file>`: Optional. The file to save the output (default: `JenkinsInstances_<current_time>.txt`).

### Example:

```bash
./JenkinsScanner.sh -i ip_list.txt -p 80,443,8443,8080,8010,8090,8085 -o jenkins_instances.txt
```

This command will scan the IPs listed in `ip_list.txt`, looking for open ports 80,443,8443,8080,8010,8090,8085 and will save the found Jenkins instances to `jenkins_instances.txt`.

## Notes
- Ensure you have the appropriate permissions or authorization to scan Jenkins servers.
- The tool is intended for ethical security assessments and learning purposes.
- Misuse of this tool can lead to legal consequences. Use responsibly.

## Contributing

Feel free to fork this repository, submit issues, and send pull requests to improve the functionality of the JenkinsVulnFinder.

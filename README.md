# JenkinsVulnFinder

This repository contains a set of scripts designed to find Jenkins instances and identify potential vulnerabilities associated with them. The First script, `JenkinsScanner.sh`, scans a list of IP addresses for open ports associated with Jenkins, identifies potential Jenkins instances, and saves the results for further analysis. Future scripts will focus on identifying vulnerabilities in the discovered Jenkins instances.

## JenkinsScanner.sh

The `JenkinsScanner.sh` script automates the following tasks:

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

## Future Scripts

In addition to `JenkinsScanner.sh`, this repository will include further scripts aimed at detecting vulnerabilities in the discovered Jenkins instances. Keep an eye on the repository for updates.

## Contributing

Feel free to fork this repository, submit issues, and send pull requests to improve the functionality of the JenkinsVulnFinder.

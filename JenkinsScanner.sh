#!/bin/bash

# Check if required tools are installed and install them if missing
check_and_install_tools() {
    # Check and install masscan
    if ! command -v masscan &> /dev/null; then
        echo "[+] Installing masscan..."
        sudo snap install masscan || { echo "Error: Failed to install masscan. Ensure snap is installed."; exit 1; }
    fi

    # Check and install httpx (install Go first if required)
    if ! command -v httpx &> /dev/null; then
        echo "[+] httpx not found. Installing dependencies..."

        # Check and install Golang
        if ! command -v go &> /dev/null; then
            echo "[+] Installing Golang..."
            sudo apt update && sudo apt install -y golang || { echo "Error: Failed to install Golang."; exit 1; }
        fi

        # Install httpx
        echo "[+] Installing httpx..."
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || { echo "Error: Failed to install httpx."; exit 1; }

        # Add Go bin to PATH if not already set
        export PATH=$PATH:$(go env GOPATH)/bin
        if ! command -v httpx &> /dev/null; then
            echo "Error: httpx installation failed. Ensure Go is correctly set up."
            exit 1
        fi
    fi

    # Check and install jq
    if ! command -v jq &> /dev/null; then
        echo "[+] Installing jq..."
        sudo apt update && sudo apt install -y jq || { echo "Error: Failed to install jq."; exit 1; }
    fi
}

check_and_install_tools


usage() {
    echo "Usage: $0 -i <ip_list_file> -p <ports> [-o <output_file>]"
    echo "  -i <ip_list_file>  : File containing list of IPs (required)"
    echo "  -p <ports>         : Ports to scan (comma-separated or 'all') (required)"
    echo "  -o <output_file>   : Optional output file name (default: output_<current_time>.csv)"
    exit 1
}

IP_LIST=""
PORTS=""
OUTPUT_FILE=""
MASSCAN_OUTPUT="masscan_output.txt"
HTTPX_INPUT="httpx_input.txt"
HTTPX_OUTPUT="httpx_output.txt"

while getopts "i:p:o:" opt; do
    case $opt in
        i) IP_LIST=$OPTARG ;;
        p) PORTS=$OPTARG ;;
        o) OUTPUT_FILE=$OPTARG ;;
        *) usage ;;
    esac
done

if [[ -z "$IP_LIST" || -z "$PORTS" ]]; then
    usage
fi

if [ -z "$OUTPUT_FILE" ]; then
    CURRENT_TIME=$(date +"%Y%m%d_%H%M%S")
    OUTPUT_FILE="JenkinsInstances_${CURRENT_TIME}.txt"
fi

# Run masscan
echo "[+] Running masscan on IP list: $IP_LIST with ports: $PORTS"
masscan -iL "$IP_LIST" -p"$PORTS" -oG "$MASSCAN_OUTPUT" --wait 0

if [ $? -ne 0 ]; then
    echo "Error: masscan failed. Exiting."
    exit 1
fi

echo "[+] Masscan complete. Output saved to $MASSCAN_OUTPUT"

# Parse masscan output to generate HTTP and HTTPS URLs
echo "[+] Parsing masscan output to generate HTTP and HTTPS URLs"

awk '
/Ports:/ {
    # Extract IP and Port from the masscan line
    match($0, /Host: ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*Ports: ([0-9]+)\/open\/tcp/, groups)
    if (groups[1] && groups[2]) {
        ip = groups[1]
        port = groups[2]
        print "http://" ip ":" port
        print "https://" ip ":" port
    }
}' "$MASSCAN_OUTPUT" | sort -u > "$HTTPX_INPUT"


# Check if URLs were generated
if [ ! -s "$HTTPX_INPUT" ]; then
    echo "[-] No valid URLs generated from masscan output. Exiting."
    exit 1
fi

echo "[+] HTTP and HTTPS URLs saved to $HTTPX_INPUT"

# Run httpx to search for 'Jenkins' in responses
echo "[+] Running httpx to check for 'Jenkins' in HTTP/HTTPS responses"
httpx -l "$HTTPX_INPUT" -match-string "Jenkins" -json > "$HTTPX_OUTPUT"

if [ $? -ne 0 ]; then
    echo "Error: httpx encountered an issue. Exiting."
    exit 1
fi
echo "[+] HTTPX scan complete"

# Check for 'Jenkins' in title tag if matched by httpx
echo "[+] Searching for 'Sign in [Jenkins]' in title tags for matching results"

while read -r line; do
    url=$(echo "$line" | jq -r '.url // empty')

    # Skip if no URL is found
    if [ -z "$url" ]; then
        continue
    fi

    # Fetch the page content and search for title with 'Sign in [Jenkins]'
    title=$(curl -s "$url/login?from=%2F" | sed -n 's/.*<title>\(.*\)<\/title>.*/\1/p' | grep -i 'Sign in \[Jenkins\]')
    if [ ! -z "$title" ]; then
        echo "$url" >> "$OUTPUT_FILE"
    fi
done < "$HTTPX_OUTPUT"

if [ -s "$OUTPUT_FILE" ]; then
    echo "[+] Jenkins instances saved to $OUTPUT_FILE"
else
    echo "[-] No Jenkins instances found."
fi

echo "[*] Script execution complete!"

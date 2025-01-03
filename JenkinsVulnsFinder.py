import requests
from requests.auth import HTTPBasicAuth
import argparse
import csv
from datetime import datetime

def detect_auth_type(base_url):
    auth_url = f"{base_url}/securityRealm/commenceLogin?from=%2F"
    try:
        response = requests.get(auth_url, allow_redirects=False)
        if response.status_code == 404:
            return "Matrix-Based Authorization"
        if response.status_code == 302:
            response = requests.get(auth_url, allow_redirects=True)
            #Update your Company name here
            if "Company Name" in response.text:
                    return "Company OAuth"
            return "Microsoft OAuth"
        elif response.status_code == 200:
            return "RBAC or OAuth"
        return "Unknown"
    except requests.RequestException as e:
        #print(f"Error during authentication type detection: {e}")
        return "Error Occured"

def get_jenkins_version(base_url):
    response = requests.get(base_url)
    if "X-Jenkins" in response.headers:
        return response.headers.get("X-Jenkins")
    return "Unknown"

def check_anonymous_access(base_url):
    response = requests.get(base_url)
    return response.status_code == 200

def check_plugins(base_url, auth, headers):
    plugins_url = f"{base_url}/pluginManager/api/json?depth=1"
    response = requests.get(plugins_url, auth=auth, headers=headers)
    if response.status_code == 200:
        plugins = response.json().get("plugins", [])
        return [(plugin['shortName'], plugin['version'], plugin.get('hasUpdate', False)) for plugin in plugins]
    return []

def check_csrf_protection(base_url, auth, headers):
    crumb_url = f"{base_url}/crumbIssuer/api/json"
    response = requests.get(crumb_url, auth=auth, headers=headers)
    return response.status_code == 200

def check_job_visibility(base_url, auth, headers):
    jobs_url = f"{base_url}/api/json?tree=jobs[name,url]"
    response = requests.get(jobs_url, auth=auth, headers=headers)
    if response.status_code == 200:
        jobs = response.json().get("jobs", [])
        job_details = []
        for job in jobs:
            name = job.get("name", "Unknown")
            url_data = job.get("url", "Unknown")
            job_details.append((name, url_data))
        return job_details
    return []

def check_script_console(base_url, auth, headers):
    console_url = f"{base_url}/script"
    response = requests.get(console_url, auth=auth, headers=headers)
    return response.status_code == 200

def check_nodes(base_url, auth, headers):
    nodes_url = f"{base_url}/computer/api/json"
    response = requests.get(nodes_url, auth=auth, headers=headers)
    if response.status_code == 200:
        try:
            nodes = response.json().get("computer", [])
            node_details = []
            for node in nodes:
                name = node.get("displayName", "Unknown")
                architecture = node.get("monitorData", {}).get("hudson.node_monitors.ArchitectureMonitor", "Unknown")
                node_details.append({
                    "name": name,
                    "architecture": architecture
                })
            return {"num_nodes": len(nodes), "nodes": node_details}
        except ValueError:
            print(f"Error: Response from {nodes_url} is not valid JSON")
    return {"num_nodes": 0, "nodes": []}

def check_http_usage(base_url):
    return base_url.lower().startswith("http://")

def check_stored_credentials(base_url, auth, headers):
    creds_url = f"{base_url}/credentials/store/system/domain/_/api/json?depth=1"
    response = requests.get(creds_url, auth=auth, headers=headers)
    if response.status_code == 200:
        credentials = response.json().get("credentials", [])
        creds_details = []
        for cred in credentials:
            cred_id = cred.get('id', 'Unknown ID')
            cred_name = cred.get('displayName', 'Unknown Name')
            cred_description = cred.get('description', 'No description')
            creds_details.append(f"{cred_name} (ID: {cred_id}, Description: {cred_description})")
        return creds_details
    return []

def check_log_access(base_url, auth, headers):
    log_url = f"{base_url}/log/all"
    response = requests.get(log_url, auth=auth, headers=headers)
    return response.status_code == 200

def check_audit_logs(base_url, auth, headers):
    audit_url = f"{base_url}/audit/api/json"
    response = requests.get(audit_url, auth=auth, headers=headers)
    return response.status_code == 200

def check_api_access(base_url, auth, headers):
    api_url = f"{base_url}/api/json"
    response = requests.get(api_url, auth=auth, headers=headers)
    return response.status_code == 200

def check_cli_access(base_url, auth, headers):
    cli_url = f"{base_url}/cli"
    response = requests.get(cli_url, auth=auth, headers=headers)
    return response.status_code == 200

def check_anonymous_node_access(base_url):
    nodes_url = f"{base_url}/computer/api/json"
    response = requests.get(nodes_url)
    return response.status_code == 200

def check_signup_allowed(base_url):
    signup_url = f"{base_url}/signup"
    response = requests.get(signup_url)
    return response.status_code == 200

def check_unauthenticated_endpoints(base_url):
    common_endpoints = [
        "/", "/login", "/signup", "/script", "/me/api/json", "/api/json", "/computer/api/json",
        "/env-vars.html", "/pluginManager/api/json", "/credentials/api/json", "/log/all", 
        "/updateCenter/api/json","/queue/api/json", "/pluginManager/checkUpdatesServer/api/json",
        "/pluginManager/api/json", "/whoAmI/api/json", "/crumbIssuer/api/json", "/overallLoad/api/json",
        "/queue/api/json"
    ]
    accessible_endpoints = []
    for endpoint in common_endpoints:
        full_url = f"{base_url.rstrip('/')}{endpoint}"
        response = requests.get(full_url)
        if response.status_code == 200:
            accessible_endpoints.append(full_url)
    return accessible_endpoints

def dir_search(base_url, paths_file, auth=None, headers=None):
    accessible_paths = []
    try:
        with open(paths_file, "r") as file:
            paths = [line.strip() for line in file if line.strip()]
            for path in paths:
                full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
                response = requests.get(full_url, auth=auth, headers=headers)
                if response.status_code == 200:
                    accessible_paths.append(full_url)
    except FileNotFoundError:
        print(f"Directory paths file not found: {paths_file}")
    return accessible_paths

def brute_force_credentials(base_url, user_list, pass_list):
    valid_credentials = []
    for user in user_list:
        for password in pass_list:
            auth = HTTPBasicAuth(user, password)
            response = requests.get(base_url, auth=auth)
            if response.status_code == 200:
                valid_credentials.append((user, password))
    return valid_credentials

def analyze_jenkins(base_url, auth,headers):
    results = {
        "URL": base_url,
        "Version": get_jenkins_version(base_url),
        "Auth Type": detect_auth_type(base_url),
        "Anonymous Access": check_anonymous_access(base_url),
        "CSRF Protection": check_csrf_protection(base_url, auth, headers),
        "Job Visibility": len(check_job_visibility(base_url, auth, headers)),
        "Script Console": check_script_console(base_url, auth, headers),
        "Node Details": len(check_nodes(base_url, auth, headers)),
        "Uses HTTP": check_http_usage(base_url),
        "Stored Credentials": check_stored_credentials(base_url, auth, headers),
        "Log Access": check_log_access(base_url, auth, headers),
        "Audit Logs Enabled": check_audit_logs(base_url, auth, headers),
        "API Access": check_api_access(base_url, auth, headers),
        "CLI Access": check_cli_access(base_url, auth, headers),
        "Anonymous Node Access": check_anonymous_node_access(base_url),
        "Signup Allowed": check_signup_allowed(base_url),
        "UnAuth Endpoints": ", ".join(check_unauthenticated_endpoints(base_url)) or "None"
    }
    try:
        node_data = check_nodes(base_url, auth,headers)
        if node_data["num_nodes"] > 0:
            node_details = ", ".join([f"{node['name']} (Architecture: {node['architecture']})" for node in node_data["nodes"]])
            results["Node Details"] = f"Total Nodes: {node_data['num_nodes']}. {node_details}"
        else:
            results["Node Details"] = "No Nodes Found"
    except Exception as e:
        print(f"Error in Node Details: {e}")
        results["Node Details"] = "Error retrieving node details"

    # Check job visibility and only list if more than 0 jobs are found
    jobs = check_job_visibility(base_url, auth, headers)
    if len(jobs) > 0:
        job_details = ", ".join([f"{job[0]} (url: {job[1]})" for job in jobs])
        results["Job Visibility"] = job_details
    else:
        results["Job Visibility"] = "None"

    # List stored credentials if more than 0
    creds_details = check_stored_credentials(base_url, auth,headers)
    if creds_details:
        results["Stored Credentials"] = ", ".join(creds_details)
    else:
        results["Stored Credentials"] = "None"

    return results

def save_to_csv(results, output_file):
    fieldnames = [
        "URL", "Version", "Auth Type", "Anonymous Access", "CSRF Protection", "Job Visibility",
        "Script Console", "Node Details", "Uses HTTP", 
        "Stored Credentials", "Log Access", "Audit Logs Enabled", "API Access", "CLI Access",
        "Anonymous Node Access", "Signup Allowed", "Plugins", "UnAuth Endpoints",  "Brute-force Credentials" ,
        "Accessible Paths"
    ]
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result)
def main():
    parser = argparse.ArgumentParser(
        description="""Jenkins Vulnerability Scanner - A tool to scan Jenkins servers for common security issues.

Examples of usage:
# Run the scanner with anonymous access:
python JenkinsVulnsFinder.py --url http://172.19.107.32:8080 --nocred 

# Run the scanner with credentials:
python JenkinsVulnsFinder.py --url http://172.19.107.32:8080 --cred username:password 

# Run the scanner with Cookie:
python JenkinsVulnsFinder.py --url http://172.19.107.32:8080 --cookie "JSESSIONID.bc33f838=node0icu313myoabe17tcvkdlhkmez1.node0;"

# Run the scanner with brute-force enabled:
python JenkinsVulnsFinder.py --url http://172.19.107.32:8080/ --nocred --brute --users users.txt --pass pass.txt

# Run Scanner with Directory/Path Search - Takes wordlist file as input
python JenkinsVulnsFinder.py --url http://172.19.107.32:8080 --nocred --dirb wordlist.txt
python JenkinsVulnsFinder.py --url http://172.19.107.32:8080 --cred --dirb wordlist.txt

""", formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("--url", help="Jenkins Base URL (e.g., http://localhost:8080)", required=False)
    parser.add_argument("--urls", help="File containing list of Jenkins URLs to check", required=False)
    parser.add_argument("--cred", help="Credentials in the format username:password", required=False)
    parser.add_argument("--nocred", action="store_true", help="Use anonymous access (no credentials required)", required=False)
    parser.add_argument("--cookie", help="Cookie string for authentication", required=False)
    
    parser.add_argument("--output", help="Output CSV file to save results (default will be generated with timestamp)", required=False)
    
    # Brute-force options
    parser.add_argument("--brute", action="store_true", help="Enable brute-force credential checking", required=False)
    parser.add_argument("--users", help="File containing list of usernames for brute force", required=False)
    parser.add_argument("--pass", dest="password", help="File containing list of passwords for brute force", required=False)
    
    # Directory search wordlist
    parser.add_argument("--dirb", help="Directory or Path brute-force wordlist file", type=str, required=False)
    
    args = parser.parse_args()

    # Ensure either --cred, --nocred, or --cookie is passed along with --url or --urls
    if not ((args.nocred or args.cred or args.cookie) and (args.url or args.urls)):
        parser.print_help()
        print("\nERROR: Either --cred, --nocred, or --cookie must be specified, and either --url or --urls must be provided.")
        return

    auth = None
    headers = {}

    if args.cookie:
        headers['Cookie'] = args.cookie
        print("Using authentication via cookies...")
    elif args.nocred:
        print("Using anonymous access...")
    elif args.cred:
        try:
            username, password = args.cred.split(":", 1)
            auth = HTTPBasicAuth(username, password)
        except ValueError:
            print("Invalid credentials format. Use username:password.")
            return
    else:
        print("Either --cred, --nocred, or --cookie must be specified.")
        return

    urls = []
    if args.url:
        urls.append(args.url.strip())
    if args.urls:
        try:
            with open(args.urls, "r") as file:
                urls.extend([line.strip() for line in file if line.strip()])
        except FileNotFoundError:
            print(f"File not found: {args.urls}")
            return

    if not urls:
        print("No URLs provided.")
        return

    output_file = args.output or f"Output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

     # Default brute-force lists
    default_users = ["admin", "user", "jenkins"]
    default_pass = ["admin","jenkins", "password", "123456","User"]

    # Use custom brute-force lists if provided
    if args.brute:
        user_list = default_users
        pass_list = default_pass

        if args.users:
            try:
                with open(args.users, "r") as file:
                    user_list = [line.strip() for line in file if line.strip()]
            except FileNotFoundError:
                print(f"User file not found: {args.users}. Using default list.")

        if args.password:
            try:
                with open(args.password, "r") as file:
                    pass_list = [line.strip() for line in file if line.strip()]
            except FileNotFoundError:
                print(f"Password file not found: {args.password}. Using default list.")

    results = []
    for url in urls:
        print(f"Analyzing {url}...")
        try:
            result = analyze_jenkins(url, auth, headers)

            # Fetch plugin details for CSV
            plugins = check_plugins(url, auth, headers)
            plugin_details = "; ".join([f"{name} (v{version}, Update: {has_update})" for name, version, has_update in plugins])
            result["Plugins"] = plugin_details

            if args.brute:
                valid_credentials = brute_force_credentials(url, user_list, pass_list)
                result["Brute-force Credentials"] = ", ".join([f"{user}:{password}" for user, password in valid_credentials]) or "None"

            if args.dirb:
                accessible_paths  = dir_search(url,args.dirb, auth, headers)
                if accessible_paths: 
                    for path in accessible_paths:
                        result["Accessible Paths"] = ", ".join(accessible_paths)

            results.append(result)
        except Exception as e:
            print(f"Error analyzing {url}: {e}")

    save_to_csv(results, output_file)
    print(f"Results saved to {output_file}")

if __name__ == "__main__":
    main()

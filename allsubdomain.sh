#!/bin/bash

# Default values
subspath="$PWD"
maindomain=""
roots_list=""
output_dir="subs"

# Help message
help_message() {
    echo "Usage: $0 [-d <main_domain>] [-r <roots_list_file>] [-o <output_directory>]"
    echo "Options:"
    echo "  -d <main_domain>         Specify the main domain to perform subdomain enumeration."
    echo "  -r <roots_list_file>    Specify a file containing a list of root domains to enumerate."
    echo "  -o <output_directory>   Specify the output directory (default: subs)."
    echo "  -h                      Display this help message."
}

# Parse command-line options
while getopts "d:r:o:h" opt; do
    case "${opt}" in
        d)
            maindomain="${OPTARG}"
            ;;
        r)
            roots_list="${OPTARG}"
            ;;
        o)
            output_dir="${OPTARG}"
            ;;
        h)
            help_message
            exit 0
            ;;
        *)
            echo "Invalid option: -$OPTARG" >&2
            help_message
            exit 1
            ;;
    esac
done

# Function to create output directory if it doesn't exist
create_output_directory() {
    local directory="$1"
    if [ -d "$directory" ]; then
        echo "Directory '$directory' already exists."
    else
        echo "Creating directory '$directory'."
        mkdir "$directory"
    fi
}

# Function to perform subdomain enumeration using various tools
perform_subdomain_enum() {
    local domain="$1"
    local output_directory="$2"

    echo "Running sublist3r for $domain"
    python3 /root/Sublist3r/sublist3r.py -d "$domain" -o "$output_directory/sublist3r"

    echo "Running subfinder for $domain"
    subfinder -d "$domain" -all -o "$output_directory/subfinder"

    echo "Running shuffledns for bruteforcing on $domain"
    shuffledns -d "$domain" -w /root/dirword -r /root/resolver -t 3000 -v -o "$output_directory/brute"

    echo "Running amass for $domain"
    amass enum -active -d "$domain" -rf /root/resolver -dns-qps 400 -timeout 90 -max-dns-queries 25000 -o "$output_directory/amass.txt"
}

# Function to combine and deduplicate results
combine_deduplicate() {
    local output_directory="$1"
    cat "$output_directory/amass.txt" "$output_directory/sublist3r" "$output_directory/brute" "$output_directory/subfinder" | sort -u > "$output_directory/allnone_filter_subs"
}

# Function to perform httpx for live subs
perform_httpx() {
    local input_file="$1"
    local output_directory="$2"

    echo "Running httpx on $input_file"
    httpx -l "$input_file" -sc -o "$output_directory/httpx"
}

# Function to sort subs based on HTTP status codes
sort_subs_by_status() {
    local input_file="$1"
    local output_directory="$2"

    grep '2[0-9]'  "$input_file" | awk -F '[' '{print$1}' > "$output_directory/host_200.txt"
    grep '4[0-9]'  "$input_file" | awk -F '[' '{print$1}' > "$output_directory/host_400.txt"
    cat "$input_file" | awk -F '[' '{print$1}' |awk -F '//' '{print$2}' > "$output_directory/all_host.txt"
}

# Function to check for subdomain takeover
check_subdomain_takeover() {
    local all_host_file="$1"
    local output_directory="$2"

    echo "Running subzy for subdomain takeover check"
    subzy run --targets "$all_host_file" --hide_fails | tee "$output_directory/takeover"
}

# Function to perform S3 bucket scanning
perform_s3_scan() {
    local all_host_file="$1"
    local output_directory="$2"

    echo "Running s3scanner for AWS S3 bucket check"
    s3scanner -bucket-file "$all_host_file" | grep exists | tee "$output_directory/aws"
}

# Function to perform CVE scanning using nuclei
perform_cve_scan() {
    local all_host_file="$1"
    local output_directory="$2"

    echo "Running nuclei for CVE scanning"
    nuclei -l "$all_host_file" -t /root/nuclei-templates/ -s critical,high,medium -o "$output_directory/nuclei"
}

# Function to capture screenshots using aquatone
capture_screenshots() {
    local all_host_file="$1"
    local output_directory="$2"

    echo "Running aquatone for capturing screenshots"
    cat "$all_host_file" | aquatone -ports 80,81,300,443,591,593,832,981,1010,1311,2082,2087,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5800,6543,7000,7396,7474,8000,8001,8008,8014,8042,8069,8080,8081,8088,8090,8091,8118,8123,8172,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,12443,16080,18091,18092,20720,28017 -out "$output_directory/screenshots"
}

# Main execution
create_output_directory "$output_dir"

if [ -n "$maindomain" ]; then
    perform_subdomain_enum "$maindomain" "$output_dir"
elif [ -n "$roots_list" ]; then
    while read -r domain; do
        perform_subdomain_enum "$domain" "$output_dir"
    done < "$roots_list"
fi

combine_deduplicate "$output_dir"

perform_httpx "$output_dir/allnone_filter_subs" "$output_dir"

sort_subs_by_status "$output_dir/httpx" "$output_dir"

check_subdomain_takeover "$output_dir/allnone_filter_subs" "$output_dir"

perform_s3_scan "$output_dir/allnone_filter_subs" "$output_dir"

perform_cve_scan "$output_dir/all_host.txt" "$output_dir"

capture_screenshots "$output_dir/all_host.txt" "$output_dir"

echo "Script completed. Results saved to $output_dir."
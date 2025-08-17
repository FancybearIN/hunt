#!/bin/bash

# VirusTotal API key
API_KEY="834a3eef1c74c2977b7d5230e06ba6cba023fc81b39e63bb19d757140f72569d"

# Create output directory in current path
mkdir -p ./vrustotal

# Check if input file provided
if [ -z "$1" ]; then
    echo "Usage: $0 domains.txt"
    exit 1
fi

# Read domains from file
while IFS= read -r domain || [[ -n "$domain" ]]; do
    echo "🔍 Checking domain: $domain"

    # Send API request
    response=$(curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=$API_KEY&domain=$domain")

    # Extract and display basic info
    detected_urls=$(echo "$response" | jq '.detected_urls | length')
    categories=$(echo "$response" | jq -r '.categories // "N/A"')
    whois=$(echo "$response" | jq -r '.whois_date // "N/A"')

    echo "  📁 Detected URLs: $detected_urls"
    echo "  🏷️  Categories: $categories"
    echo "  🕒 WHOIS Date: $whois"
    echo "-------------------------------"

    # Save output in ./vrustotal/domain.txt
    {
        echo "Domain: $domain"
        echo "Detected URLs: $detected_urls"
        echo "Categories: $categories"
        echo "WHOIS Date: $whois"
        echo "-----------------------------"
    } > "./vrustotal/${domain}.txt"

    # Optional sleep to avoid rate limit
    sleep 15
done < "$1"


#!/bin/bash

ARCHIVISTA_SERVER_URL="http://localhost:8090"

go build -o archivista-data-provider .




#start the server
echo "Starting server..."
./archivista-data-provider serve --archivista-url=$ARCHIVISTA_SERVER_URL &
sleep 5

# Test the server

# Define the server's base URL
base_url="http://localhost:8090"

echo "Running curl commands to test server at $base_url"

# Test the /gatekeeper/validate endpoint with a POST request
echo -e "\n\nSending POST request to /gatekeeper/validate endpoint..."
curl -X POST -H "Content-Type: application/json" -d '<json_body>' $base_url/gatekeeper/validate

# Test the server's behavior with methods other than POST
echo -e "\n\nSending GET request to /gatekeeper/validate endpoint..."
curl -X GET $base_url/gatekeeper/validate

# Test server's behavior with a POST request with an empty body
echo -e "\n\nSending POST request with an empty body to /gatekeeper/validate endpoint..."
curl -X POST -H "Content-Type: application/json" -d '' $base_url/gatekeeper/validate

echo -e "\n\nFinished testing"

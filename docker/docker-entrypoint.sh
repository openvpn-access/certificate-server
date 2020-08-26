#!/bin/bash

CONFIG_FILE=/config/certificate-server.json

# Check if configuration file exists
if [[ ! -f $CONFIG_FILE ]]; then
    echo "No configuration file available..."
    echo "Copying default config..."

    cp /opt/app/default-config.json $CONFIG_FILE
fi

# Start certificate-server
while [ true ]
do
    echo "Starting certificate-server..."
    # shellcheck disable=SC2046
    /opt/app/certificate_server --port=$(jq -r .port $CONFIG_FILE) \
                                --cpu_cores=$(jq -r .cpu_cores $CONFIG_FILE) \
                                --ca_cert=$(jq -r .pki.ca_cert $CONFIG_FILE) \
                                --ca_key=$(jq -r .pki.ca_key $CONFIG_FILE) \
                                --ta=$(jq -r .pki.ta $CONFIG_FILE)

    if [[ ! $? -eq 0 ]]; then
        echo "certificate-server crashed... Restarting in 5 seconds..."
        sleep 3
    else
        exit 0
    fi
done


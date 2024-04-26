#!/usr/bin/env bash

id=$(cat /proc/sys/kernel/random/uuid | tr -d '-' | base64 | cut -b 1-22)
echo $id
#!/usr/bin/env bash

files=("diploma" "elm" "microcredential" "pda1" "ehic" "pid")

for file in "${files[@]}"; do
    printf "\nSyncing vctm_%s.json...\n" "$file"
    remote="../vc-ops/interop-common/overlay/opt/vc/metadata/vctm_$file.json"
    local="metadata/vctm_$file.json"

    rsync -avz --progress "$local" "$remote"

    remoteS256=$(sha256sum $remote)
    localS256=$(sha256sum $local)
    printf "\nRemote SHA256: %s\nLocal SHA256: %s\n" "$remoteS256" "$localS256"
done
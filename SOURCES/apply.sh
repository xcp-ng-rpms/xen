#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROGRESS_FILE="${SCRIPT_DIR}/applied_patches.log"
SPEC_FILE="${SCRIPT_DIR}/../SPECS/xen.spec"

cd "${SCRIPT_DIR}/xen-4.20.2.git" || exit 1

touch "${PROGRESS_FILE}"

for i in $(grep -E "^Patch[0-9]" "${SPEC_FILE}" | grep -v "#" | awk '{ print $2 }'); do
    if grep -qxF "${i}" "${PROGRESS_FILE}"; then
        echo "Skipping already applied: ${i}"
        continue
    fi

    FORMAT=$(grep "^From" "${SCRIPT_DIR}/${i}")

    if [[ -z "${FORMAT}" ]]; then
        echo "Applying (git apply): ${i}"
        if ! git apply "${SCRIPT_DIR}/${i}"; then
            git reset --hard HEAD
            exit 1
        fi
        git add -f .
        git commit -m "${i}"
    else
        echo "Applying (git am): ${i}"
        if ! git am "${SCRIPT_DIR}/${i}"; then
            git am --abort
            exit 1
        fi
    fi

    echo "${i}" >> "${PROGRESS_FILE}"
    echo "Recorded: ${i}"
done

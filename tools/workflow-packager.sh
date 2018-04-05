#!/usr/bin/env bash

readonly workflow_src_dir="../src"

if [[ ! -f "${workflow_src_dir}/info.plist" ]]; then
  echo "You need to be inside the workflow’s tools directory." >&2
  exit 1
fi

readonly workflow_name="$(/usr/libexec/PlistBuddy -c 'print name' "${workflow_src_dir}/info.plist")"
readonly workflow_file="${HOME}/Downloads/${workflow_name}.alfredworkflow" # CHANGE me

readonly workflow_dir_to_package="${workflow_src_dir}"

if DITTONORSRC=1 ditto -ck "${workflow_dir_to_package}" "${workflow_file}"; then
  echo "Created ${workflow_file}" >&1
  exit 0
else
  echo "There was an error creating ${workflow_file}." >&2
  exit 1
fi

#!/bin/bash

# Get the version parameter from the Makefile
new_tag="$1"
latest_tag="$2"

# Get commit messages since the latest tag
commit_messages=$(git log --pretty=format:"%s" "$latest_tag"..HEAD)

# Define changelog entry
changelog_entry="nasp-kernel-module ($new_tag) unstable; urgency=medium\n"

while IFS= read -r line; do
  changelog_entry+="\n  * $line"
done <<< "$commit_messages"

changelog_entry+="\n\n -- Nasp maintainers <team@nasp.io>  $(date -R)"

sed -i '' '1s/^/'"$changelog_entry"'\n\n/' debian/changelog


# Update the Readme and the dkms.conf
sed -i '' 's/PACKAGE_VERSION=".*"/PACKAGE_VERSION="'"$new_tag"'"/' dkms.conf
sed -i '' 's/github.com\/cisco-open\/nasp-kernel-module.git \/usr\/src\/nasp-.*\//github.com\/cisco-open\/nasp-kernel-module.git \/usr\/src\/nasp-'"$new_tag"'\//' README.md; \
sed -i '' 's/sudo dkms add -m nasp -v .*$/sudo dkms add -m nasp -v '"$new_tag"'/' README.md; \
sed -i '' 's/sudo dkms install -m nasp -v .*$/sudo dkms install -m nasp -v '"$new_tag"'/' README.md; \
sed -i '' 's/sudo modprobe nasp/sudo modprobe nasp -v '"$new_tag"'/' README.md; \
sed -i '' 's/sudo modprobe -r nasp/sudo modprobe -r nasp -v '"$new_tag"'/' README.md; \
sed -i '' 's/sudo dkms uninstall -m nasp -v .*$/sudo dkms uninstall -m nasp -v '"$new_tag"'/' README.md; \
sed -i '' 's/sudo dkms remove -m nasp -v .*$/sudo dkms remove -m nasp -v '"$new_tag"'/' README.md
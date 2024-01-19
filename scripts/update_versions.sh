#!/bin/bash

# Get the version parameter from the Makefile
new_tag="$1"
latest_tag="$2"

# Get commit messages since the latest tag
commit_messages=$(git --no-pager log --pretty=format:"%s" "$latest_tag"..HEAD)

# Define changelog entry
changelog_entry="camblet-driver ($new_tag) unstable; urgency=medium\n"

while IFS= read -r line; do
  changelog_entry+="\n  * $line"
done <<< "$commit_messages"

changelog_entry+="\n\n -- Camblet maintainers <team@camblet.io>  $(date -R)"

escaped_changelog_entry=$(printf "%s" "$changelog_entry" | sed 's/\//\\&/g')
sed -i '' "1s/^/$escaped_changelog_entry\\n\\n/" debian/changelog

# Update the dkms.conf
sed -i '' 's/PACKAGE_VERSION=".*"/PACKAGE_VERSION="'"$new_tag"'"/' dkms.conf
# Update the kernel-module.spec
sed -i '' 's/Version:        .*/Version:        '"$new_tag"'/' rpmbuild/SPECS/camblet-driver.spec
# Update the main.c
sed -i '' 's/MODULE_VERSION(".*")/MODULE_VERSION("'"$new_tag"'")/' main.c
# Update the Readme.md
sed -i '' 's/github.com\/cisco-open\/camblet-driver.git \/usr\/src\/camblet-.*\//github.com\/cisco-open\/camblet-driver.git \/usr\/src\/camblet-'"$new_tag"'\//' README.md; \
sed -i '' 's/sudo dkms add -m camblet -v .*$/sudo dkms add -m camblet -v '"$new_tag"'/' README.md; \
sed -i '' 's/sudo dkms install -m camblet -v .*$/sudo dkms install -m camblet -v '"$new_tag"'/' README.md; \
sed -i '' 's/sudo dkms uninstall -m camblet -v .*$/sudo dkms uninstall -m camblet -v '"$new_tag"'/' README.md; \
sed -i '' 's/sudo dkms remove -m camblet -v .*$/sudo dkms remove -m camblet -v '"$new_tag"'/' README.md

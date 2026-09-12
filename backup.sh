#!/bin/bash
# Back up the project to GitHub.
#
# Usage:  ./backup.sh "what changed"
#
# Credentials come from the macOS keychain. The first push will ask for a
# username and password; use your GitHub username and a Personal Access Token
# as the password. The keychain remembers it after that, so the token never
# needs to be typed again and never appears in any file.
set -e
cd "$(dirname "$0")"

MSG="${1:-Update project files}"

if [ -z "$(git status --porcelain)" ]; then
    echo "Nothing has changed - no backup needed."
    exit 0
fi

echo "==> Changes to be backed up:"
git status --short

git add -A
git commit -q -m "$MSG"
git push -q origin main
echo "==> Backed up to https://github.com/MaheshwariKushagra/securepi-gateway"

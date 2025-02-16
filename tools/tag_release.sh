#!/bin/bash

# Get the git repository root directory
GIT_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"
if [ $? -ne 0 ]; then
    echo "Error: Not in a git repository"
    exit 1
fi

# Check if a version number was provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <new_version>"
    echo "Example: $0 0.70.8"
    exit 1
fi

NEW_VERSION=$1

# Create and push tag
git tag -a "v$NEW_VERSION" -m "Release version $NEW_VERSION"
git push origin "v$NEW_VERSION"  
 
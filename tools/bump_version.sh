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

# Validate version format (should be numbers separated by dots)
if ! [[ $NEW_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version must be in format X.Y.Z (e.g., 0.70.8)"
    exit 1
fi

# Check if klp.py exists in the repository root
if [ ! -f "$GIT_ROOT/klp.py" ]; then
    echo "Error: klp.py not found in repository root"
    exit 1
fi

# Make sure we're on dev branch
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "dev" ]; then
    echo "Error: Must be on dev branch to create a release"
    exit 1
fi

# Change to repository root for all operations
cd "$GIT_ROOT" || exit 1

# Update version in klp.py
if ! sed -i.bak "s/__version__ = \".*\"/__version__ = \"$NEW_VERSION\"/" klp.py; then
    echo "Error: Failed to update version in klp.py"
    rm -f klp.py.bak
    exit 1
fi
rm -f klp.py.bak

# Check if changes were made
if ! git diff --quiet klp.py; then
    # Commit the changes
    git add klp.py
    git commit -m "Bump version to $NEW_VERSION"
else
    echo "No changes needed - version already set to $NEW_VERSION"
fi


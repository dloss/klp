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

# Make sure we're up to date
echo "Pulling latest changes from dev..."
git pull origin dev || exit 1

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
    git push origin dev
    
    # Create PR
    echo "Changes pushed to dev. Please:"
    echo "1. Create a Pull Request from dev to main"
    echo "2. Wait for tests to pass"
    echo "3. Merge the PR"
    echo "4. Press ENTER when the PR is merged to create the tag automatically"
    read

    # Switch to main and update
    git checkout main
    git pull origin main

    # Verify the version change is in main
    if ! grep -q "__version__ = \"$NEW_VERSION\"" klp.py; then
        echo "Error: Version change not found in main branch. Has the PR been merged?"
        exit 1
    fi

    # Create and push tag
    git tag -a "v$NEW_VERSION" -m "Release version $NEW_VERSION"
    git push origin "v$NEW_VERSION"
    
    echo "Successfully:"
    echo "- Updated version to $NEW_VERSION in klp.py"
    echo "- Created and pushed tag v$NEW_VERSION"
    echo "- Release workflow should now be running"
    
    # Switch back to dev
    git checkout dev
else
    echo "No changes needed - version already set to $NEW_VERSION"
fi
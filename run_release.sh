#!/usr/bin/env bash

set -eo pipefail

# Resolve repository root directory
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

echo "=========================================="
echo " ACME CA Server - Release Workflow"
echo "=========================================="

# 0. Safety Check: Verify working tree is clean
if [ -n "$(git status --porcelain)" ]; then
    echo ""
    echo "Error: Uncommitted changes detected in working tree." >&2
    echo "Please commit or stash your changes before releasing." >&2
    echo ""
    git status -s
    exit 1
fi

# 1. Run lint checks
LINT_SCRIPT="$REPO_DIR/run_lint.sh"
if [ ! -f "$LINT_SCRIPT" ]; then
    echo "Error: Lint script not found at $LINT_SCRIPT" >&2
    exit 1
fi

echo ""
echo "--> Running code quality and lint checks (run_lint.sh)..."
if ! bash "$LINT_SCRIPT"; then
    echo ""
    echo "Error: run_lint.sh failed. Release aborted." >&2
    exit 1
fi
echo "--> All lint checks passed successfully."

# 2. Display recent release tags
echo ""
echo "=========================================="
echo " Recent Release Tags"
echo "=========================================="
git tag -l | tail -n 5
echo "------------------------------------------"

LAST_TAG="$(git tag -l | tail -n 1)"

# 3. Prompt for next release name
echo ""
read -r -p "Enter the next release tag (e.g., v0.8.2): " NEXT_TAG

if [ -z "$NEXT_TAG" ]; then
    echo "Error: Release tag cannot be empty. Aborted." >&2
    exit 1
fi

# 4. Handle release tagging
if [ "$NEXT_TAG" = "$LAST_TAG" ]; then
    echo ""
    echo "Notice: '$NEXT_TAG' matches the last release tag."
    echo "Select an action:"
    echo "  1) Rename tag message"
    echo "  2) Re-push tag"
    echo "  3) Cancel"
    read -r -p "Choose an option [1-3]: " ACTION_CHOICE

    case "$ACTION_CHOICE" in
        1)
            echo ""
            read -r -p "Enter new tag description/message: " NEW_MSG
            if [ -z "$NEW_MSG" ]; then
                echo "Error: Tag message cannot be empty when renaming. Aborted." >&2
                exit 1
            fi
            echo "--> Updating tag '$NEXT_TAG' message..."
            git tag -f -a "$NEXT_TAG" -m "$NEW_MSG"
            echo "--> Force-pushing tag to origin..."
            git push origin "$NEXT_TAG" --force
            echo "--> Tag '$NEXT_TAG' successfully updated and force-pushed."
            ;;
        2)
            echo ""
            echo "--> Re-pushing tag '$NEXT_TAG'..."
            echo "--> Deleting local tag..."
            git tag -d "$NEXT_TAG"
            echo "--> Deleting remote tag on origin..."
            git push origin ":refs/tags/$NEXT_TAG"
            echo "--> Recreating local tag..."
            git tag "$NEXT_TAG"
            echo "--> Pushing tag to origin..."
            git push origin "$NEXT_TAG"
            echo "--> Tag '$NEXT_TAG' successfully re-pushed."
            ;;
        *)
            echo "Release action cancelled."
            exit 0
            ;;
    esac
else
    # New release tag
    echo ""
    read -r -p "Enter release message (optional, press Enter for lightweight tag): " TAG_MSG
    echo ""
    if [ -n "$TAG_MSG" ]; then
        echo "--> Creating annotated tag '$NEXT_TAG'..."
        git tag -a "$NEXT_TAG" -m "$TAG_MSG"
    else
        echo "--> Creating lightweight tag '$NEXT_TAG'..."
        git tag "$NEXT_TAG"
    fi

    echo "--> Pushing tag '$NEXT_TAG' to origin..."
    git push origin "$NEXT_TAG"
    echo "--> Release '$NEXT_TAG' successfully tagged and pushed."
fi

echo ""
echo "=========================================="
echo " Release workflow completed successfully!"
echo " Current commit: $(git rev-parse --short HEAD)"
echo " Tag: $NEXT_TAG"
echo "=========================================="

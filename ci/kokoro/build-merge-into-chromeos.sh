#!/bin/bash
# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
set -e
cd "${KOKORO_ARTIFACTS_DIR}/git/crosvm"

readonly GERRIT_URL=https://chromium-review.googlesource.com
readonly ORIGIN=${GERRIT_URL}/chromiumos/platform/crosvm
readonly RETRIES=3

gerrit_api() {
    # Call gerrit API. Strips XSSI protection line from output.
    # See: https://gerrit-review.googlesource.com/Documentation/dev-rest-api.html
    local url="${GERRIT_URL}/${1}"
    curl --silent "$url" | tail -n +2
}

query_change() {
    # Query gerrit for a specific change.
    # See: https://gerrit-review.googlesource.com/Documentation/rest-api-changes.html#get-change
    gerrit_api "changes/$1/?o=CURRENT_REVISION"
}

query_changes() {
    # Query gerrit for a list of changes.
    # See: https://gerrit-review.googlesource.com/Documentation/rest-api-changes.html#list-changes
    local query=$(printf '%s+' "$@")
    gerrit_api "changes/?q=${query}"
}

query_related_changes() {
    # Query related changes from gerrit.
    # See: https://gerrit-review.googlesource.com/Documentation/rest-api-changes.html#get-related-changes
    gerrit_api "changes/$1/revisions/current/related"
}

get_previous_merge_id() {
    # Query all open merge commits previously made by crosvm-bot. May be null if
    # none are open.
    query=(
        project:chromiumos/platform/crosvm
        branch:chromeos
        status:open
        owner:crosvm-bot@crosvm-packages.iam.gserviceaccount.com
    )
    # Pick the one that was created last.
    query_changes "${query[@]}" |
        jq --raw-output 'sort_by(.created)[-1].change_id'
}

get_last_change_in_chain() {
    # Use the related changes API to find the last change in the chain of
    # commits.
    local change_id=$1

    # The list of commits is sorted by the git commit order, with the latest
    # change first and includes the current change.
    local last_change
    last_change=$(query_related_changes "$change_id" | jq --raw-output \
        "[.changes[] | select(.status == \"NEW\")][0].change_id")

    # If there are no related changes the list will be empty.
    if [ "$last_change" == "null" ]; then
        echo "${change_id}"
    else
        echo "${last_change}"
    fi
}

fetch_change() {
    # Fetch the provided change and print the commit sha.
    local change_id=$1

    # Find the git ref we need to fetch.
    local change_ref
    change_ref=$(query_change "$change_id" |
        jq --raw-output -e ".revisions[.current_revision].ref")
    git fetch -q origin "${change_ref}"
}

gerrit_prerequisites() {
    # Authenticate to GoB if we don't already have a cookie.
    # This should only happen when running in Kokoro, not locally.
    # See: go/gob-gce
    if [[ -z $(git config http.cookiefile) ]]; then
        git clone https://gerrit.googlesource.com/gcompute-tools \
            "${KOKORO_ARTIFACTS_DIR}/gcompute-tools"
        "${KOKORO_ARTIFACTS_DIR}/gcompute-tools/git-cookie-authdaemon" --no-fork

        # Setup correct user info for the service account.
        git config user.name "Crosvm Bot"
        git config user.email crosvm-bot@crosvm-packages.iam.gserviceaccount.com
    fi

    # We cannot use the original origin that kokoro used, as we no longer have
    # access the GoB host via rpc://.
    git remote remove origin
    git remote add origin ${ORIGIN}
    git fetch -q origin

    # Set up gerrit Change-Id hook.
    mkdir -p .git/hooks
    curl -Lo .git/hooks/commit-msg \
        https://gerrit-review.googlesource.com/tools/hooks/commit-msg
    chmod +x .git/hooks/commit-msg
}

upload() {
    git push origin HEAD:refs/for/chromeos%r=crosvm-uprev@google.com
}

upload_with_retries() {
    # Try uploading to gerrit. Retry due to errors on first upload.
    # See: b/209031134
    for i in $(seq 1 $RETRIES); do
        echo "Push attempt $i"
        if upload; then
            return 0
        fi
    done
    return 1
}

main() {
    gerrit_prerequisites

    # Make a copy of the merge script, so we are using the HEAD version to
    # create the merge.
    cp ./tools/chromeos/create_merge "${KOKORO_ARTIFACTS_DIR}/create_merge"

    # Clean possible stray files from previous builds.
    git clean -f -d -x
    git checkout -f

    # Parent commit to use for this merge.
    local parent_commit="origin/chromeos"

    # Query gerrit to find the latest merge commit and fetch it to be used as
    # a parent.
    local previous_merge="$(get_previous_merge_id)"
    if [ "$previous_merge" != "null" ]; then
        # The oncall may have uploaded a custom merge or cherry-pick on top
        # of the detected merge. Find the last changed in that chain.
        local last_change_in_chain=$(get_last_change_in_chain "${previous_merge}")
        echo "Found previous merge: ${GERRIT_URL}/q/${previous_merge}"
        echo "Last change in that chain: ${GERRIT_URL}/q/${last_change_in_chain}"
        fetch_change "${last_change_in_chain}"
        parent_commit="FETCH_HEAD"
    fi

    local merge_list=$(git log --oneline --decorate=no --no-color \
        "${parent_commit}..origin/main")
    if [ -z "$merge_list" ]; then
        echo "Already up to date, nothing to merge."
        return
    else
        echo "Merge list:"
        echo "${merge_list}"
        echo ""
    fi

    echo "Checking out parent: ${parent_commit}"
    git checkout -b chromeos "${parent_commit}"
    git branch --set-upstream-to origin/chromeos chromeos

    "${KOKORO_ARTIFACTS_DIR}/create_merge" "origin/main"

    upload_with_retries
}
main

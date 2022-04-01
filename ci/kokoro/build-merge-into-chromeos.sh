#!/bin/bash
# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
set -e

readonly GERRIT_URL=https://chromium-review.googlesource.com
readonly ORIGIN=https://chromium.googlesource.com/chromiumos/platform/crosvm
readonly RETRIES=3
readonly MIN_COMMIT_COUNT=${MIN_COMMIT_COUNT:-5}

gerrit_api_get() {
    # GET request to the gerrit API. Strips XSSI protection line from output.
    # See: https://gerrit-review.googlesource.com/Documentation/dev-rest-api.html
    local url="${GERRIT_URL}/${1}"
    curl --silent "$url" | tail -n +2
}

gerrit_api_post() {
    # POST to gerrit API using http cookies from git.
    local endpoint=$1
    local body=$2
    local cookie_file=$(git config http.cookiefile)
    if [[ -z "${cookie_file}" ]]; then
        echo 1>&2 "Cannot find git http cookie file."
        return 1
    fi
    local url="${GERRIT_URL}/${endpoint}"
    curl --silent \
        --cookie "${cookie_file}" \
        -X POST \
        -d "${body}" \
        -H "Content-Type: application/json" \
        "$url" |
        tail -n +2
}

query_change() {
    # Query gerrit for a specific change.
    # See: https://gerrit-review.googlesource.com/Documentation/rest-api-changes.html#get-change
    gerrit_api_get "changes/$1/?o=CURRENT_REVISION"
}

query_changes() {
    # Query gerrit for a list of changes.
    # See: https://gerrit-review.googlesource.com/Documentation/rest-api-changes.html#list-changes
    local query=$(printf '%s+' "$@")
    gerrit_api_get "changes/?q=${query}"
}

query_related_changes() {
    # Query related changes from gerrit.
    # See: https://gerrit-review.googlesource.com/Documentation/rest-api-changes.html#get-related-changes
    gerrit_api_get "changes/$1/revisions/current/related"
}

get_previous_merge_id() {
    # Query all open merge commits previously made by crosvm-bot. May be null if
    # none are open.
    query=(
        project:chromiumos/platform/crosvm
        branch:chromeos
        status:open
        owner:crosvm-bot@crosvm-packages.iam.gserviceaccount.com
        -hashtag:dryrun
    )
    # Pick the one that was created last.
    query_changes "${query[@]}" |
        jq --raw-output 'sort_by(.created)[-1].id'
}

get_last_change_in_chain() {
    # Use the related changes API to find the last change in the chain of
    # commits.
    local change_id=$1

    # The list of commits is sorted by the git commit order, with the latest
    # change first and includes the current change.
    local last_change
    last_change=$(query_related_changes "$change_id" |
        jq --raw-output "[.changes[] | select(.status == \"NEW\")][0].change_id")

    # If there are no related changes the list will be empty.
    if [ "$last_change" == "null" ]; then
        echo "${change_id}"
    else
        # The related API does not give us the unique ID of changes. Build it manually.
        echo "chromiumos%2Fplatform%2Fcrosvm~chromeos~${last_change}"
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

get_dry_run_ids() {
    # Query all dry run changes. They are identified by the hashtag:dryrun when
    # uploaded.
    query=(
        project:chromiumos/platform/crosvm
        branch:chromeos
        status:open
        hashtag:dryrun
        owner:crosvm-bot@crosvm-packages.iam.gserviceaccount.com
    )
    query_changes "${query[@]}" |
        jq --raw-output '.[].id'
}

abandon_dry_runs() {
    # Abandon all pending dry run commits
    for change in $(get_dry_run_ids); do
        echo "Abandoning ${GERRIT_URL}/q/${change}"
        gerrit_api_post "a/changes/${change}/abandon" "{}" >/dev/null
    done
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
    git push origin \
        "HEAD:refs/for/chromeos%r=crosvm-uprev@google.com,$1"
}

upload_with_retries() {
    # Try uploading to gerrit. Retry due to errors on first upload.
    # See: b/209031134
    for i in $(seq 1 $RETRIES); do
        echo "Push attempt $i"
        if upload "$1"; then
            return 0
        fi
    done
    return 1
}

main() {
    cd "${KOKORO_ARTIFACTS_DIR}/git/crosvm"

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

    echo "Checking out parent: ${parent_commit}"
    git checkout -b chromeos "${parent_commit}"
    git branch --set-upstream-to origin/chromeos chromeos

    local merge_count=$(git log --oneline --decorate=no --no-color \
        "${parent_commit}..origin/main" | wc -l)
    if [ "${merge_count}" -ge "$MIN_COMMIT_COUNT" ]; then
        "${KOKORO_ARTIFACTS_DIR}/create_merge" "origin/main"
    else
        echo "Not enough commits to merge."
    fi

    upload_with_retries

    echo "Abandoning previous dry runs"
    abandon_dry_runs

    echo "Creating dry run merge"
    git checkout -b dryrun --track origin/chromeos

    "${KOKORO_ARTIFACTS_DIR}/create_merge" --dry-run-only "origin/main"
    upload_with_retries "hashtag=dryrun,l=Commit-Queue+1,l=Bot-Commit+1"
}

main

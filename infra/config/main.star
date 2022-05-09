#!/usr/bin/env lucicfg

lucicfg.check_version("1.30.9", "Please update depot_tools")

# Use LUCI Scheduler BBv2 names and add Scheduler realms configs.
lucicfg.enable_experiment("crbug.com/1182002")

lucicfg.config(
    config_dir = "generated",
    tracked_files = ["*.cfg"],
    fail_on_warnings = True,
    lint_checks = ["default", "-module-docstring"],
)

luci.project(
    name = "crosvm",
    buildbucket = "cr-buildbucket.appspot.com",
    logdog = "luci-logdog.appspot.com",
    milo = "luci-milo.appspot.com",
    notify = "luci-notify.appspot.com",
    scheduler = "luci-scheduler.appspot.com",
    swarming = "chromium-swarm.appspot.com",
    tricium = "tricium-prod.appspot.com",
    bindings = [
        # Allow owners to submit any task in any pool.
        luci.binding(
            roles = [
                "role/swarming.poolOwner",
                "role/swarming.poolUser",
                "role/swarming.taskTriggerer",
            ],
            groups = "mdb/crosvm-acl-luci-admin",
        ),

        # Allow any googler to see all bots and tasks there.
        luci.binding(
            roles = "role/swarming.poolViewer",
            groups = "googlers",
        ),

        # Allow any googler to read/validate/reimport the project configs.
        luci.binding(
            roles = "role/configs.developer",
            groups = "googlers",
        ),
    ],
    acls = [
        # Publicly readable.
        acl.entry(
            roles = [
                acl.BUILDBUCKET_READER,
                acl.LOGDOG_READER,
                acl.PROJECT_CONFIGS_READER,
                acl.SCHEDULER_READER,
            ],
            groups = "all",
        ),
        # Allow committers to use CQ and to force-trigger and stop CI builds.
        acl.entry(
            roles = [
                acl.SCHEDULER_OWNER,
                acl.CQ_COMMITTER,
            ],
            groups = "mdb/crosvm-acl-luci-admin",
        ),
        # Group with bots that have write access to the Logdog prefix.
        acl.entry(
            roles = acl.LOGDOG_WRITER,
            groups = "luci-logdog-chromium-writers",
        ),
    ],
)

# Per-service tweaks.
luci.logdog(gs_bucket = "logdog-crosvm-archive")

# Realms with ACLs for corresponding Swarming pools.
luci.realm(name = "pools/ci")
luci.realm(name = "pools/try")

# Global recipe defaults
luci.recipe.defaults.cipd_version.set("refs/heads/main")
luci.recipe.defaults.cipd_package.set("infra/recipe_bundles/chromium.googlesource.com/crosvm/crosvm")
luci.recipe.defaults.use_python3.set(True)

# The try bucket will include builders which work on pre-commit or pre-review
# code.
luci.bucket(name = "try")

# The ci bucket will include builders which work on post-commit code.
luci.bucket(
    name = "ci",
    acls = [
        acl.entry(
            roles = acl.BUILDBUCKET_TRIGGERER,
            groups = [
                "mdb/crosvm-acl-luci-admin",
            ],
        ),
    ],
)

# The prod bucket will include builders which work on post-commit code and
# generate executable artifacts used by other users or machines.
luci.bucket(name = "prod")

# This sets the default CIPD ref to use in builds to get the right version of
# recipes for the build.
#
# The recipe bundler sets CIPD refs equal in name to the git refs that it
# processed the recipe code from.
#
# Note: This will cause all recipe commits to automatically deploy as soon
# as the recipe bundler compiles them from your refs/heads/main branch.
cipd_version = "refs/heads/main"

# Example builder to verify configuration
luci.builder(
    name = "Example Builder",
    bucket = "ci",
    executable = luci.recipe(
        name = "hello_world",
    ),
    schedule = None,
    service_account = "crosvm-luci-ci-builder@crosvm-infra.iam.gserviceaccount.com",
)

# Create builders for change verifier
def verify_builder(bucket):
    luci.builder(
        name = "Verify CL",
        bucket = bucket,
        executable = luci.recipe(
            name = "verify_cl",
        ),
        service_account = "crosvm-luci-%s-builder@crosvm-infra.iam.gserviceaccount.com" % bucket,
        dimensions = {
            "os": "Ubuntu",
            "cpu": "x86-64",
            "pool": "luci.crosvm.%s" % bucket,
        },
    )

verify_builder("try")
verify_builder("ci")

# Configure Change Verifier to watch crosvm
luci.cq(
    status_host = "chromium-cq-status.appspot.com",
)

luci.cq_group(
    name = "main_repo",
    watch = cq.refset(
        repo = "https://chromium.googlesource.com/crosvm/crosvm",
        refs = ["refs/heads/.+"],  # will watch all branches
    ),
)

# Attach our "Verify CL" builder to this CQ group.
luci.cq_tryjob_verifier(
    builder = "try/Verify CL",
    cq_group = "main_repo",
)

# Configure postsubmit tests running in ci pool
luci.gitiles_poller(
    name = "main source",
    bucket = "ci",
    repo = "https://chromium.googlesource.com/crosvm/crosvm",
    # triggers = ["ci/Verify CL"],
)
luci.console_view(
    name = "CI builders",
    repo = "https://chromium.googlesource.com/crosvm/crosvm",
    entries = [
        luci.console_view_entry(builder = "ci/Verify CL"),
    ],
)

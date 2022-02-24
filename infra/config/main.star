#!/usr/bin/env lucicfg

lucicfg.check_version("1.30.9", "Please update depot_tools")

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
)

# Per-service tweaks.
luci.logdog(gs_bucket = "logdog-crosvm-archive")

# Realms with ACLs for corresponding Swarming pools.
luci.realm(name = "pools/ci")
luci.realm(name = "pools/try")

# Global recipe defaults
luci.recipe.defaults.cipd_version.set("refs/heads/main")
luci.recipe.defaults.use_python3.set(True)

# The try bucket will include builders which work on pre-commit or pre-review
# code.
luci.bucket(name = "try")

# The ci bucket will include builders which work on post-commit code.
luci.bucket(name = "ci")

# The prod bucket will include builders which work on post-commit code and
# generate executable artifacts used by other users or machines.
luci.bucket(name = "prod")

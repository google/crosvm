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
            groups = ["googlers", "project-crosvm-committers"],
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

# Configure Change Verifier to watch crosvm
luci.cq(
    status_host = "chromium-cq-status.appspot.com",
)
luci.cq_group(
    name = "main",
    watch = cq.refset(
        repo = "https://chromium.googlesource.com/crosvm/crosvm",
        refs = ["refs/heads/.+"],  # will watch all branches
    ),
    # Allows us to submit chains of commits with a single CQ run.
    allow_submit_with_open_deps = True,
)

# Console showing all postsubmit verify builders
luci.console_view(
    name = "Postsubmit",
    repo = "https://chromium.googlesource.com/crosvm/crosvm",
)

# View showing all presubmit builders
luci.list_view(
    name = "Presubmit",
)

# View showing all infra builders
luci.list_view(
    name = "Infra",
)

# Allows builders to send email notifications on failures.
luci.notifier(
    name = "postsubmit-failures",
    on_status_change = True,
    notify_emails = [
        "crosvm-uprev@grotations.appspotmail.com",
        "crosvm-uprev-apac@grotations.appspotmail.com",
        "denniskempin@google.com",
    ],
)
luci.notifier(
    name = "infra-failures",
    on_status_change = True,
    notify_emails = [
        "denniskempin@google.com",
        "keiichiw@google.com",
    ],
)

def verify_builder(
        name,
        dimensions,
        presubmit = True,
        postsubmit = True,
        properties = dict(),
        presubmit_properties = dict(),
        postsubmit_properties = dict(),
        category = "generic",
        **args):
    """Creates both a CI and try builder with the same properties.

    The CI builder is attached to the gitlies poller and console view, and the try builder
    is added to the change verifier.

    Args:
        name: Name of the builder
        dimensions: Passed to luci.builder
        presubmit: Create a presubmit builder (defaults to True)
        postsubmit: Create a postsubmit builder (defaults to True)
        category: Category of this builder in the concole view
        properties: Builder properties for both presubmit and postsubmit
        presubmit_properties: Builder properties for only presubmit
        postsubmit_properties: Builder properties for only postsubmit
        **args: Passed to luci.builder
    """

    # CI builder
    if postsubmit:
        props = dict(**properties)
        props.update(postsubmit_properties)
        luci.builder(
            name = name,
            bucket = "ci",
            service_account = "crosvm-luci-ci-builder@crosvm-infra.iam.gserviceaccount.com",
            dimensions = dict(pool = "luci.crosvm.ci", **dimensions),
            notifies = ["postsubmit-failures"],
            properties = props,
            **args
        )
        luci.gitiles_poller(
            name = "main source",
            bucket = "ci",
            repo = "https://chromium.googlesource.com/crosvm/crosvm",
            triggers = ["ci/%s" % name],
        )
        luci.console_view_entry(
            console_view = "Postsubmit",
            builder = "ci/%s" % name,
            category = category,
        )

    # Try builder
    if presubmit:
        props = dict(**properties)
        props.update(presubmit_properties)
        luci.builder(
            name = name,
            bucket = "try",
            service_account = "crosvm-luci-try-builder@crosvm-infra.iam.gserviceaccount.com",
            dimensions = dict(pool = "luci.crosvm.try", **dimensions),
            properties = props,
            **args
        )
        luci.list_view_entry(
            list_view = "Presubmit",
            builder = "try/%s" % name,
        )

        # Attach try builder to Change Verifier
        luci.cq_tryjob_verifier(
            builder = "try/%s" % name,
            cq_group = "main",
        )

def verify_linux_builder(arch, crosvm_direct = False, coverage = True, **kwargs):
    """Creates a verify builder that builds crosvm on linux

    Args:
        arch: Architecture to build and test
        crosvm_direct: Test crosvm-direct instead of crosvm
        coverage: Disable coverage collection
        **kwargs: Passed to verify_builder
    """
    name = "linux_%s" % arch
    if crosvm_direct:
        name += "_direct"
    verify_builder(
        name = name,
        dimensions = {
            "os": "Ubuntu",
            "cpu": "x86-64",
        },
        executable = luci.recipe(
            name = "build_linux",
        ),
        properties = {
            "test_arch": arch,
            "crosvm_direct": crosvm_direct,
        },
        postsubmit_properties = {
            "repeat_tests": 3,
            "coverage": coverage,
        },
        presubmit_properties = {
            "retry_tests": 2,
        },
        caches = [
            swarming.cache("builder", name = "linux_builder_cache"),
        ],
        category = "linux",
        **kwargs
    )

def verify_chromeos_builder(board, **kwargs):
    """Creates a verify builder that builds crosvm for ChromeOS

    Args:
        board: ChromeOS board to build and test
        **kwargs: Passed to verify_builder
    """
    verify_builder(
        name = "chromeos_%s" % board,
        dimensions = {
            "os": "Ubuntu",
            "cpu": "x86-64",
        },
        executable = luci.recipe(
            name = "build_chromeos",
        ),
        properties = {
            "board": board,
        },
        category = "linux",
        **kwargs
    )

def infra_builder(name, postsubmit, **args):
    """Creates a ci job to run infra recipes that are not involved in verifying changes.

    The builders are added to a separate infra dashboard.

    Args:
        name: Name of the builder
        postsubmit: True if the builder should run after each submitted commit.
        **args: Passed to luci.builder
    """
    luci.builder(
        name = name,
        bucket = "ci",
        service_account = "crosvm-luci-ci-builder@crosvm-infra.iam.gserviceaccount.com",
        dimensions = {
            "pool": "luci.crosvm.ci",
            "os": "Ubuntu",
            "cpu": "x86-64",
        },
        notifies = ["infra-failures"],
        **args
    )
    if postsubmit:
        luci.gitiles_poller(
            name = "main source",
            bucket = "ci",
            repo = "https://chromium.googlesource.com/crosvm/crosvm",
            triggers = ["ci/%s" % name],
        )
    luci.list_view_entry(
        list_view = "Infra",
        builder = "ci/%s" % name,
    )

verify_linux_builder("x86_64")
verify_linux_builder("x86_64", crosvm_direct = True)
verify_linux_builder("aarch64")
verify_linux_builder("armhf", coverage = False)
verify_linux_builder("mingw64", coverage = False)

verify_chromeos_builder("amd64-generic", presubmit = False)

verify_builder(
    name = "chromeos_hatch",
    dimensions = {
        "os": "Ubuntu",
        "cpu": "x86-64",
    },
    executable = luci.recipe(
        name = "build_chromeos_hatch",
    ),
    category = "linux",
    presubmit = False,
)

verify_builder(
    name = "windows",
    dimensions = {
        "os": "Windows",
        "cpu": "x86-64",
    },
    executable = luci.recipe(
        name = "build_windows",
    ),
    category = "windows",
)

verify_builder(
    name = "health_check",
    dimensions = {
        "os": "Ubuntu",
        "cpu": "x86-64",
    },
    executable = luci.recipe(
        name = "health_check",
    ),
    caches = [
        swarming.cache("builder", name = "linux_builder_cache"),
    ],
    category = "linux",
)

infra_builder(
    name = "push_to_github",
    executable = luci.recipe(
        name = "push_to_github",
    ),
    postsubmit = True,
)

infra_builder(
    name = "build_docs",
    executable = luci.recipe(
        name = "build_docs",
    ),
    postsubmit = True,
)

infra_builder(
    name = "update_chromeos_merges",
    executable = luci.recipe(
        name = "update_chromeos_merges",
    ),
    schedule = "0,30 * * * *",  # Run every 30 minutes
    postsubmit = False,
)

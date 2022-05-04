PYTHON_VERSION_COMPATIBILITY = "PY3"

DEPS = [
    "depot_tools/bot_update",
    "depot_tools/gclient",
    "recipe_engine/buildbucket",
    "recipe_engine/context",
    "recipe_engine/path",
]


def RunSteps(api):
    # TODO(denniskempin): Consider using git directly for simpler config
    gitilies = api.buildbucket.build.input.gitiles_commit
    if gitilies.host:
        url = "http://%s/%s" % (gitilies.host, gitilies.project)
    else:
        cl = api.buildbucket.build.input.gerrit_changes[0]
        gs_suffix = "-review.googlesource.com"
        host = cl.host
        if host.endswith(gs_suffix):
            host = "%s.googlesource.com" % host[: -len(gs_suffix)]
        url = "http://%s/%s" % (host, cl.project)

    gclient_config = api.gclient.make_config()
    s = gclient_config.solutions.add()
    s.url = url
    s.name = "src"
    gclient_config.got_revision_mapping[s.name] = "got_revision"

    with api.context(cwd=api.path["cache"].join("builder")):
        update_result = api.bot_update.ensure_checkout(gclient_config=gclient_config)

    # At this point the code for the Gerrit CL is checked out at
    # `api.path['cache'].join('builder')`, which by default is preserved locally
    # on the bot machine and re-used between different builds for the same
    # builder.

    # TODO(denniskempin): Add some sort of build and/or verification step(s).


def GenTests(api):
    yield api.test(
        "basic try",
        # These are just to make the JSON expectation file data look closer to
        # reality. Project and git_repo will be filled in "for real" by the LUCI
        # Change Verifier service when it creates your build.
        api.buildbucket.try_build(
            project="crosvm",
            git_repo="https://chromium.googlesource.com/crosvm/crosvm",
        ),
    )
    yield api.test(
        "basic ci",
        # These are just to make the JSON expectation file data look closer to
        # reality. Project and git_repo will be filled in "for real" by the LUCI
        # Change Verifier service when it creates your build.
        api.buildbucket.ci_build(
            project="crosvm",
            git_repo="https://chromium.googlesource.com/crosvm/crosvm",
        ),
    )

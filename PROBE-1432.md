# Deliberate regression probe (#1432)

This file exists to prove that `no-pre-transfer-repo-path` fires, and it is
removed by the next commit on this branch. The line below is the regression: a
reference naming the pre-transfer repository path, in ordinary tracked prose,
outside the two paths the rule exempts.

See the [security model](https://github.com/iderex/jellyfin-plugin-sso/wiki/Security-Model).

#!/usr/bin/bash
# Syntax checks for the three files that carry the plugin, run by hand and by CI.
#
# Nothing here needs the network or a package: the helper is parsed as Python,
# the panel model is parsed by Node, and Panel.qml is checked by Qt 6's qmllint
# when this machine has it (Omarchy does; a plain CI runner does not, and the
# Qt 5 qmllint in /usr/bin cannot parse Qt 6 QML). Run it from anywhere:
# tests/lint.sh
set -uo pipefail
root=${BASH_SOURCE[0]%/*}
[ "$root" = "${BASH_SOURCE[0]}" ] && root="."
cd "$root/.." || exit 1

fails=0

if python3 -c 'import ast; ast.parse(open("bin/vigil", "rb").read())'; then
  echo "bin/vigil parses as Python"
else
  echo "bin/vigil does not parse" >&2
  fails=1
fi

if /usr/bin/env node --check Model.js; then
  echo "Model.js parses as JavaScript"
else
  echo "Model.js does not parse" >&2
  fails=1
fi

qml_lint=""
for candidate in qmllint6 /usr/lib/qt6/bin/qmllint /usr/lib64/qt6/bin/qmllint qmllint; do
  if "$candidate" --version 2>/dev/null | grep -q '^qmllint 6\.'; then
    qml_lint=$candidate
    break
  fi
done

if [ -z "$qml_lint" ]; then
  echo "Qt 6's qmllint is not installed here, so Panel.qml was not checked"
elif "$qml_lint" Panel.qml >/dev/null 2>&1; then
  echo "Panel.qml passes qmllint"
else
  echo "Panel.qml fails qmllint; by hand it says:" >&2
  "$qml_lint" Panel.qml >&2
  fails=1
fi

exit "$fails"

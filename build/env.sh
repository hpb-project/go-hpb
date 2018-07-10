#!/bin/sh

set -e

if [ ! -f "build/env.sh" ]; then
    echo "$0 must be run from the root of the repository."
    exit 2
fi

# Create fake Go workspace if it doesn't exist yet.
workspace="$PWD/build/workspace"
root="$PWD"
hpbdir="$workspace/src/github.com/hpb-project"
if [ ! -L "$hpbdir/go-hpb" ]; then
    mkdir -p "$hpbdir"
    cd "$hpbdir"
    ln -s ../../../../../. go-hpb
    cd "$root"
fi

# Set up the environment to use the workspace.
GOPATH="$workspace"
export GOPATH

# Run the command inside the workspace.
cd "$hpbdir/go-hpb"
PWD="$hpbdir/go-hpb"

# Launch the arguments with the configured environment.
exec "$@"

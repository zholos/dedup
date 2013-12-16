#!/bin/sh
set -e

cd "$(dirname "$0")"
root=$PWD
dedup=$root/../dedup.py
[ -e "$dedup" ]

coverage=
if [ "$1" = --coverage ]; then
    coverage=1; shift
fi

dedup () {
    while [ -e "$COVERAGE_FILE" ]; do
        # this may run in a subshell and so not persist
        COVERAGE_FILE=$COVERAGE_FILE-
    done
    $python "$dedup" "$@"
}

each_python () {
    python=python2; "$@"
    python=python3; "$@"
    if [ $coverage ]; then
        python="coverage2 run"
        ( export COVERAGE_FILE=$root/.coverage.2."$test"; "$@" )
        python="coverage3 run"
        ( export COVERAGE_FILE=$root/.coverage.3."$test"; "$@" )
    fi
}

each_test () {
    for test in *; do
        if [ -d "$test" ]; then
            "$@"
        fi
    done
}

clean () {
    if [ -e "$test"/setup ]; then
        ( cd "$test" && rm -rf -- a b 1 2 3 4 )
    fi
    rm -f -- "$test"/output
}

setup () {
    clean "$test"
    if [ -e "$test"/setup ]; then
        ( cd "$test" && . ./setup )
    fi
}

test () {
    setup "$test"
    if ! ( cd "$test" && . ./run >output ); then
        echo "$test failed to run with $python"
        exit 1
    elif ! diff -u -- "$test"/expect "$test"/output; then
        exit 1
    fi
}

if [ $# = 0 ]; then
    set -- run clean
fi
for cmd; do
    case $cmd in
        clean)
            each_test clean
            rm -f .coverage
            ;;
        setup)
            each_test setup
            ;;
        run)
            if [ $coverage ]; then
                rm -f .coverage .coverage.*
            fi
            each_test each_python test
            echo "all tests passed."
            if [ $coverage ]; then
                coverage2 combine
                coverage2 annotate "$dedup"
            fi
            ;;
        *) echo "bad command"; exit 1 ;;
    esac
done

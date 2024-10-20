#!/usr/bin/env bash

./show_duplicated_compilation_units.sh  |
    awk '{print $2}' | xargs -n1 dirname | sed -e 's#^\.\./##' |
    sort | uniq -c | sort -rn

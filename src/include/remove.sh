[ $# -eq 2 ] && arg="$1" || arg=""
eval file="\$$#"
sed 's/a/aA/g;s/__/aB/g;s/#/aC/g' "$file" |
          gcc -P -E $arg - |
          sed 's/aC/#/g;s/aB/__/g;s/aA/a/g'

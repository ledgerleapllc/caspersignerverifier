#!/usr/local/bin

SCRIPT_DIR="$(cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)"

python3 $SCRIPT_DIR/../sign.py 'hello' test.secret.key test.public.key
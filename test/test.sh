#!/usr/local/bin

SCRIPT_DIR="$(cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)"

python3 -m pip install ed25519 && \
python3 -m pip install ecdsa && \
python3 $SCRIPT_DIR/../sign.py 'hello' test.secret.key test.public.key && \
php test.php && \
python3 $SCRIPT_DIR/../sign.py -s 'hello' secp256k1.secret.key secp256k1.public.key && \
php test.php
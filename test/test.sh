#!/usr/local/bin

SCRIPT_DIR="$(cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)"

python3 -m pip install ed25519 && \
python3 -m pip install ecdsa && \
python3 $SCRIPT_DIR/../sign.py 'hello' $SCRIPT_DIR/test.secret.key $SCRIPT_DIR/test.public.key && \
php $SCRIPT_DIR/test.php && \
python3 $SCRIPT_DIR/../sign.py -s 'hello' $SCRIPT_DIR/secp256k1.secret.key $SCRIPT_DIR/secp256k1.public.key && \
php $SCRIPT_DIR/test.php
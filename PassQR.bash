if [ -n "$1" ]
then
    >&2 echo "PassQR does not accept additional arguments."
else
    python3 /usr/local/lib/password-store/extensions/src/main_window.py
fi

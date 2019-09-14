# Padding Oracles Demo

This repo contains a website vulnerable to a padding oracle attack as well as a program able to exploit the vulnerability. 

- Website includes all demo pages
    - Oracle is in tools.php line 64 : `function pkcs7unpad`
    - captcha is part of register-get.php
- `attack.py` contains the attack itself
    - probably requires modules installation to run...
    - To run, `python attack.py`

## To run

1. Launch a server with `./website` as the base folder
2. run `python attack.py`

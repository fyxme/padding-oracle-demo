# Padding Oracles Demo

This repo contains a website vulnerable to a padding oracle attack as well as a program able to exploit the vulnerability. 

This was developped in order to demonstrate a Padding Oracle vulnerability and how it can be abused.

The powerpoint for the presentation is also provided as `padding-oracles.pptx`.

## The vulnerable website

The website is located under the folder `website`. 

It is written in PHP.

- Website includes all demo pages
    - Oracle is in tools.php line 64 : `function pkcs7unpad`
    - captcha is part of register-get.php

## The attack script

The attack script is a python script name `attack.py`

- `attack.py` contains the attack itself
    - probably requires modules installation to run...
    - To run, `python attack.py`

## To run the demo

1. Launch a server with `./website` as the base folder
2. run `python attack.py`

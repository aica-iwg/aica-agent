#!/usr/bin/env bash

if [[ "$USER" == "appuser" ]]
then
    echo -e '\x58\x35\x4f\x21\x50\x25\x40\x41\x50\x5b\x34\x5c\x50\x5a\x58\x35\x34\x28\x50\x5e\x29\x37\x43\x43\x29\x37\x7d\x24\x45\x49\x43\x41\x52\x2d\x53\x54\x41\x4e\x44\x41\x52\x44\x2d\x41\x4e\x54\x49\x56\x49\x52\x55\x53\x2d\x54\x45\x53\x54\x2d\x46\x49\x4c\x45\x21\x24\x48\x2b\x48\x2a' > /tmp/notmalware.bin
    wget https://secure.eicar.org/eicar.com.txt -O /tmp/cutekittens2.com.txt
    wget https://secure.eicar.org/eicar_com.zip -O /home/appuser/epicfile3.zip

    # TODO: Replace this part with something that can use the malwarebazaar API (or some equivalent) to download stuff instead
    #       I haven't really done it because ClamAV only uses signatures, so we could be pulling a lot of unknown
    #       stuff which isn't useful. Good reference: https://github.com/Squiblydoo/bazaarShopper
    cp /opt/test-files/malware.zip /tmp/malware.zip
    cd /tmp
    unzip -P infected malware.zip

    head *.malz
fi
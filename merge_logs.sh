#!/bin/bash

cp /var/log/apache2/access* .
gzip -d access*.gz
cat access* > apache.log
rm access*
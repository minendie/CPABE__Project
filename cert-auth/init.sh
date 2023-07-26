#!/bin/bash
sleep 10
python3 generate_certificate.py
python3 generate_global_key.py
cat ca-private-key.pem ca-public-key.pem > ca.pem
python3 multisocat.py

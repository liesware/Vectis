#!/bin/bash

figlet Vectis
cowsay Standard Procedure Testing

read -p "Press any key to start: " keyboard
echo "\n###########################"

echo "\n### HTTP Positive/Negative"
uv sync
uv run tests/http_all.py

echo "\n### Manual HTTP Fuzzing"
uv run tests/http_fuzz.py 

echo "\n### HTTP Schemathesis"
uv sync --group fuzz
uv run tests/http_schemathesis.py --profile prepared 
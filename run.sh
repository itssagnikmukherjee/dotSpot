#!/bin/bash
source venv/bin/activate

# Load environment variables from .env if it exists
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
fi

python dotspot.py "$@"

#!/bin/bash
# Start both LARA apps: main (port 8000) and account (port 8001)
uvicorn account_app:app --host 0.0.0.0 --port 8001 &
uvicorn main:app --host 0.0.0.0 --port 8000

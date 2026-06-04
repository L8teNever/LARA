#!/bin/bash
# Start LARA main app (port 8000)
uvicorn main:app --host 0.0.0.0 --port 8000

#!/bin/bash
# Uruchom serwer WebSocket w tle
python websocket_server.py &
# Uruchom główną aplikację Flask
gunicorn main:app

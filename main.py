from flask import Flask
import asyncio
import threading
from websockets import serve

app = Flask(__name__)

@app.route('/')
def index():
    return "Główna strona aplikacji"

# Funkcja uruchamiająca serwer WebSocket w osobnym wątku
def start_websocket_server():
    async def echo(websocket, path):
        async for message in websocket:
            await websocket.send(message)

    async def main():
        async with serve(echo, "0.0.0.0", 8081):
            await asyncio.Future()  # Uruchom bezterminowo

    asyncio.run(main())

# Uruchom serwer WebSocket w osobnym wątku
threading.Thread(target=start_websocket_server, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

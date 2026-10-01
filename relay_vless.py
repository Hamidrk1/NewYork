import asyncio
import logging
from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger("X4G-Gateway")

async def handle_relay_vless(websocket: WebSocket, target_host: str, target_port: int):
    # حل مشکل Circular Import با امپورت محلی در زمان اجرا
    try:
        from main import is_ip_allowed
        client_ip = websocket.client.host if websocket.client else "unknown"
        if not is_ip_allowed(client_ip):
            logger.warning(f"Unauthorized access attempt from {client_ip}")
            await websocket.close(code=4003)
            return
    except Exception as e:
        logger.error(f"Error checking IP permission: {e}")

    await websocket.accept()
    try:
        reader, writer = await asyncio.open_connection(target_host, target_port)
    except Exception as e:
        logger.error(f"Failed to connect to target {target_host}:{target_port} -> {e}")
        await websocket.close(code=1011)
        return

    async def forward_ws_to_tcp():
        try:
            while True:
                data = await websocket.receive_bytes()
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except WebSocketDisconnect:
            pass
        except Exception as e:
            logger.debug(f"WS to TCP relay ended: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def forward_tcp_to_ws():
        try:
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                await websocket.send_bytes(data)
        except Exception as e:
            logger.debug(f"TCP to WS relay ended: {e}")
        finally:
            try:
                await websocket.close()
            except Exception:
                pass

    await asyncio.gather(
        forward_ws_to_tcp(),
        forward_tcp_to_ws(),
        return_exceptions=True
    )

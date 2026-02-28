import asyncio
import json
import datetime
import threading
import socket
from typing import List, Dict, Any, Optional, Set
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from mitmproxy import http, options
from mitmproxy.tools.dump import DumpMaster
import pyshark
from starlette.responses import FileResponse
import geoip2.database


# ================= 配置与全局状态 =================

@dataclass
class FilterConfig:
    # 默认只启用 HTTP 和 HTTPS
    enabled_protocols: Set[str] = field(default_factory=lambda: {"HTTP", "HTTPS"})
    enable_domain_block: bool = False
    blocked_domains: Set[str] = field(default_factory=set)
    filter_direction: str = "ALL"

    def is_allowed(self, protocol: str, direction: str, host: str = "") -> bool:
        if self.enabled_protocols and protocol not in self.enabled_protocols:
            return False
        if self.filter_direction != "ALL" and self.filter_direction != direction:
            return False
        if self.enable_domain_block and host:
            for domain in self.blocked_domains:
                if domain in host:
                    return False
        return True


global_config = FilterConfig()
config_lock = threading.Lock()

traffic_log = []
MAX_LOG_SIZE = 500
clients: List[WebSocket] = []
clients_lock = threading.Lock()

# ================= IP 地理位置逻辑 =================

GEOIP_DB_PATH = "GeoLite2-City.mmdb"
geo_reader = None

try:
    geo_reader = geoip2.database.Reader(GEOIP_DB_PATH)
    print(f"✅ 地理位置数据库已加载：{GEOIP_DB_PATH}")
except FileNotFoundError:
    print(f"⚠️  警告：未找到 {GEOIP_DB_PATH}，IP 地理位置功能将不可用。")
    print("💡 请运行: curl -L -o GeoLite2-City.mmdb 'https://git.io/GeoLite2-City.mmdb'")
except Exception as e:
    print(f"⚠️  警告：加载地理位置数据库失败：{e}")


def get_ip_location(ip_address: str) -> str:
    """查询 IP 地理位置，返回 '国家 城市' 格式"""
    if not geo_reader:
        return "未知 (无数据库)"

    try:
        # 跳过私有 IP
        if ip_address.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.2', '172.30.', '172.31.', '127.', '0.')):
            return "局域网/本地"

        response = geo_reader.city(ip_address)
        country = response.country.names.get('zh-CN', response.country.iso_code)

        # 尝试获取城市
        city = response.city.names.get('zh-CN')
        if not city:
            # 如果城市没有中文名，尝试获取省份
            subdivisions = response.subdivisions.most_specific
            if subdivisions:
                city = subdivisions.names.get('zh-CN', subdivisions.iso_code)
            else:
                city = "未知城市"

        return f"{country} {city}"
    except geoip2.errors.AddressNotFoundError:
        return "未知位置"
    except Exception:
        return "查询失败"


# ================= 核心逻辑 =================

def get_local_ip_prefixes():
    prefixes = ["127.", "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31."]
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if ip:
            prefixes.append(ip.split('.')[0] + '.')
    except:
        pass
    return prefixes


LOCAL_PREFIXES = get_local_ip_prefixes()


def determine_direction(src_ip: str, dst_ip: str) -> str:
    for prefix in LOCAL_PREFIXES:
        if src_ip.startswith(prefix):
            return "OUT"
    for prefix in LOCAL_PREFIXES:
        if dst_ip.startswith(prefix):
            return "IN"
    return "OUT"


def add_traffic_entry(entry: Dict[str, Any]):
    protocol = entry.get('protocol', 'UNKNOWN')
    direction = entry.get('direction', 'UNKNOWN')
    host = entry.get('host', '')

    with config_lock:
        if not global_config.is_allowed(protocol, direction, host):
            return

    # 出站查目标 IP，入站查源 IP
    target_ip = entry.get('dst_ip') if direction == 'OUT' else entry.get('src_ip')
    entry['location'] = get_ip_location(target_ip) if target_ip else "未知"

    entry['timestamp'] = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

    with clients_lock:
        traffic_log.insert(0, entry)
        if len(traffic_log) > MAX_LOG_SIZE:
            traffic_log.pop()

        if clients:
            message = json.dumps({"type": "new_packet", "data": entry})
            loop = asyncio.get_event_loop()
            for client in list(clients):
                asyncio.run_coroutine_threadsafe(safe_send(client, message), loop)


async def safe_send(websocket: WebSocket, message: str):
    try:
        await websocket.send_text(message)
    except Exception:
        pass


# ================= Mitmproxy 插件 =================

# ================= Mitmproxy 插件 =================

def decode_content(content: bytes) -> str:
    """尝试将二进制内容解码为字符串，失败则返回提示"""
    if not content:
        return ""
    if len(content) > 50000:  # 限制最大显示长度，防止前端卡死 (50KB)
        return f"... (数据过大 {len(content)} 字节，仅显示前 50KB) ..."

    try:
        # 尝试 UTF-8 解码
        return content.decode('utf-8')
    except UnicodeDecodeError:
        try:
            # 尝试 GBK 解码 (针对部分中文旧网站)
            return content.decode('gbk')
        except:
            return "[二进制数据 / 图片 / 视频 / 加密内容]"


# ... (前面的代码不变)

class TrafficAddon:
    def request(self, flow: http.HTTPFlow):
        # 确保这里 req_body 即使是空字符串也要传过去，不要传 None
        req_content = decode_content(flow.request.content)
        # ... (省略中间代码)
        entry = {
            # ...
            "req_body": req_content,
            "res_body": "",  # 请求阶段响应体为空字符串
            # ...
        }
        add_traffic_entry(entry)

    def response(self, flow: http.HTTPFlow):
        protocol = "HTTPS" if flow.request.scheme == "https" else "HTTP"

        # 【优化】解码响应内容
        res_content = decode_content(flow.response.content)
        res_headers = dict(flow.response.headers)

        entry = {
            "id": id(flow),
            "protocol": protocol,
            "method": "-> 响应",
            "host": flow.request.host,
            "path": "",
            "src_ip": flow.server_conn.address[0],
            "dst_ip": flow.client_conn.peername[0],
            "dst_port": flow.client_conn.peername[1],
            "direction": "IN",
            "size": len(flow.response.content) if flow.response.content else 0,
            "status": flow.response.status_code,
            "info": f"状态码：{flow.response.status_code}",
            "req_headers": "",
            "req_body": "",
            # 【关键】即使内容是 "[二进制数据...]" 或 ""，也要传下去，让前端知道请求结束了
            "res_headers": json.dumps(res_headers, ensure_ascii=False, indent=2),
            "res_body": res_content
        }
        add_traffic_entry(entry)


# ================= 后台任务 =================

async def run_mitm_async():
    try:
        opts = options.Options(listen_port=8080, mode=["regular"], ssl_insecure=True)
        master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        master.addons.add(TrafficAddon())
        print("✅ MitmProxy 引擎已启动...")
        await master.run()
    except Exception as e:
        print(f"❌ MitmProxy 严重错误：{e}")
        import traceback
        traceback.print_exc()


async def sniff_non_http_async():
    interface = None

    def capture_thread():
        try:
            bpf_filter = "not port 8080 and not port 8081"
            print(f"✅ PyShark 引擎已启动 (过滤器：{bpf_filter})")
            cap = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter, display_filter="ip")
            for packet in cap:
                try:
                    if not hasattr(packet, 'ip'):
                        continue
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    protocol = packet.highest_layer
                    layer_obj = getattr(packet, protocol.lower(), None)
                    src_port = getattr(layer_obj, 'srcport', 'N/A') if layer_obj else 'N/A'
                    dst_port = getattr(layer_obj, 'dstport', 'N/A') if layer_obj else 'N/A'
                    direction = determine_direction(src_ip, dst_ip)
                    host = ""
                    if protocol == "DNS" and hasattr(packet, 'dns') and hasattr(packet.dns, 'qname'):
                        host = str(packet.dns.qname).rstrip('.')
                    entry = {
                        "id": hash(str(packet)),
                        "protocol": protocol,
                        "method": "",
                        "host": host or f"{dst_ip}:{dst_port}" if direction == "OUT" else f"{src_ip}:{src_port}",
                        "path": "",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": str(dst_port),
                        "direction": direction,
                        "size": int(packet.length) if hasattr(packet, 'length') else 0,
                        "status": "-",
                        "info": f"{protocol} 数据包"
                    }
                    add_traffic_entry(entry)
                except Exception:
                    continue
        except Exception as e:
            print(f"❌ 抓包错误：{e}")

    thread = threading.Thread(target=capture_thread, daemon=True)
    thread.start()
    try:
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass


# ================= FastAPI 应用 =================

@asynccontextmanager
async def lifespan(app: FastAPI):
    t1 = asyncio.create_task(run_mitm_async())
    t2 = asyncio.create_task(sniff_non_http_async())
    yield
    t1.cancel()
    t2.cancel()
    try:
        await t1
        await t2
    except asyncio.CancelledError:
        pass


app = FastAPI(lifespan=lifespan, title="NetWall 防火墙")


class ConfigUpdate(BaseModel):
    enabled_protocols: Optional[List[str]] = None
    enable_domain_block: Optional[bool] = None
    blocked_domains: Optional[List[str]] = None
    filter_direction: Optional[str] = None


@app.get("/api/config")
async def get_config():
    with config_lock:
        return {
            "enabled_protocols": list(global_config.enabled_protocols),
            "enable_domain_block": global_config.enable_domain_block,
            "blocked_domains": list(global_config.blocked_domains),
            "filter_direction": global_config.filter_direction
        }


@app.post("/api/config")
async def update_config(cfg: ConfigUpdate):
    with config_lock:
        if cfg.enabled_protocols is not None:
            global_config.enabled_protocols = set(cfg.enabled_protocols)
        if cfg.enable_domain_block is not None:
            global_config.enable_domain_block = cfg.enable_domain_block
        if cfg.blocked_domains is not None:
            global_config.blocked_domains = set(cfg.blocked_domains)
        if cfg.filter_direction is not None:
            global_config.filter_direction = cfg.filter_direction
    return {"status": "success", "message": "配置已更新"}


@app.get("/")
async def get_index():
    return FileResponse("index.html")


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    with clients_lock:
        clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        with clients_lock:
            if websocket in clients:
                clients.remove(websocket)


if __name__ == "__main__":
    import uvicorn

    print("🚀 正在启动 NetWall 动态防火墙...")
    print("📡 管理界面：http://localhost:8081")
    print("🕵️ 代理端口：8080")
    print("🌍 地理位置数据库：GeoLite2-City.mmdb")
    uvicorn.run(app, host="0.0.0.0", port=8081, log_level="warning")

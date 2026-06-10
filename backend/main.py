import asyncio
import ctypes
import json
import logging
import platform
import subprocess
import sys
import threading
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import config
from network_sniffer import NetworkSniffer
from feature_engineering import FeatureEngineer
from detection_engine import DetectionEngine
from diagnosis_engine import DiagnosisEngine
from decision_engine import DecisionEngine
from response_engine import ResponseEngine
from verification_engine import VerificationEngine
from risk_engine import RiskEngine
from database import Database
from threat_intel import ThreatIntelFeed
from behavioral_engine import BehavioralEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)


def _is_admin_process() -> bool:
    try:
        if platform.system() == "Windows":
            if ctypes.windll.shell32.IsUserAnAdmin() != 0:
                return True
            r = subprocess.run(["net", "session"], capture_output=True)
            return r.returncode == 0
    except Exception:
        pass
    return False


def _elevate_and_restart() -> None:
    import os
    script  = os.path.abspath(sys.argv[0])
    workdir = os.path.dirname(script)
    python  = sys.executable

    logger.warning(
        "Not running as Administrator — firewall blocking requires elevation.\n"
        "  A UAC prompt will appear. Please click 'Yes' to allow.\n"
        "  Python: %s\n  Script: %s", python, script,
    )

    ps_cmd = (
        f"Start-Process -FilePath '{python}' "
        f"-ArgumentList '\"{script}\"' "
        f"-WorkingDirectory '{workdir}' "
        f"-Verb RunAs"
    )
    ret = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_cmd],
        capture_output=True, text=True,
    )
    if ret.returncode != 0:
        logger.error(
            "PowerShell elevation failed:\n%s\n"
            "Please right-click your terminal → 'Run as Administrator' and run: python main.py",
            ret.stderr.strip(),
        )
    sys.exit(0)


if platform.system() == "Windows" and config.RESPONSE_MODE == "live" and not _is_admin_process():
    _elevate_and_restart()


class SystemState:
    def __init__(self):
        self.running = False
        self.monitoring = False
        self.last_scan: Optional[str] = None
        self.current_features = None
        self.alerts: list = []
        self.actions: list = []
        self.verifications: list = []
        self.capture_mode: str = config.CAPTURE_MODE
        self.response_mode: str = config.RESPONSE_MODE
        self._lock = asyncio.Lock()

    async def set(self, **kwargs):
        async with self._lock:
            for k, v in kwargs.items():
                setattr(self, k, v)


class WSBroadcaster:
    def __init__(self):
        self._clients: list[WebSocket] = []

    def connect(self, ws: WebSocket):
        self._clients.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self._clients:
            self._clients.remove(ws)

    async def broadcast(self, payload: dict):
        if not self._clients:
            return
        message = json.dumps(payload)
        dead = []
        for client in self._clients:
            try:
                await client.send_text(message)
            except Exception:
                dead.append(client)
        for client in dead:
            self.disconnect(client)


state = SystemState()
broadcaster = WSBroadcaster()

sniffer = NetworkSniffer(mode=config.CAPTURE_MODE, interface=config.CAPTURE_INTERFACE)
feature_engineer = FeatureEngineer()
detection_engine = DetectionEngine()
diagnosis_engine = DiagnosisEngine()
decision_engine = DecisionEngine()
response_engine = ResponseEngine(mode=config.RESPONSE_MODE)
verification_engine = VerificationEngine()
risk_engine = RiskEngine()
database = Database(db_type="sqlite", db_path="nnnids.db")
threat_intel = ThreatIntelFeed()
behavioral_engine = BehavioralEngine()


@asynccontextmanager
async def lifespan(app: FastAPI):
    risk_engine.seed_from_db(database.get_risk_history_for_engine())
    logger.info(
        "NNNIDS started | capture=%s | response=%s | interface=%s | auto_start=%s",
        config.CAPTURE_MODE, config.RESPONSE_MODE,
        config.CAPTURE_INTERFACE or "auto", config.AUTO_START,
    )
    if config.AUTO_START:
        asyncio.create_task(
            _continuous_monitor(config.MONITOR_WINDOW, config.MONITOR_INTERVAL)
        )
        logger.info(
            "Continuous monitoring auto-started | window=%ds | interval=%.1fs",
            config.MONITOR_WINDOW, config.MONITOR_INTERVAL,
        )
    yield
    sniffer.stop_streaming()
    await state.set(monitoring=False)
    database.close()


app = FastAPI(
    title="NNNIDS API",
    description="Self-Healing AI Network Intrusion Detection System",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    duration: int = 10


class MonitorRequest(BaseModel):
    window_seconds: int = 10
    interval_seconds: float = 15.0


class UnblockRequest(BaseModel):
    ip: str


async def _emit(stage: str, progress: int, total: int, detail: str = ""):
    await broadcaster.broadcast({
        "type": "pipeline",
        "stage": stage,
        "progress": progress,
        "total": total,
        "detail": detail,
        "timestamp": datetime.now().isoformat(),
    })


async def _run_pipeline(packets: list) -> dict:
    await _emit("features", 1, 7)
    previous_features = state.current_features
    features = feature_engineer.extract_features(packets)
    await state.set(current_features=features)

    if features.empty:
        await _emit("idle", 1, 7, "No traffic captured in this window")
        return {"alerts": 0, "actions": 0}

    if not detection_engine.is_trained:
        await _emit("training", 2, 7, "Building ML baseline from first window")
        detection_engine.train(features)

    await _emit("detection", 3, 7)
    detections = detection_engine.detect(features, threat_intel, behavioral_engine)

    await _emit("diagnosis", 4, 7)
    diagnoses = diagnosis_engine.diagnose_batch(detections)
    await state.set(alerts=diagnoses)
    for alert in diagnoses:
        database.insert_alert(alert)

    if diagnoses:
        await broadcaster.broadcast({
            "type": "alerts",
            "alerts": diagnoses,
            "count": len(diagnoses),
            "timestamp": datetime.now().isoformat(),
        })

    await _emit("decision", 5, 7)
    decisions = decision_engine.decide_batch(diagnoses)

    await _emit("response", 6, 7)
    actions = []
    for decision in decisions:
        action = response_engine.execute(decision)
        actions.append(action)
        database.insert_action(action)
        await broadcaster.broadcast({
            "type": "action",
            "action": action,
            "timestamp": datetime.now().isoformat(),
        })
        # Push live blocked-IP list so the UI reflects firewall state instantly
        await broadcaster.broadcast({
            "type": "blocked_ips",
            "blocked_ips": list(response_engine.blocked_ips),
            "timestamp": datetime.now().isoformat(),
        })
    await state.set(actions=actions)

    verifications = []
    if actions and previous_features is not None:
        ip_actions: dict[str, dict] = {}
        for a in actions:
            ip = a["src_ip"]
            if ip not in ip_actions or a.get("status") == "EXECUTED":
                ip_actions[ip] = a

        for ip, act in ip_actions.items():
            v = verification_engine.verify(
                src_ip=ip,
                before_features=previous_features,
                after_features=features,
                action_taken=act["action_type"],
                action_status=act.get("status", "UNKNOWN"),
            )
            database.insert_verification(v)
            verifications.append(v)

        if verifications:
            await broadcaster.broadcast({
                "type": "verifications",
                "verifications": verifications,
                "timestamp": datetime.now().isoformat(),
            })
    elif actions and previous_features is None:
        for action in actions[:5]:
            v = verification_engine.verify(
                src_ip=action["src_ip"],
                before_features=None,
                after_features=features,
                action_taken=action["action_type"],
                action_status=action.get("status", "UNKNOWN"),
            )
            database.insert_verification(v)

    await _emit("risk", 7, 7)
    risk_data = risk_engine.calculate_risk(diagnoses, verifications, features)
    risk_data["timestamp"] = datetime.now().isoformat()
    database.insert_risk_record(risk_data)

    await broadcaster.broadcast({
        "type": "risk",
        "current_risk": risk_engine.current_risk,
        "risk_level": risk_engine.get_risk_level(),
        "trend": risk_engine.get_trend(),
        "timestamp": datetime.now().isoformat(),
    })

    await state.set(last_scan=datetime.now().isoformat())
    return {"alerts": len(diagnoses), "actions": len(actions), "verifications": len(verifications)}


async def _run_one_shot(duration: int):
    await state.set(running=True)
    try:
        await _emit("capture", 0, 7, f"Capturing {duration}s of live traffic")
        loop = asyncio.get_event_loop()
        packets = await loop.run_in_executor(None, lambda: sniffer.start_capture(duration))
        await _run_pipeline(packets)
        await _emit("complete", 7, 7, "Scan complete")
    except RuntimeError as e:
        logger.error("Capture failed: %s", e)
        await broadcaster.broadcast({"type": "error", "message": str(e), "action": "install_npcap"})
    except Exception as e:
        logger.exception("Pipeline error")
        await broadcaster.broadcast({"type": "error", "message": str(e)})
    finally:
        await state.set(running=False)


_monitor_task: Optional[asyncio.Task] = None


async def _continuous_monitor(window_seconds: int, interval_seconds: float):
    await state.set(monitoring=True)
    loop = asyncio.get_event_loop()

    logger.info(
        "Continuous monitoring started | window=%ds | interval=%.1fs",
        window_seconds, interval_seconds,
    )

    while state.monitoring:
        try:
            await broadcaster.broadcast({
                "type": "monitor_tick",
                "timestamp": datetime.now().isoformat(),
                "window_seconds": window_seconds,
            })
            packets = await loop.run_in_executor(
                None, lambda: sniffer.start_capture(duration=window_seconds)
            )
            summary = await _run_pipeline(packets)
            logger.info("Monitor window complete | %s", summary)
        except RuntimeError as e:
            logger.error("Capture failed during monitoring: %s", e)
            await broadcaster.broadcast({"type": "error", "message": str(e), "action": "install_npcap"})
            await state.set(monitoring=False)
            break
        except Exception as e:
            logger.exception("Monitor window error")
            await broadcaster.broadcast({"type": "error", "message": str(e)})

        await asyncio.sleep(interval_seconds)

    await state.set(monitoring=False)
    logger.info("Continuous monitoring stopped")


@app.get("/")
async def root():
    return {
        "system": "NNNIDS",
        "version": "2.0.0",
        "status": "operational",
        "capture_mode": config.CAPTURE_MODE,
        "response_mode": config.RESPONSE_MODE,
    }


@app.get("/status")
async def get_status():
    stats = database.get_stats()
    return {
        "running": state.running,
        "monitoring": state.monitoring,
        "last_scan": state.last_scan,
        "total_alerts": stats["total_alerts"],
        "total_actions": stats["total_actions"],
        "current_risk": risk_engine.current_risk,
        "capture_mode": state.capture_mode,
        "response_mode": state.response_mode,
        "interface": sniffer.interface,
    }


@app.post("/scan/start")
async def start_scan(scan_req: ScanRequest, background_tasks: BackgroundTasks):
    if state.running:
        raise HTTPException(
            status_code=400,
            detail="A scan is already running. Wait for it to finish or call POST /scan/reset."
        )
    background_tasks.add_task(_run_one_shot, scan_req.duration)
    return {"status": "started", "duration": scan_req.duration, "mode": config.CAPTURE_MODE}


@app.post("/scan/reset")
async def reset_scan():
    was_running = state.running
    await state.set(running=False)
    return {"status": "reset", "was_running": was_running}


@app.post("/monitor/start")
async def start_monitor(req: MonitorRequest, background_tasks: BackgroundTasks):
    global _monitor_task
    if state.monitoring:
        raise HTTPException(status_code=400, detail="Continuous monitoring is already active")
    background_tasks.add_task(_continuous_monitor, req.window_seconds, req.interval_seconds)
    return {
        "status": "monitoring_started",
        "window_seconds": req.window_seconds,
        "interval_seconds": req.interval_seconds,
        "mode": config.CAPTURE_MODE,
    }


@app.post("/monitor/stop")
async def stop_monitor():
    if not state.monitoring:
        raise HTTPException(status_code=400, detail="Monitoring is not active")
    await state.set(monitoring=False)
    return {"status": "monitoring_stopped"}


@app.post("/unblock")
async def unblock_ip(req: UnblockRequest):
    result = response_engine.unblock(req.ip)
    return result


class BlockRequest(BaseModel):
    ip: str


@app.post("/block")
async def block_ip(req: BlockRequest):
    decision = {
        "diagnosis_id": "manual",
        "src_ip": req.ip,
        "attack_type": "manual_block",
        "severity": "HIGH",
        "recommended_action": "BLOCK_IP",
        "reason": "Manual block triggered by operator",
        "auto_execute": True,
        "metadata": {},
    }
    action = response_engine.execute(decision)
    return action


@app.get("/traffic")
async def get_traffic():
    if state.current_features is None or state.current_features.empty:
        return {"features": []}
    return {"features": state.current_features.to_dict("records")}


@app.get("/alerts")
async def get_alerts(limit: int = 50):
    alerts = database.get_alerts(limit=limit)
    return {"alerts": alerts, "count": len(alerts)}


@app.get("/actions")
async def get_actions(limit: int = 50):
    actions = database.get_actions(limit=limit)
    return {"actions": actions, "count": len(actions)}


@app.get("/verifications")
async def get_verifications(limit: int = 50):
    verifications = database.get_verifications(limit=limit)
    return {"verifications": verifications, "count": len(verifications)}


@app.get("/risk")
async def get_risk():
    return {
        "current_risk": risk_engine.current_risk,
        "risk_level": risk_engine.get_risk_level(),
        "trend": risk_engine.get_trend(),
        "history": risk_engine.get_risk_history(limit=20),
    }


@app.get("/history")
async def get_history(limit: int = 100):
    return {
        "alerts": database.get_alerts(limit=limit),
        "actions": database.get_actions(limit=limit),
        "verifications": database.get_verifications(limit=limit),
        "risk_history": database.get_risk_history(limit=limit),
    }


@app.get("/stats")
async def get_stats():
    return {
        "database": database.get_stats(),
        "verification": verification_engine.get_verification_summary(),
        "current_risk": risk_engine.current_risk,
        "blocked_ips": list(response_engine.blocked_ips),
    }


@app.get("/blocked")
async def get_blocked():
    return {"blocked_ips": list(response_engine.blocked_ips)}


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    broadcaster.connect(ws)
    await ws.send_text(json.dumps({
        "type": "connected",
        "capture_mode": config.CAPTURE_MODE,
        "response_mode": config.RESPONSE_MODE,
        "interface": sniffer.interface,
        "timestamp": datetime.now().isoformat(),
    }))
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        broadcaster.disconnect(ws)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
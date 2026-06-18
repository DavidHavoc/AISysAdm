from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from .agents import LinuxStateAgent, LogAnalysisAgent, OrchestratorAgent
from .collector import DemoCollector, SshCollector
from .config import Settings
from .credentials import CredentialVault
from .executor import AnsibleExecutor, SimulatedExecutor
from .memory import InMemoryAgentMemory, RedisAgentMemory
from .models import (
    CampaignRequest,
    Host,
    HostInput,
    PatchCampaign,
    Remediation,
    ScanJob,
    ScanRequest,
    SshCredential,
)
from .providers import ModelRouter
from .repository import InMemoryRepository, Repository, SqlRepository
from .service import SysadminService


def build_service(settings: Settings) -> SysadminService:
    repository: Repository = (
        SqlRepository(settings.database_url)
        if settings.database_url
        else InMemoryRepository()
    )
    memory = (
        RedisAgentMemory(settings.redis_url, settings.agent_memory_ttl_seconds)
        if settings.redis_url
        else InMemoryAgentMemory()
    )
    vault = CredentialVault(settings.data_dir / "ssh-keys")
    collector = (
        SshCollector(vault) if settings.collector_mode == "ssh" else DemoCollector()
    )
    executor = (
        AnsibleExecutor(settings.ansible_playbook_dir, vault)
        if settings.execution_mode == "ansible"
        else SimulatedExecutor()
    )
    router = ModelRouter(settings)
    return SysadminService(
        repository=repository,
        collector=collector,
        log_agent=LogAnalysisAgent(router, memory),
        state_agent=LinuxStateAgent(router, memory),
        orchestrator=OrchestratorAgent(router, memory),
        executor=executor,
    )


def create_app(
    settings: Optional[Settings] = None,
    service: Optional[SysadminService] = None,
) -> FastAPI:
    resolved_settings = settings or Settings()
    app = FastAPI(
        title="AI Linux Sysadmin API",
        version="0.2.0",
        description=(
            "Three-agent Linux analysis with approval-gated Ansible patching, "
            "explicit reboot handling, and controlled fleet rollouts."
        ),
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=resolved_settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.state.settings = resolved_settings
    app.state.service = service or build_service(resolved_settings)
    app.state.vault = CredentialVault(resolved_settings.data_dir / "ssh-keys")

    @app.get("/")
    async def root():
        return {
            "name": "AI Linux Sysadmin API",
            "status": "running",
            "documentation": "/docs",
            "health": "/health",
        }

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        return Response(status_code=204)

    @app.get("/health")
    async def health():
        return {"ok": True, "executionMode": resolved_settings.execution_mode}

    @app.get("/hosts", response_model=list[Host])
    async def list_hosts():
        return app.state.service.list_hosts()

    @app.post("/hosts", response_model=Host, status_code=201)
    async def create_host(host: HostInput):
        return app.state.service.create_host(host)

    @app.post("/credentials/ssh-keys", response_model=SshCredential, status_code=201)
    async def upload_key(name: str = Form(...), key: UploadFile = File(...)):
        try:
            return app.state.vault.save_private_key(name, await key.read())
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    @app.post("/scans", response_model=ScanJob, status_code=201)
    async def run_scan(request: ScanRequest):
        scan = await app.state.service.run_scan(request)
        if scan.status == "failed":
            raise HTTPException(status_code=502, detail=scan.error)
        return scan

    @app.get("/hosts/{host_id}/findings")
    async def list_findings(host_id: str):
        return app.state.service.list_findings(host_id)

    @app.get("/remediations", response_model=list[Remediation])
    async def list_remediations():
        return app.state.service.list_remediations()

    @app.post("/remediations/{remediation_id}/approve", response_model=Remediation)
    async def approve_remediation(remediation_id: str):
        try:
            return await app.state.service.approve_remediation(remediation_id)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    @app.post("/remediations/{remediation_id}/reject", response_model=Remediation)
    async def reject_remediation(remediation_id: str):
        try:
            return app.state.service.reject_remediation(remediation_id)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    @app.get("/jobs/{job_id}", response_model=ScanJob)
    async def get_job(job_id: str):
        job = app.state.service.get_scan(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        return job

    @app.get("/campaigns", response_model=list[PatchCampaign])
    async def list_campaigns():
        return app.state.service.list_campaigns()

    @app.post("/campaigns", response_model=PatchCampaign, status_code=201)
    async def create_campaign(request: CampaignRequest):
        try:
            return await app.state.service.create_campaign(request)
        except (ValueError, RuntimeError) as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    @app.post("/campaigns/{campaign_id}/approve", response_model=PatchCampaign)
    async def approve_campaign(campaign_id: str):
        try:
            return await app.state.service.approve_campaign(campaign_id)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    @app.post("/campaigns/{campaign_id}/reject", response_model=PatchCampaign)
    async def reject_campaign(campaign_id: str):
        try:
            return app.state.service.reject_campaign(campaign_id)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    return app


app = create_app()

from __future__ import annotations

from typing import Optional

from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.middleware.cors import CORSMiddleware

from .config import BEAT_HEALTH_KEY, WORKER_HEALTH_KEY, Settings
from .models import (
    Alert,
    ApprovalRequest,
    AuditEvent,
    CampaignActionResponse,
    CampaignRequest,
    ConnectionTestRequest,
    ConnectionTestResult,
    DurableJob,
    Host,
    HostInput,
    HostSchedule,
    HostScheduleInput,
    LoginRequest,
    LoginResponse,
    LogPage,
    PatchCampaign,
    Remediation,
    ScanJob,
    ScanRequest,
    SshCredential,
    StructuredLogEvent,
    User,
)
from .queue import CeleryJobDispatcher, InlineJobDispatcher, JobDispatcher
from .runtime import Runtime, build_runtime


SESSION_COOKIE = "ai_sysadm_session"
CSRF_HEADER = "x-csrf-token"


def create_app(
    settings: Optional[Settings] = None,
    runtime: Optional[Runtime] = None,
    dispatcher: Optional[JobDispatcher] = None,
) -> FastAPI:
    resolved_runtime = runtime or build_runtime(settings)
    resolved_settings = resolved_runtime.settings
    resolved_dispatcher = dispatcher or (
        CeleryJobDispatcher()
        if resolved_settings.app_environment == "alpha"
        else (
            InlineJobDispatcher(resolved_runtime.service)
            if resolved_settings.celery_task_always_eager
            or not resolved_settings.redis_url
            else CeleryJobDispatcher()
        )
    )
    app = FastAPI(
        title="AI Linux Sysadmin API",
        version="0.3.0-alpha",
        description=(
            "Durable three-agent Linux analysis with scheduled scans, structured "
            "evidence, approval-gated Ansible patching, and explicit reboot handling."
        ),
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=resolved_settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.state.runtime = resolved_runtime
    app.state.dispatcher = resolved_dispatcher

    async def current_user(request: Request) -> User:
        user = resolved_runtime.auth.authenticate(
            request.cookies.get(SESSION_COOKIE)
        )
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )
        return user

    async def mutation_user(
        request: Request,
        user: User = Depends(current_user),
    ) -> User:
        if not resolved_runtime.auth.verify_csrf(
            request.cookies.get(SESSION_COOKIE),
            request.headers.get(CSRF_HEADER),
        ):
            raise HTTPException(status_code=403, detail="CSRF token is invalid")
        return user

    @app.get("/")
    async def root():
        return {
            "name": "AI Linux Sysadmin API",
            "status": "running",
            "version": "0.3.0-alpha",
            "documentation": "/docs",
            "health": "/health/live",
        }

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        return Response(status_code=204)

    @app.get("/health/live")
    async def liveness():
        return {"ok": True}

    @app.get("/health/ready")
    async def readiness():
        try:
            database_ready = resolved_runtime.repository.healthcheck()
        except Exception:
            database_ready = False
        try:
            redis_ready = bool(
                resolved_runtime.redis_client
                and resolved_runtime.redis_client.ping()
            )
        except Exception:
            redis_ready = False
        checks = {
            "database": database_ready,
            "redis": redis_ready,
            "executionMode": resolved_settings.execution_mode,
            "collectorMode": resolved_settings.collector_mode,
        }
        ready = all(value is True or isinstance(value, str) for value in checks.values())
        if not ready:
            raise HTTPException(status_code=503, detail=checks)
        return {"ok": True, "checks": checks}

    @app.get("/health/ops")
    async def operational_health():
        def marker(key: str):
            try:
                value = (
                    resolved_runtime.redis_client.get(key)
                    if resolved_runtime.redis_client
                    else None
                )
            except Exception:
                value = None
            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="replace")
            return {"healthy": bool(value), "lastSeenAt": value}

        checks = {
            "worker": marker(WORKER_HEALTH_KEY),
            "celeryBeat": marker(BEAT_HEALTH_KEY),
        }
        healthy = all(item["healthy"] for item in checks.values())
        response = {"ok": healthy, "checks": checks}
        if not healthy:
            raise HTTPException(status_code=503, detail=response)
        return response

    @app.get("/health")
    async def health_compatibility():
        return {
            "ok": True,
            "executionMode": resolved_settings.execution_mode,
            "collectorMode": resolved_settings.collector_mode,
        }

    @app.post("/auth/login", response_model=LoginResponse)
    async def login(payload: LoginRequest, request: Request, response: Response):
        rate_key = "%s:%s" % (
            request.client.host if request.client else "unknown",
            payload.username,
        )
        try:
            login_response, token = resolved_runtime.auth.login(
                payload.username,
                payload.password,
                rate_key,
            )
        except ValueError as error:
            raise HTTPException(status_code=401, detail=str(error)) from error
        response.set_cookie(
            SESSION_COOKIE,
            token,
            httponly=True,
            secure=resolved_settings.cookie_secure,
            samesite="strict",
            max_age=resolved_settings.session_ttl_hours * 3600,
            path="/",
        )
        resolved_runtime.service.audit(
            login_response.user.username,
            "auth.login",
            "session",
        )
        return login_response

    @app.post("/auth/logout", status_code=204)
    async def logout(
        request: Request,
        response: Response,
        user: User = Depends(mutation_user),
    ):
        resolved_runtime.auth.logout(request.cookies.get(SESSION_COOKIE))
        response.delete_cookie(SESSION_COOKIE, path="/")
        resolved_runtime.service.audit(user.username, "auth.logout", "session")
        return Response(status_code=204)

    @app.get("/auth/me", response_model=User)
    async def me(user: User = Depends(current_user)):
        return user

    @app.get("/credentials", response_model=list[SshCredential])
    async def list_credentials(user: User = Depends(current_user)):
        return resolved_runtime.credentials.list_credentials()

    @app.post("/credentials", response_model=SshCredential, status_code=201)
    async def upload_key(
        name: str = Form(...),
        key: UploadFile = File(...),
        user: User = Depends(mutation_user),
    ):
        try:
            credential = resolved_runtime.credentials.save_private_key(
                name,
                await key.read(),
            )
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        resolved_runtime.service.audit(
            user.username,
            "credential.created",
            "credential",
            credential.id,
            {"fingerprint": credential.fingerprint},
        )
        return credential

    @app.delete("/credentials/{credential_id}", status_code=204)
    async def delete_credential(
        credential_id: str,
        user: User = Depends(mutation_user),
    ):
        resolved_runtime.credentials.delete_credential(credential_id)
        resolved_runtime.service.audit(
            user.username,
            "credential.deleted",
            "credential",
            credential_id,
        )
        return Response(status_code=204)

    @app.get("/hosts", response_model=list[Host])
    async def list_hosts(user: User = Depends(current_user)):
        return resolved_runtime.service.list_hosts()

    @app.post("/hosts", response_model=Host, status_code=201)
    async def create_host(
        host: HostInput,
        user: User = Depends(mutation_user),
    ):
        return resolved_runtime.service.create_host(host, user.username)

    @app.put("/hosts/{host_id}", response_model=Host)
    async def update_host(
        host_id: str,
        host: HostInput,
        user: User = Depends(mutation_user),
    ):
        try:
            return resolved_runtime.service.update_host(
                host_id,
                host,
                user.username,
            )
        except ValueError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error

    @app.delete("/hosts/{host_id}", status_code=204)
    async def delete_host(
        host_id: str,
        user: User = Depends(mutation_user),
    ):
        try:
            resolved_runtime.service.delete_host(host_id, user.username)
        except ValueError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        return Response(status_code=204)

    @app.post(
        "/hosts/{host_id}/test-connection",
        response_model=ConnectionTestResult,
    )
    async def test_connection(
        host_id: str,
        payload: ConnectionTestRequest,
        user: User = Depends(mutation_user),
    ):
        try:
            return await resolved_runtime.service.test_connection(
                host_id,
                payload.confirm_fingerprint,
                user.username,
            )
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    @app.post("/scans", response_model=DurableJob, status_code=202)
    async def queue_scan(
        payload: ScanRequest,
        user: User = Depends(mutation_user),
    ):
        try:
            job = resolved_runtime.service.create_scan_job(
                payload,
                user.username,
            )
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        await resolved_dispatcher.dispatch(job)
        return resolved_runtime.service.get_job(job.id)

    @app.get("/scans", response_model=list[ScanJob])
    async def list_scans(
        host_id: Optional[str] = Query(default=None, alias="hostId"),
        user: User = Depends(current_user),
    ):
        return resolved_runtime.service.list_scans(host_id)

    @app.get("/scans/{scan_id}", response_model=ScanJob)
    async def get_scan(scan_id: str, user: User = Depends(current_user)):
        scan = resolved_runtime.service.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan

    @app.get("/hosts/{host_id}/findings")
    async def list_host_findings(
        host_id: str,
        user: User = Depends(current_user),
    ):
        return resolved_runtime.service.list_findings(host_id)

    @app.get("/findings")
    async def list_findings(user: User = Depends(current_user)):
        return resolved_runtime.service.list_findings()

    @app.get("/remediations", response_model=list[Remediation])
    async def list_remediations(user: User = Depends(current_user)):
        return resolved_runtime.service.list_remediations()

    @app.post(
        "/remediations/{remediation_id}/approve",
        response_model=Remediation,
    )
    async def approve_remediation(
        remediation_id: str,
        payload: ApprovalRequest,
        user: User = Depends(mutation_user),
    ):
        try:
            return resolved_runtime.service.approve_remediation_plan(
                remediation_id,
                payload,
                user.username,
            )
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    @app.post(
        "/remediations/{remediation_id}/reboot-approval",
        response_model=Remediation,
    )
    async def approve_remediation_reboot(
        remediation_id: str,
        payload: ApprovalRequest,
        user: User = Depends(mutation_user),
    ):
        try:
            return resolved_runtime.service.approve_remediation_reboot(
                remediation_id,
                payload,
                user.username,
            )
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    @app.post(
        "/remediations/{remediation_id}/execute",
        response_model=DurableJob,
        status_code=202,
    )
    async def execute_remediation(
        remediation_id: str,
        user: User = Depends(mutation_user),
    ):
        try:
            job = resolved_runtime.service.prepare_remediation_job(
                remediation_id,
                user.username,
            )
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        await resolved_dispatcher.dispatch(job)
        return resolved_runtime.service.get_job(job.id)

    @app.post(
        "/remediations/{remediation_id}/reject",
        response_model=Remediation,
    )
    async def reject_remediation(
        remediation_id: str,
        user: User = Depends(mutation_user),
    ):
        try:
            return resolved_runtime.service.reject_remediation(
                remediation_id,
                user.username,
            )
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    @app.get("/jobs", response_model=list[DurableJob])
    async def list_jobs(user: User = Depends(current_user)):
        return resolved_runtime.service.list_jobs()

    @app.get("/jobs/{job_id}", response_model=DurableJob)
    async def get_job(job_id: str, user: User = Depends(current_user)):
        job = resolved_runtime.service.get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        return job

    @app.get("/hosts/{host_id}/schedule", response_model=HostSchedule)
    async def get_schedule(host_id: str, user: User = Depends(current_user)):
        try:
            return resolved_runtime.service.get_schedule(host_id)
        except ValueError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error

    @app.put("/hosts/{host_id}/schedule", response_model=HostSchedule)
    async def update_schedule(
        host_id: str,
        payload: HostScheduleInput,
        user: User = Depends(mutation_user),
    ):
        try:
            return resolved_runtime.service.save_schedule(
                host_id,
                payload,
                user.username,
            )
        except (ValueError, KeyError) as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    @app.get("/schedules", response_model=list[HostSchedule])
    async def list_schedules(user: User = Depends(current_user)):
        return resolved_runtime.service.list_schedules()

    @app.get("/agent-runs")
    async def list_agent_runs(
        scan_id: Optional[str] = Query(default=None, alias="scanId"),
        user: User = Depends(current_user),
    ):
        return resolved_runtime.service.list_agent_runs(scan_id)

    @app.get("/agent-runs/{scan_id}/messages")
    async def list_agent_messages(
        scan_id: str,
        user: User = Depends(current_user),
    ):
        return resolved_runtime.service.list_agent_messages(scan_id)

    @app.get("/logs", response_model=LogPage)
    async def list_logs(
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=50, ge=1, le=200, alias="pageSize"),
        host_id: Optional[str] = Query(default=None, alias="hostId"),
        job_id: Optional[str] = Query(default=None, alias="jobId"),
        scan_id: Optional[str] = Query(default=None, alias="scanId"),
        remediation_id: Optional[str] = Query(default=None, alias="remediationId"),
        agent_run_id: Optional[str] = Query(default=None, alias="agentRunId"),
        severity: Optional[str] = None,
        source: Optional[str] = None,
        phase_id: Optional[str] = Query(default=None, alias="phaseId"),
        task_id: Optional[str] = Query(default=None, alias="taskId"),
        user: User = Depends(current_user),
    ):
        return resolved_runtime.service.list_logs(
            {
                "host_id": host_id,
                "job_id": job_id,
                "scan_id": scan_id,
                "remediation_id": remediation_id,
                "agent_run_id": agent_run_id,
                "severity": severity,
                "source": source,
                "phase_id": phase_id,
                "task_id": task_id,
            },
            page,
            page_size,
        )

    @app.get("/logs/{log_id}", response_model=StructuredLogEvent)
    async def get_log(log_id: str, user: User = Depends(current_user)):
        item = resolved_runtime.service.get_log(log_id)
        if not item:
            raise HTTPException(status_code=404, detail="Log event not found")
        return item

    @app.get("/alerts", response_model=list[Alert])
    async def list_alerts(user: User = Depends(current_user)):
        return resolved_runtime.service.list_alerts()

    @app.post("/alerts/{alert_id}/acknowledge", response_model=Alert)
    async def acknowledge_alert(
        alert_id: str,
        user: User = Depends(mutation_user),
    ):
        try:
            return resolved_runtime.service.acknowledge_alert(
                alert_id,
                user.username,
            )
        except ValueError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error

    @app.get("/audit-events", response_model=list[AuditEvent])
    async def list_audit_events(user: User = Depends(current_user)):
        return resolved_runtime.service.list_audits()

    @app.get("/campaigns", response_model=list[PatchCampaign])
    async def list_campaigns(user: User = Depends(current_user)):
        return resolved_runtime.service.list_campaigns()

    @app.get("/campaigns/{campaign_id}", response_model=PatchCampaign)
    async def get_campaign(
        campaign_id: str,
        user: User = Depends(current_user),
    ):
        try:
            return resolved_runtime.service.get_campaign(campaign_id)
        except ValueError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error

    @app.post("/campaigns", response_model=PatchCampaign, status_code=201)
    async def create_campaign(
        payload: CampaignRequest,
        user: User = Depends(mutation_user),
    ):
        try:
            return resolved_runtime.service.create_campaign(
                payload,
                user.username,
            )
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    @app.post(
        "/campaigns/{campaign_id}/proposals",
        response_model=CampaignActionResponse,
        status_code=202,
    )
    async def create_campaign_proposals(
        campaign_id: str,
        user: User = Depends(mutation_user),
    ):
        try:
            campaign, jobs = resolved_runtime.service.queue_campaign_proposals(
                campaign_id,
                user.username,
            )
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        for job in jobs:
            await resolved_dispatcher.dispatch(job)
        return CampaignActionResponse(
            campaign=resolved_runtime.service.get_campaign(campaign.id),
            jobs=[
                resolved_runtime.service.get_job(job.id)
                for job in jobs
                if resolved_runtime.service.get_job(job.id)
            ],
        )

    @app.post(
        "/campaigns/{campaign_id}/hosts/{host_id}/approve",
        response_model=PatchCampaign,
    )
    async def approve_campaign_host(
        campaign_id: str,
        host_id: str,
        payload: ApprovalRequest,
        user: User = Depends(mutation_user),
    ):
        try:
            return resolved_runtime.service.approve_campaign_host(
                campaign_id,
                host_id,
                payload,
                user.username,
            )
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    @app.post(
        "/campaigns/{campaign_id}/hosts/{host_id}/reboot-approval",
        response_model=PatchCampaign,
    )
    async def approve_campaign_host_reboot(
        campaign_id: str,
        host_id: str,
        payload: ApprovalRequest,
        user: User = Depends(mutation_user),
    ):
        try:
            return resolved_runtime.service.approve_campaign_host_reboot(
                campaign_id,
                host_id,
                payload,
                user.username,
            )
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    @app.post(
        "/campaigns/{campaign_id}/hosts/{host_id}/reject",
        response_model=PatchCampaign,
    )
    async def reject_campaign_host(
        campaign_id: str,
        host_id: str,
        user: User = Depends(mutation_user),
    ):
        try:
            return resolved_runtime.service.reject_campaign_host(
                campaign_id,
                host_id,
                user.username,
            )
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    @app.post(
        "/campaigns/{campaign_id}/execute",
        response_model=CampaignActionResponse,
        status_code=202,
    )
    async def execute_campaign(
        campaign_id: str,
        user: User = Depends(mutation_user),
    ):
        try:
            campaign, jobs = resolved_runtime.service.prepare_campaign_execution(
                campaign_id,
                user.username,
            )
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        for job in jobs:
            await resolved_dispatcher.dispatch(job)
        return CampaignActionResponse(
            campaign=resolved_runtime.service.get_campaign(campaign.id),
            jobs=[
                resolved_runtime.service.get_job(job.id)
                for job in jobs
                if resolved_runtime.service.get_job(job.id)
            ],
        )

    @app.post(
        "/campaigns/{campaign_id}/cancel",
        response_model=PatchCampaign,
    )
    async def cancel_campaign(
        campaign_id: str,
        user: User = Depends(mutation_user),
    ):
        try:
            return resolved_runtime.service.cancel_campaign(
                campaign_id,
                user.username,
            )
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

    return app


app = create_app()

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from typing import Dict, List, Optional
from datetime import datetime
import boto3
import os
from pydantic_settings import BaseSettings
from cloud_scanner import CloudScanner, NotificationService, Finding

class Settings(BaseSettings):
    SLACK_WEBHOOK_URL: Optional[str] = None
    TEAMS_WEBHOOK_URL: Optional[str] = None
    AWS_REGION: str = "us-west-2"
    AWS_ACCESS_KEY_ID: str
    AWS_SECRET_ACCESS_KEY: str
    
    class Config:
        env_file = ".env"

settings = Settings()
app = FastAPI(title="Cloud Scanner API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize notification service
notification_service = NotificationService(
    slack_webhook=settings.SLACK_WEBHOOK_URL,
    teams_webhook=settings.TEAMS_WEBHOOK_URL
)

active_scans = set()
scan_results = {}

@app.post("/api/scan/start")
async def start_scan(background_tasks: BackgroundTasks):
    """Start a new cloud configuration scan"""
    scan_id = str(datetime.now().timestamp())
    if scan_id in active_scans:
        raise HTTPException(status_code=400, detail="Scan already in progress")
    
    active_scans.add(scan_id)
    background_tasks.add_task(run_scan, scan_id)
    
    return {"scan_id": scan_id, "status": "started"}

@app.get("/api/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get the status of a scan"""
    if scan_id not in active_scans and scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan_id in scan_results:
        return {"scan_id": scan_id, "status": "completed"}
    else:
        return {"scan_id": scan_id, "status": "in_progress"}

@app.get("/api/scan/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """Get the results of a scan"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return scan_results[scan_id]

@app.get("/api/scan/{scan_id}/export")
async def export_scan_results(scan_id: str, format: str = "csv"):
    """Export scan results in specified format"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Create export directory if it doesn't exist
    os.makedirs("exports", exist_ok=True)
    
    findings = scan_results[scan_id]["findings"]
    scanner = CloudScanner(boto3.Session(
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_REGION
    ))
    scanner.findings = findings
    
    if format.lower() == "csv":
        filename = f"exports/scan_{scan_id}.csv"
        scanner.export_findings_csv(filename)
    elif format.lower() == "pdf":
        filename = f"exports/scan_{scan_id}.pdf"
        scanner.export_findings_pdf(filename)
    else:
        raise HTTPException(status_code=400, detail="Unsupported export format")
    
    return FileResponse(
        path=filename,
        filename=os.path.basename(filename),
        media_type='application/octet-stream'
    )

@app.post("/api/notifications/test")
async def test_notifications():
    """Test notification integration"""
    test_finding = Finding(
        severity="HIGH",
        resource_id="test-resource",
        rule_id="TEST_NOTIFICATION",
        description="This is a test notification",
        remediation="No action needed - test only",
        compliance_standards=["TEST.1"],
        timestamp=datetime.now(),
        service="TEST",
        region=settings.AWS_REGION,
        account_id="123456789012"
    )
    
    if notification_service:
        notification_service.send_slack_notification([test_finding])
        notification_service.send_teams_notification([test_finding])
        return {"status": "Notifications sent"}
    
    raise HTTPException(status_code=400, detail="Notification service not configured")

async def run_scan(scan_id: str):
    """Run the cloud configuration scan"""
    session = boto3.Session(
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_REGION
    )
    scanner = CloudScanner(session)
    
    findings = []
    findings.extend(scanner.scan_ec2_instances())
    findings.extend(scanner.scan_s3_buckets())
    findings.extend(scanner.scan_iam_users())
    findings.extend(scanner.scan_rds_instances())
    
    scan_results[scan_id] = {
        "scan_id": scan_id,
        "status": "completed",
        "findings": findings
    }
    
    active_scans.remove(scan_id)
    
    if notification_service:
        notification_service.send_slack_notification(findings)
        notification_service.send_teams_notification(findings)

def list_s3_buckets():
    session = boto3.Session(
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_REGION
    )
    s3_client = session.client('s3')
    response = s3_client.list_buckets()
    for bucket in response['Buckets']:
        print(bucket['Name'])

if __name__ == "__main__":
    list_s3_buckets()
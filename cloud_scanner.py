import boto3
from datetime import datetime
import logging
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
import json
import csv
import io
from fpdf import FPDF
import requests

@dataclass
class Finding:
    """Represents a security finding/violation"""
    severity: str
    resource_id: str
    rule_id: str
    description: str
    remediation: str
    compliance_standards: List[str]
    timestamp: datetime
    service: str
    region: str
    account_id: str

class NotificationService:
    """Handles notifications to Slack and Microsoft Teams"""
    def __init__(self, slack_webhook: Optional[str], teams_webhook: Optional[str]):
        self.slack_webhook = slack_webhook
        self.teams_webhook = teams_webhook

    def send_slack_notification(self, findings: List[Finding]):
        if not self.slack_webhook:
            return
        message = self._format_message(findings)
        requests.post(self.slack_webhook, json={"text": message})

    def send_teams_notification(self, findings: List[Finding]):
        if not self.teams_webhook:
            return
        message = self._format_message(findings)
        requests.post(self.teams_webhook, json={"text": message})

    def _format_message(self, findings: List[Finding]) -> str:
        messages = []
        for finding in findings:
            messages.append(f"Severity: {finding.severity}\n"
                            f"Resource ID: {finding.resource_id}\n"
                            f"Rule ID: {finding.rule_id}\n"
                            f"Description: {finding.description}\n"
                            f"Remediation: {finding.remediation}\n"
                            f"Compliance Standards: {', '.join(finding.compliance_standards)}\n"
                            f"Timestamp: {finding.timestamp}\n"
                            f"Service: {finding.service}\n"
                            f"Region: {finding.region}\n"
                            f"Account ID: {finding.account_id}\n")
        return "\n\n".join(messages)

class CloudScanner:
    def __init__(self, session: boto3.Session):
        self.session = session
        self.account_id = self.session.client('sts').get_caller_identity().get('Account')
        self.logger = logging.getLogger(__name__)

    def scan_ec2_instances(self) -> List[Finding]:
        """Scan EC2 instances for security misconfigurations"""
        ec2_client = self.session.client('ec2')
        findings = []

        try:
            instances = ec2_client.describe_instances()['Reservations']
            for reservation in instances:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    
                    # Check for public IP address
                    if instance.get('PublicIpAddress'):
                        findings.append(Finding(
                            severity="HIGH",
                            resource_id=instance_id,
                            rule_id="EC2_PUBLIC_IP",
                            description="EC2 instance has a public IP address",
                            remediation="Remove the public IP address or use a private IP address",
                            compliance_standards=["CIS.5.1", "NIST.SC-7"],
                            timestamp=datetime.now(),
                            service="EC2",
                            region=instance['Placement']['AvailabilityZone'][:-1],
                            account_id=self.account_id
                        ))

                    # Check for outdated AMI
                    if 'ami-12345678' in instance.get('ImageId', ''):
                        findings.append(Finding(
                            severity="MEDIUM",
                            resource_id=instance_id,
                            rule_id="EC2_OUTDATED_AMI",
                            description="EC2 instance uses an outdated AMI",
                            remediation="Update the instance to use a current AMI",
                            compliance_standards=["NIST.SI-2", "CIS.4.8"],
                            timestamp=datetime.now(),
                            service="EC2",
                            region=instance['Placement']['AvailabilityZone'][:-1],
                            account_id=self.account_id
                        ))

        except Exception as e:
            self.logger.error(f"Error scanning EC2 instances: {str(e)}")

        return findings

    def scan_s3_buckets(self) -> List[Finding]:
        """Scan S3 buckets for security misconfigurations"""
        s3_client = self.session.client('s3')
        findings = []

        try:
            buckets = s3_client.list_buckets()['Buckets']
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                # Check for public access
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl['Grants']:
                    if grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        findings.append(Finding(
                            severity="HIGH",
                            resource_id=bucket_name,
                            rule_id="S3_PUBLIC_ACCESS",
                            description="S3 bucket has public access",
                            remediation="Remove public access from the bucket",
                            compliance_standards=["CIS.3.1", "NIST.AC-3"],
                            timestamp=datetime.now(),
                            service="S3",
                            region=self.session.region_name,
                            account_id=self.account_id
                        ))

        except Exception as e:
            self.logger.error(f"Error scanning S3 buckets: {str(e)}")

        return findings

    def scan_iam_users(self) -> List[Finding]:
        """Scan IAM users for security misconfigurations"""
        iam_client = self.session.client('iam')
        findings = []

        try:
            users = iam_client.list_users()['Users']
            for user in users:
                user_name = user['UserName']
                
                # Check for MFA
                mfa_devices = iam_client.list_mfa_devices(UserName=user_name)['MFADevices']
                if not mfa_devices:
                    findings.append(Finding(
                        severity="HIGH",
                        resource_id=user_name,
                        rule_id="IAM_NO_MFA",
                        description="IAM user does not have MFA enabled",
                        remediation="Enable MFA for the IAM user",
                        compliance_standards=["CIS.1.2", "NIST.IA-2"],
                        timestamp=datetime.now(),
                        service="IAM",
                        region=self.session.region_name,
                        account_id=self.account_id
                    ))

        except Exception as e:
            self.logger.error(f"Error scanning IAM users: {str(e)}")

        return findings

    def scan_rds_instances(self) -> List[Finding]:
        """Scan RDS instances for security misconfigurations"""
        rds_client = self.session.client('rds')
        findings = []

        try:
            instances = rds_client.describe_db_instances()['DBInstances']
            for instance in instances:
                instance_id = instance['DBInstanceIdentifier']
                
                # Check for public accessibility
                if instance.get('PubliclyAccessible'):
                    findings.append(Finding(
                        severity="HIGH",
                        resource_id=instance_id,
                        rule_id="RDS_PUBLIC_ACCESS",
                        description="RDS instance is publicly accessible",
                        remediation="Disable public accessibility for the RDS instance",
                        compliance_standards=["CIS.4.1", "NIST.SC-7"],
                        timestamp=datetime.now(),
                        service="RDS",
                        region=instance['AvailabilityZone'][:-1],
                        account_id=self.account_id
                    ))

        except Exception as e:
            self.logger.error(f"Error scanning RDS instances: {str(e)}")

        return findings

    def export_findings_csv(self, filename: str):
        """Export findings to a CSV file"""
        with open(filename, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Severity', 'Resource ID', 'Rule ID', 'Description', 'Remediation', 'Compliance Standards', 'Timestamp', 'Service', 'Region', 'Account ID'])
            for finding in self.findings:
                writer.writerow([finding.severity, finding.resource_id, finding.rule_id, finding.description, finding.remediation, ', '.join(finding.compliance_standards), finding.timestamp, finding.service, finding.region, finding.account_id])

    def export_findings_pdf(self, filename: str):
        """Export findings to a PDF file"""
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        for finding in self.findings:
            pdf.cell(200, 10, txt=f"Severity: {finding.severity}", ln=True)
            pdf.cell(200, 10, txt=f"Resource ID: {finding.resource_id}", ln=True)
            pdf.cell(200, 10, txt=f"Rule ID: {finding.rule_id}", ln=True)
            pdf.cell(200, 10, txt=f"Description: {finding.description}", ln=True)
            pdf.cell(200, 10, txt=f"Remediation: {finding.remediation}", ln=True)
            pdf.cell(200, 10, txt=f"Compliance Standards: {', '.join(finding.compliance_standards)}", ln=True)
            pdf.cell(200, 10, txt=f"Timestamp: {finding.timestamp}", ln=True)
            pdf.cell(200, 10, txt=f"Service: {finding.service}", ln=True)
            pdf.cell(200, 10, txt=f"Region: {finding.region}", ln=True)
            pdf.cell(200, 10, txt=f"Account ID: {finding.account_id}", ln=True)
            pdf.cell(200, 10, ln=True)  # Add a blank line
        pdf.output(filename)
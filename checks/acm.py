import boto3
import json
import logging

from utils.utils import describe_regions

from datetime import datetime
from datetime import timedelta

class acm(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)
        self.certificates = self.get_certificates()

    def run(self):
        findings = []
        findings += [ self.acm_1() ]
        findings += [ self.acm_2() ]
        return findings
    
    def get_certificates(self):
        # returns list of certificates
        logging.info("Getting Certificate List")
        certificates = {}
        for region in self.regions:
            client = self.session.client('acm', region_name=region)
            try:
                certificates[region] = client.list_certificates()["CertificateSummaryList"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting certificate list - %s" % e.response["Error"]["Code"])
        return certificates


    def acm_1(self):
        # ACM Certificate with Transparency Logging Set to Disabled

        results = {
            "id" : "acm_1",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "acm",
            "name" : "ACM Certificate with Transparency Logging Set to Disabled",
            "affected": [],
            "analysis" : "",
            "description" : "The account under review contains SSL/TLS certificates that do not have Transparency logging enabled. Disabling Transparency Logging may result in browsers not trusting your certificate. As of April 30 2018, Google Chrome no longer trusts public SSL/TLS certificates that are not recorded in a certificate transparency log. Transparency Logging should be enabled as a best practice.",
            "remediation" : "Enable Certificate Transparancy Logging on all certificates.",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
            "cvss_score" : "5.3",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        
        for region, certificates in self.certificates.items():
            client = self.session.client('acm', region_name=region)
            for certificate in certificates:
                description = client.describe_certificate(CertificateArn=certificate["CertificateArn"])["Certificate"]
                if description["Options"]["CertificateTransparencyLoggingPreference"] != "ENABLED":
                    results["affected"].append(certificate["CertificateArn"])

        if results["affected"]:
            results["analysis"] = "The affected Certificates do not have transparancy logging enabled."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found."
            results["pass_fail"] = "PASS"
        
        return results
    
    def acm_2(self):
        # Expired ACM Certificates

        results = {
            "id" : "acm_2",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "acm",
            "name" : "Expired ACM Certificates",
            "affected": [],
            "analysis" : "",
            "description" : "The account under review contains SSL/TLS certificates that have expired. Expired certificates will often result in users not being able to connect to your service resulting in loss of availability.",
            "remediation" : "Monitor certificate expiration and take action to renew; replace or remove expired certificates as requried. AWS Config can be used to monitor your account for expired certificates with the managed rule acm-certificate-expiration-check.",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
            "cvss_score" : "5.3",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        
        for region, certificates in self.certificates.items():
            client = self.session.client('acm', region_name=region)
            for certificate in certificates:
                description = client.describe_certificate(CertificateArn=certificate["CertificateArn"])["Certificate"]
                if datetime.today() > datetime(description["NotAfter"].year, description["NotAfter"].month, description["NotAfter"].day, description["NotAfter"].hour, description["NotAfter"].minute):
                    results["affected"].append(certificate["CertificateArn"])

        if results["affected"]:
            results["analysis"] = "The affected Certificates have expired."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No expired certificates found."
            results["pass_fail"] = "PASS"
        
        return results
    
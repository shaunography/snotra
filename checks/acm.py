import boto3
import json
import logging

from utils.utils import describe_regions
from utils.utils import get_account_id

from datetime import datetime
from datetime import timedelta

class acm(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)
        self.certificates = self.get_certificates()
        self.descriptions = self.get_descriptions()
        self.tags = self.get_tags()
        self.account_id = get_account_id(session)

    def run(self):
        findings = []
        findings += [ self.acm_1() ]
        findings += [ self.acm_2() ]
        findings += [ self.acm_3() ]
        findings += [ self.acm_4() ]
        return findings
    
    def get_certificates(self):
        # returns list of certificates
        logging.info("Getting Certificate List")
        certificates = {}
        for region in self.regions:
            client = self.session.client('acm', region_name=region)
            try:
                certificate_summary_list = client.list_certificates()["CertificateSummaryList"]
                if certificate_summary_list:
                    certificates[region] = certificate_summary_list
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting certificate list - %s" % e.response["Error"]["Code"])
        return certificates

    def get_descriptions(self):
        descriptions = {}
        logging.info("Getting Certificate Descriptions")
        for region, certificates in self.certificates.items():
            descriptions[region] = []
            client = self.session.client('acm', region_name=region)
            for certificate in certificates:
                try:
                    logging.info(f'Getting Certificate Description for { certificate["CertificateArn"] }')
                    description = client.describe_certificate(CertificateArn=certificate["CertificateArn"])["Certificate"]
                    if description:
                        descriptions[region].append(description)
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting certificate description - %s" % e.response["Error"]["Code"])
        return descriptions

    def get_tags(self):
        tags = {}
        logging.info("Getting Certificate Tags")
        for region, certificates in self.certificates.items():
            tags[region] = {}
            client = self.session.client('acm', region_name=region)
            for certificate in certificates:
                tags[region][certificate["CertificateArn"]] = []
                try:
                    logging.info(f'Getting Certificate Tags for { certificate["CertificateArn"] }')
                    tags_list = client.list_tags_for_certificate(CertificateArn=certificate["CertificateArn"])["Tags"]
                    if tags_list:
                        tags[region][certificate["CertificateArn"]] = tags_list
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting certificate Tags - %s" % e.response["Error"]["Code"])
        return tags

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
        
        for region, descriptions in self.descriptions.items():
            for certificate in descriptions:
                if certificate["Options"]["CertificateTransparencyLoggingPreference"] != "ENABLED":
                    results["affected"].append(certificate["CertificateArn"])

        if results["affected"]:
            results["analysis"] = "The affected Certificates do not have transparancy logging enabled."
            results["pass_fail"] = "FAIL"
        elif self.certificates:
            results["analysis"] = "No issues found."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        else:
            results["analysis"] = "No Certificates In Use"
            results["affected"].append(self.account_id)
        
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
        
        for region, descriptions in self.descriptions.items():
            for description in descriptions:
                try:
                    if datetime.today() > datetime(description["NotAfter"].year, description["NotAfter"].month, description["NotAfter"].day, description["NotAfter"].hour, description["NotAfter"].minute):
                        results["affected"].append(description["CertificateArn"])
                except KeyError:
                    logging.error("Error getting certificate expiration date")

        if results["affected"]:
            results["analysis"] = "The affected Certificates have expired."
            results["pass_fail"] = "FAIL"
        elif self.certificates:
            results["analysis"] = "No expired certificates found."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        else:
            results["analysis"] = "No Certificates In Use."
            results["affected"].append(self.account_id)
        
        return results
    
    def acm_3(self):
        # RSA certificates managed by ACM should use a key length of at least 2,048 bits

        results = {
            "id" : "acm_3",
            "ref" : "ACM.2",
            "compliance" : "FSBP",
            "level" : "N/A",
            "service" : "acm",
            "name" : "RSA certificates managed by ACM should use a key length of at least 2,048 bits",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether RSA certificates managed by AWS Certificate Manager use a key length of at least 2,048 bits. The control fails if the key length is smaller than 2,048 bits. The strength of encryption directly correlates with key size. We recommend key lengths of at least 2,048 bits to protect your AWS resources as computing power becomes less expensive and servers become more advanced.",
            "remediation" : "The minimum key length for RSA certificates issued by ACM is already 2,048 bits. For instructions on issuing new RSA certificates with ACM, see Issuing and managing certificates in the AWS Certificate Manager User Guide. While ACM allows you to import certificates with shorter key lengths, you must use keys of at least 2,048 bits to pass this control. You can't change the key length after importing a certificate. Instead, you must delete certificates with a key length smaller than 2,048 bits. For more information about importing certificates into ACM, see Prerequisites for importing certificates in the AWS Certificate Manager User Guide.",
            "impact" : "high",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "cvss_score" : "7.4",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        # 'KeyAlgorithm': 'RSA_1024'|'RSA_2048'|'RSA_3072'|'RSA_4096'|'EC_prime256v1'|'EC_secp384r1'|'EC_secp521r1',
        for region, descriptions in self.descriptions.items():
            for certificate in descriptions:
                if certificate["KeyAlgorithm"] == "RSA_1024":
                    results["affected"].append(certificate["CertificateArn"])

        if results["affected"]:
            results["analysis"] = "The affected Certificates are using a key length of 1024 bits."
            results["pass_fail"] = "FAIL"
        elif self.certificates:
            results["analysis"] = "No vulnerable certificates found."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        else:
            results["analysis"] = "No Certificates In Use."
            results["affected"].append(self.account_id)
        
        return results
    
    def acm_4(self):
        # ACM certificates should be tagged

        results = {
            "id" : "acm_4",
            "ref" : "ACM.3",
            "compliance" : "FSBP",
            "level" : "N/A",
            "service" : "acm",
            "name" : "ACM certificates should be tagged",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether an AWS Certificate Manager (ACM) certificate has tags with the specific keys defined in the parameter requiredTagKeys. The control fails if the certificate doesn’t have any tag keys or if it doesn’t have all the keys specified in the parameter requiredTagKeys. If the parameter requiredTagKeys isn't provided, the control only checks for the existence of a tag key and fails if the certificate isn't tagged with any key. System tags, which are automatically applied and begin with aws:, are ignored. A tag is a label that you assign to an AWS resource, and it consists of a key and an optional value. You can create tags to categorize resources by purpose, owner, environment, or other criteria. Tags can help you identify, organize, search for, and filter resources. Tagging also helps you track accountable resource owners for actions and notifications. When you use tagging, you can implement attribute-based access control (ABAC) as an authorization strategy, which defines permissions based on tags. You can attach tags to IAM entities (users or roles) and to AWS resources. You can create a single ABAC policy or a separate set of policies for your IAM principals. You can design these ABAC policies to allow operations when the principal's tag matches the resource tag. For more information, see What is ABAC for AWS? in the IAM User Guide.",
            "remediation" : "To add tags to an ACM certificate, see Tagging AWS Certificate Manager certificates in the AWS Certificate Manager User Guide.\nMore Information:\nhttps://docs.aws.amazon.com/acm/latest/userguide/tags.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, certificates in self.certificates.items():
            client = self.session.client('acm', region_name=region)
            for certificate in certificates:
                try:
                    logging.info(f'Getting Certificate Tags for { certificate["CertificateArn"] }')
                    tags_list = client.list_tags_for_certificate(CertificateArn=certificate["CertificateArn"])["Tags"]
                    if not tags_list:
                        results["affected"].append(certificate["CertificateArn"])
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting certificate Tags - %s" % e.response["Error"]["Code"])


        if results["affected"]:
            results["analysis"] = "The affected Certificates do not have tags attached"
            results["pass_fail"] = "FAIL"
        elif self.certificates:
            results["analysis"] = "No vulnerable certificates found."
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)
        else:
            results["analysis"] = "No Certificates In Use."
            results["affected"].append(self.account_id)
        
        return results
    

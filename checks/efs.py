import boto3
import logging

from utils.utils import describe_regions
from utils.utils import get_account_id

class efs(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)
        self.file_systems = self.describe_file_systems()
        self.account_id = get_account_id(session)

    def run(self):
        findings = []
        findings += [ self.efs_1() ]
        findings += [ self.efs_2() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.efs_2() ]
        return findings

    def describe_file_systems(self):
        file_systems = {}
        logging.info("getting file systems")
        for region in self.regions:
            client = self.session.client('efs', region_name=region)
            try:
                file_systems[region] = client.describe_file_systems()["FileSystems"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting file systems - %s" % e.response["Error"]["Code"])
        return file_systems
        
    def efs_1(self):
        # efs grants access to all clients
        
        results = {
            "id" : "efs_1",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "efs",
            "name" : "EFS Grants Access To All Clients",
            "affected": [],
            "analysis" : "",
            "description" : "The account being reviewed was found to contain an EFS (elastic File System) that has no File System Policy configured and therefore allows network clients to access all files hosted on the system without any restrictions. To minimise the risk of sensitive date being disclosed to unauthorised network bearers consider implementing IAM policies to control who can access the filesystem and what actions they can perform (read, write, etc).",
            "remediation" : "Configure a File System Policy for the affect EFS end points and apply the principle of least privilege. More Information https://docs.aws.amazon.com/efs/latest/ug/iam-access-control-nfs-efs.html",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
            "cvss_score" : "5.6",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        all_file_systems = []

        for region, file_systems in self.file_systems.items():
            client = self.session.client('efs', region_name=region)
            
            for file_system in file_systems:
                file_system_id = file_system["FileSystemId"]
                all_file_systems += [file_system_id]
                try:
                    file_system_policy = client.describe_file_system_policy(FileSystemId=file_system_id)
                except boto3.exceptions.botocore.errorfactory.ClientError:
                    results["affected"].append("{}({})".format(file_system_id, region))
        
        if not all_file_systems:
            results["analysis"] = "No File Systems in use"
            results["affected"].append(self.account_id)
        else:
            if results["affected"]:
                results["analysis"] = "The affected file systems do not have an access policy configured and therefore allow access from all clients."
                results["pass_fail"] = "FAIL"
            else:
                results["analysis"] = "All file systems have an access policy configured."
                results["pass_fail"] = "PASS"
                results["affected"].append(self.account_id)
        
        return results

    def efs_2(self):
        # Ensure that encryption is enabled for EFS file systems (Manual)
        
        results = {
            "id" : "efs_2",
            "ref" : "2.4.1",
            "compliance" : "cis",
            "level" : "N/A",
            "service" : "efs",
            "name" : "Ensure that encryption is enabled for EFS file systems (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "EFS data should be encrypted at rest using AWS KMS (Key Management Service). Data should be encrypted at rest to reduce the risk of a data breach via direct access to the storage device.",
            "remediation" : "Enable AWS KMS encryption for all Elastic File Systems.",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        all_file_systems = []

        for region, file_systems in self.file_systems.items():
            for file_system in file_systems:
                file_system_id = file_system["FileSystemId"]
                all_file_systems += [file_system_id]
                try:
                    if file_system["Encrypted"] != True:
                        results["affected"].append("{}({})".format(file_system_id, region))
                except KeyError:
                    logging.error("Error getting file systems encryption status, check manually - %s" % e.response["Error"]["Code"])

        if not all_file_systems:
            results["analysis"] = "No File Systems in use"
            results["affected"].append(self.account_id)
        else:
            if results["affected"]:
                results["analysis"] = "The affected file systems are not encrypted."
                results["pass_fail"] = "FAIL"
            else:
                results["analysis"] = "All file are encrypted."
                results["pass_fail"] = "PASS"
                results["affected"].append(self.account_id)
            
        return results

import boto3
import logging

from utils.utils import describe_regions

class rds(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)
        self.instances = self.describe_db_instances()

    def run(self):
        findings = []
        findings += [ self.rds_1() ]
        findings += [ self.rds_2() ]
        return findings

    def describe_db_instances(self):
        instances = {}
        logging.info("getting instance reservations")
        for region in self.regions:
            client = self.session.client('rds', region_name=region)
            try:
                instances[region] = client.describe_db_instances()["DBInstances"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting db instances - %s" % e.response["Error"]["Code"])
        return instances
        
    def rds_1(self):
        # Ensure that encryption is enabled for RDS Instances (Automated)

        results = {
            "id" : "rds_1",
            "ref" : "2.3.1",
            "compliance" : "cis",
            "level" : 1,
            "service" : "rds",
            "name" : "Ensure that encryption is enabled for RDS Instances",
            "affected": [],
            "analysis" : "",
            "description" : "Amazon RDS encrypted DB instances use the industry standard AES-256 encryption algorithm to encrypt your data on the server that hosts your Amazon RDS DB instances. After your data is encrypted, Amazon RDS handles authentication of access and decryption of your data transparently with a minimal impact on performance. Databases are likely to hold sensitive and critical data, it is highly recommended to implement encryption in order to protect your data from unauthorized access or disclosure. With RDS encryption enabled, the data stored on the instance's underlying storage, the automated backups, read replicas, and snapshots, are all encrypted.",
            "remediation" : "Ensure that encryption is enabled for all RDS Instances",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        
        for region, instances in self.instances.items():
            client = self.session.client('rds', region_name=region)
            for instance in instances:
                db_instance_identifier = instance["DBInstanceIdentifier"]
                if instance["StorageEncrypted"] != True:
                        results["affected"] += [db_instance_identifier]

        if results["affected"]:
            results["analysis"] = "The affected RDS instances do not have encryption enabled."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "All RDS instances have encryption enabled."
            results["pass_fail"] = "PASS"
        
        return results


    def rds_2(self):
        # RDS Instances Do Not Have Deletion Protection Enabled

        results = {
            "id" : "rds_2",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "rds",
            "name" : "RDS Instances Do Not Have Deletion Protection Enabled",
            "affected": [],
            "analysis" : "",
            "description" : "RDS instances were identified which do not have deletion protection enabled. To minimise the risk of data loss it recommended to enabled deletion protection on at least production databases. Amazon RDS enforces deletion protection when you use the console, the CLI, or the API to delete a DB instance. To delete a DB instance that has deletion protection enabled, first modify the instance and disable deletion protection. Enabling or disabling deletion protection doesn't cause an outage.",
            "remediation" : "Enable Deletion Protection on all affected RDS instances.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        
        for region, instances in self.instances.items():
            client = self.session.client('rds', region_name=region)
            for instance in instances:
                if instance["DeletionProtection"] == False:
                    results["affected"].append(instance["DBInstanceIdentifier"])

        if results["affected"]:
            results["analysis"] = "The affected RDS Instances do not have deletion protection enabled."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "All RDS instances have encryption enabled."
            results["pass_fail"] = "PASS"
        
        return results

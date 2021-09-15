import boto3

from utils.utils import describe_regions

class rds(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)

    def run(self):
        findings = []
        findings += [ self.rds_1() ]
        return findings
        
    def rds_1(self):
        # Ensure that encryption is enabled for RDS Instances (Automated)

        results = {
            "id" : "rds_1",
            "ref" : "2.3.1",
            "compliance" : "cis",
            "level" : 1,
            "service" : "rds",
            "name" : "Ensure that encryption is enabled for RDS Instances",
            "affected": "",
            "analysis" : "All RDS instances have encryption enabled",
            "description" : "Amazon RDS encrypted DB instances use the industry standard AES-256 encryption algorithm to encrypt your data on the server that hosts your Amazon RDS DB instances. After your data is encrypted, Amazon RDS handles authentication of access and decryption of your data transparently with a minimal impact on performance. Databases are likely to hold sensitive and critical data, it is highly recommended to implement encryption in order to protect your data from unauthorized access or disclosure. With RDS encryption enabled, the data stored on the instance's underlying storage, the automated backups, read replicas, and snapshots, are all encrypted.",
            "remediation" : "Ensure that encryption is enabled for all RDS Instances",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : "PASS"
        }

        print("running check: rds_1")

        failing_instances = []
        
        for region in self.regions:
            client = self.session.client('rds', region_name=region)
            instances = client.describe_db_instances()["DBInstances"]
            for instance in instances:
                db_instance_identifier = instance["DBInstanceIdentifier"]
                instance_description = client.describe_db_instances(DBInstanceIdentifier=db_instance_identifier)["DBInstances"][0]
                if instance_description["StorageEncrypted"] != True:
                    failing_instances += [db_instance_identifier]

        if failing_instances:
            results["analysis"] = "the following EC2 regions do not encrypt EBS volumes by default: {}".format(" ".join(failing_instances))
            results["affected"] = ", ".join(failing_instances)
            results["pass_fail"] = "FAIL"
        
        return results

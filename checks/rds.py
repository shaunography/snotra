import boto3

from utils.utils import describe_regions

class rds(object):

    def __init__(self):
        self.regions = describe_regions()

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
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : "PASS"
        }

        print("running check: rds_1")

        failing_instances = []
        
        for region in self.regions:
            client = boto3.client('rds', region_name=region)
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

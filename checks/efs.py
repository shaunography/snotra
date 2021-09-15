import boto3

from utils.utils import describe_regions

class efs(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)

    def run(self):
        findings = []
        findings += [ self.efs_1() ]
        return findings
        
    def efs_1(self):
        # efs grants access to all clients
        
        results = {
            "id" : "efs_1",
            "ref" : "n/a",
            "compliance" : "n/a",
            "level" : "n/a",
            "service" : "efs",
            "name" : "EFS Grants Access To All Clients",
            "affected": "",
            "analysis" : "All file systems have an access policy configured",
            "description" : "The account being reviewed was found to contain an EFS (elastic File System) that has no File System Policy configured and therefore allows network clients to access all files hosted on the system without any restrictions. To minimise the risk of sensitive date being disclosed to unauthorised network bearers consider implementing IAM policies to control who can access the filesystem and what actions they can perform (read, write, etc).",
            "remediation" : "Configure a File System Policy for the affect EFS end points and apply the principle of least privilege. More Information https://docs.aws.amazon.com/efs/latest/ug/iam-access-control-nfs-efs.html",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
            "cvss_score" : "5.6",
            "pass_fail" : "PASS"
        }

        print("running check: efs_1")

        failing_file_systems = []
        all_file_systems = []

        for region in self.regions:
            client = self.session.client('efs', region_name=region)
            file_systems = client.describe_file_systems()["FileSystems"]
            for file_system in file_systems:
                file_system_id = file_system["FileSystemId"]
                all_file_systems += [file_system["Name"]]
                try:
                    file_system_policy = client.describe_file_system_policy(FileSystemId=file_system_id)
                except boto3.exceptions.botocore.errorfactory.ClientError:
                    failing_file_systems += ["{}({})".format(file_system_id, region)]
        
        if not all_file_systems:
            results["analysis"] = "No File Systems in use"
            
        if failing_file_systems:
            results["analysis"] = "The following file systems do not have an access policy configured and therefore allow access from all clients: {}".format(" ".join(failing_file_systems))
            results["affected"] = ", ".join(failing_file_systems)
            results["pass_fail"] = "FAIL"
        
        return results

import boto3
import json

from utils.utils import describe_regions
from utils.utils import get_account_id

class cloudtrail(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)
        self.account_id = get_account_id(session)

    def run(self):
        findings = []
        findings += [ self.cloudtrail_1() ]
        findings += [ self.cloudtrail_2() ]
        findings += [ self.cloudtrail_3() ]
        findings += [ self.cloudtrail_4() ]
        findings += [ self.cloudtrail_5() ]
        findings += [ self.cloudtrail_6() ]
        findings += [ self.cloudtrail_7() ]
        findings += [ self.cloudtrail_8() ]
        return findings
    
    def cloudtrail_1(self):
        # Ensure CloudTrail is enabled in all regions (Automated)

        results = {
            "id" : "cloudtrail_1",
            "ref" : "3.1",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudtrail",
            "name" : "Ensure CloudTrail is enabled in all regions",
            "affected": "",
            "analysis" : "No multi region enabled trails were found",
            "description" : "AWS CloudTrail is a web service that records AWS API calls for your account and delivers log files to you. The recorded information includes the identity of the API caller, the time of the API call, the source IP address of the API caller, the request parameters, and the response elements returned by the AWS service. CloudTrail provides a history of AWS API calls for an account, including API calls made via the Management Console, SDKs, command line tools, and higher-level AWS services (such as CloudFormation).",
            "remediation" : "Enable CloudTrail in all regions",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "n/a",
            "cvss_score" : "n/a",
            "pass_fail" : "FAIL"
        }

        print("running check: cloudtrail_1")

        results["affected"] = self.account_id
        
        multi_region_trails = []
        
        for region in self.regions:
            client = self.session.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            for trail in trail_list:
                trail_name = trail["Name"]
                if trail["IsMultiRegionTrail"] == True:
                    if trail["HomeRegion"] == region:
                        if client.get_trail_status(Name=trail_name)["IsLogging"] == True:
                            multi_region_trails += [trail_name]

        if multi_region_trails:
            results["analysis"] = "the following trails are multi region enabled: {}".format(" ".join(multi_region_trails))
            #results["affected"] = ", ".join(multi_region_trails)
            results["pass_fail"] = "PASS"
        
        return results

    def cloudtrail_2(self):
        # Ensure CloudTrail log file validation is enabled (Automated)

        results = {
            "id" : "cloudtrail_2",
            "ref" : "3.2",
            "compliance" : "cis",
            "level" : 2,
            "service" : "cloudtrail",
            "name" : "Ensure CloudTrail log file validation is enabled",
            "affected": "",
            "analysis" : "log file validation is enabled on all trails",
            "description" : "CloudTrail log file validation creates a digitally signed digest file containing a hash of each log that CloudTrail writes to S3. These digest files can be used to determine whether a log file was changed, deleted, or unchanged after CloudTrail delivered the log. It is recommended that file validation be enabled on all CloudTrails. Enabling log file validation will provide additional integrity checking of CloudTrail logs.",
            "remediation" : "Enabled log file validation on all your trails",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "n/a",
            "cvss_score" : "n/a",
            "pass_fail" : "PASS"
        }

        print("running check: cloudtrail_2")

        trails = []
        failing_trails = []
        
        for region in self.regions:
            client = self.session.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            trails += trail_list
            for trail in trail_list:
                if trail["LogFileValidationEnabled"] == False:
                        failing_trails += [trail["Name"]]

        if not trails:
            results["analysis"] = "no CloudTrail Trails in use"
            results["pass_fail"] = "FAIL"

        if failing_trails:
            results["analysis"] = "the following trails do not have log file validation enabled: {}".format(" ".join(failing_trails))
            results["affected"] = ", ".join(failing_trails)
            results["pass_fail"] = "FAIL"
        
        return results

    def cloudtrail_3(self):
        # Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible (Automated)

        results = {
            "id" : "cloudtrail_3",
            "ref" : "3.3",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudtrail",
            "name" : "Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible",
            "affected": "",
            "analysis" : "no public cloud trail buckets found",
            "description" : "CloudTrail logs a record of every API call made in your AWS account. These logs file are stored in an S3 bucket. It is recommended that the bucket policy or access control list (ACL) applied to the S3 bucket that CloudTrail logs to prevent public access to the CloudTrail logs. Allowing public access to CloudTrail log content may aid an adversary in identifying weaknesses in the affected account's use or configuration.",
            "remediation" : "Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : "PASS"
        }

        print("running check: cloudtrail_3")

        failing_trails = []
        trails = []

        s3_client = self.session.client('s3')
        
        for region in self.regions:
            cloudtrail_client = self.session.client('cloudtrail', region_name=region)
            trail_list = cloudtrail_client.describe_trails()["trailList"]
            trails += trail_list
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    bucket_name = trail["S3BucketName"]
                    trail_name = trail["Name"]
                    grants = s3_client.get_bucket_acl(Bucket=bucket_name)["Grants"]
                    for grant in grants:
                        try:
                            if grant["Grantee"]["URI"] == "https://acs.amazonaws.com/groups/global/AllUsers":
                                failing_trails += [trail_name]
                            if grant["Grantee"]["URI"] == "https://acs.amazonaws.com/groups/global/AuthenticatedUsers":
                                failing_trails += [trail_name]
                        except KeyError:
                            pass
                                     
                        try:
                            policy = json.loads(s3_client.get_bucket_policy(Bucket=bucket_name)["Policy"])
                        # botocore.exceptions.ClientError: An error occurred (NoSuchBucketPolicy) when calling the GetBucketPolicy operation: The bucket policy does not exist
                        except boto3.exceptions.botocore.exceptions.ClientError:
                            # no bucket policy exists
                            pass
                        else:
                            statements = policy["Statement"]
                            for statement in statements:
                                effect = statement["Effect"]
                                if effect == "Allow":
                                    try:
                                        if statement["Principal"]["AWS"] == "*":
                                            failing_trails += [trail_name]
                                    except KeyError:
                                        pass

                                    try:
                                        if statement["Principal"]["Service"] == "*":
                                            failing_trails += [trail_name]
                                    except KeyError:
                                        pass

        if not trails:
            results["analysis"] = "no CloudTrail Trails in use"
            results["pass_fail"] = "FAIL"
        
        if failing_trails:
            results["analysis"] = "the following trails are using a potentially public S3 bucket: {}".format(" ".join(set(failing_trails)))
            results["affected"] = ", ".join(set(failing_trails))
            results["pass_fail"] = "FAIL"
        
        return results



    def cloudtrail_4(self):
        # Ensure CloudTrail trails are integrated with CloudWatch Logs (Automated)

        results = {
            "id" : "cloudtrail_4",
            "ref" : "3.4",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudtrail",
            "name" : "Ensure CloudTrail trails are integrated with CloudWatch Logs",
            "affected": "",
            "analysis" : "all trails are integrated with CloudWatch Logs",
            "description" : "AWS CloudTrail is a web service that records AWS API calls made in a given AWS account. The recorded information includes the identity of the API caller, the time of the API call, the source IP address of the API caller, the request parameters, and the response elements returned by the AWS service. CloudTrail uses Amazon S3 for log file storage and delivery, so log files are stored durably. In addition to capturing CloudTrail logs within a specified S3 bucket for long term analysis, realtime analysis can be performed by configuring CloudTrail to send logs to CloudWatch Logs. For a trail that is enabled in all regions in an account, CloudTrail sends log files from all those regions to a CloudWatch Logs log group. It is recommended that CloudTrail logs be sent to CloudWatch Logs. Note: The intent of this recommendation is to ensure AWS account activity is being captured, monitored, and appropriately alarmed on. CloudWatch Logs is a native way to accomplish this using AWS services but does not preclude the use of an alternate solution. Sending CloudTrail logs to CloudWatch Logs will facilitate real-time and historic activity logging based on user, API, resource, and IP address, and provides opportunity to establish alarms and notifications for anomalous or sensitivity account activity. ",
            "remediation" : "Ensure CloudTrail trails are integrated with CloudWatch Logs",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "n/a",
            "cvss_score" : "n/a",
            "pass_fail" : "PASS"
        }

        print("running check: cloudtrail_4")

        failing_trails = []
        trails = []
        
        for region in self.regions:
            client = self.session.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            trails += trail_list
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    if "CloudWatchLogsLogGroupArn" not in trail:
                        failing_trails += [trail["Name"]]

        if not trails:
            results["analysis"] = "no CloudTrail Trails in use"
            results["pass_fail"] = "FAIL"

        if failing_trails:
            results["analysis"] = "the following trails are not integrated with CloudWatch Logs: {}".format(" ".join(failing_trails))
            results["affected"] = ", ".join(failing_trails)
            results["pass_fail"] = "FAIL"

        return results


    def cloudtrail_5(self):
        # Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Automated)

        results = {
            "id" : "cloudtrail_5",
            "ref" : "3.6",
            "compliance" : "cis",
            "level" : 1,
            "service" : "cloudtrail",
            "name" : "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket",
            "affected": "",
            "analysis" : "S3 bucket access logging is enabled",
            "description" : "S3 Bucket Access Logging generates a log that contains access records for each request made to your S3 bucket. An access log record contains details about the request, such as the request type, the resources specified in the request worked, and the time and date the request was processed. It is recommended that bucket access logging be enabled on the CloudTrail S3 bucket. By enabling S3 bucket logging on target S3 buckets, it is possible to capture all events which may affect objects within any target buckets. Configuring logs to be placed in a separate bucket allows access to log information which can be useful in security and incident response workflows.",
            "remediation" : "Ensure the CloudTrail S3 bucket has access logging is enabled",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "n/a",
            "cvss_score" : "n/a",
            "pass_fail" : "PASS"
        }

        print("running check: cloudtrail_5")
        
        failing_trails = []
        trails = []

        s3_client = self.session.client('s3')
        
        for region in self.regions:
            cloudtrail_client = self.session.client('cloudtrail', region_name=region)
            trail_list = cloudtrail_client.describe_trails()["trailList"]
            trails += trail_list
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    if "LoggingEnabled" not in s3_client.get_bucket_logging(Bucket=trail["S3BucketName"]):
                        failing_trails += [trail["Name"]]

        if not trails:
            results["analysis"] = "no CloudTrail trails in use"
            results["pass_fail"] = "FAIL"
        
        if failing_trails:
            results["analysis"] = "the following trails do not have S3 bucket access logging enabled: {}".format(" ".join(failing_trails))
            results["affected"] = ", ".join(failing_trails)
            results["pass_fail"] = "FAIL"

        return results
    
    
    def cloudtrail_6(self):
        # Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Automated)

        results = {
            "id" : "cloudtrail_6",
            "ref" : "3.7",
            "compliance" : "cis",
            "level" : 2,
            "service" : "cloudtrail",
            "name" : "Ensure CloudTrail logs are encrypted at rest using KMS CMKs",
            "affected": "",
            "analysis" : "CloudTrail logs are encrypted at rest with KMS CMKs",
            "description" : "AWS CloudTrail is a web service that records AWS API calls for an account and makes those logs available to users and resources in accordance with IAM policies. AWS Key Management Service (KMS) is a managed service that helps create and control the encryption keys used to encrypt account data, and uses Hardware Security Modules (HSMs) to protect the security of encryption keys. CloudTrail logs can be configured to leverage server side encryption (SSE) and KMS customer created master keys (CMK) to further protect CloudTrail logs. It is recommended that CloudTrail be configured to use SSE-KMS. Configuring CloudTrail to use SSE-KMS provides additional confidentiality controls on log data as a given user must have S3 read permission on the corresponding log bucket and must be granted decrypt permission by the CMK policy.",
            "remediation" : "Configure CloudTrail to use SSE-KMS for encryption at rest.",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : "PASS"
        }

        print("running check: cloudtrail_6")

        failing_trails = []
        trails = []
        
        for region in self.regions:
            client = self.session.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            trails += trail_list
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    if "KmsKeyId" not in trail:
                        failing_trails += [trail["Name"]]

        if not trails:
            results["analysis"] = "no CloudTrail Trails in use"
            results["pass_fail"] = "FAIL"

        if failing_trails:
            results["analysis"] = "the following trails do not encrypt logs at rest: {}".format(" ".join(failing_trails))
            results["affected"] = ", ".join(failing_trails)
            results["pass_fail"] = "FAIL"
        
        return results

    def cloudtrail_7(self):
        # Ensure that Object-level logging for write events is enabled for S3 bucket (Automated)

        results = {
            "id" : "cloudtrail_7",
            "ref" : "3.10",
            "compliance" : "cis",
            "level" : 2,
            "service" : "cloudtrail",
            "name" : "Ensure that Object-level logging for write events is enabled for S3 bucket",
            "affected": "",
            "analysis" : "No trails were found with S3 Object-Level Logging enabled",
            "description" : "S3 object-level API operations such as GetObject, DeleteObject, and PutObject are called data events. By default, CloudTrail trails don't log data events and so it is recommended to enable Object-level logging for S3 buckets. Enabling object-level logging will help you meet data compliance requirements within your organization, perform comprehensive security analysis, monitor specific patterns of user behavior in your AWS account or take immediate actions on any object-level API activity within your S3 Buckets using Amazon CloudWatch Events.",
            "remediation" : "Enable S3 bucket Object-level logging for write events in CloudTrail",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "n/a",
            "cvss_score" : "n/a",
            "pass_fail" : "FAIL"
        }
        
        print("running check: cloudtrail_7")

        results["affected"] = self.account_id

        passing_trails = []
        trails = []
     
        for region in self.regions:
            client = self.session.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            trails += trail_list
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    if trail["HasCustomEventSelectors"] == True:
                        trail_name = trail["Name"]
                        event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"]
                        for selector in event_selectors:
                            if selector["ReadWriteType"] == "All" or selector["ReadWriteType"] == "WriteOnly":
                                for resources in selector["DataResources"]:
                                    if resources["Type"] == "AWS::S3::Object":
                                        passing_trails += [trail_name]
        
        if not trails:
            results["analysis"] = "no CloudTrails Trails in use"
            results["pass_fail"] = "FAIL"

        if passing_trails:
            results["analysis"] = "the following trails have S3 Object-Level logging enabled: {}".format(" ".join(passing_trails))
            #results["affected"] = ", ".join(passing_trails)
            results["pass_fail"] = "PASS"

        return results
    
    def cloudtrail_8(self):
        # Ensure that Object-level logging for read events is enabled for S3 bucket (Automated)

        results = {
            "id" : "cloudtrail_8",
            "ref" : "3.11",
            "compliance" : "cis",
            "level" : 2,
            "service" : "cloudtrail",
            "name" : "Ensure that Object-level logging for write read is enabled for S3 bucket",
            "affected": "",
            "analysis" : "No trails were found with S3 Object-Level Logging enabled",
            "description" : "S3 object-level API operations such as GetObject, DeleteObject, and PutObject are called data events. By default, CloudTrail trails don't log data events and so it is recommended to enable Object-level logging for S3 buckets. Enabling object-level logging will help you meet data compliance requirements within your organization, perform comprehensive security analysis, monitor specific patterns of user behavior in your AWS account or take immediate actions on any object-level API activity using Amazon CloudWatch Events.",
            "remediation" : "Enable S3 bucket Object-level logging for read events in CloudTrail",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "n/a",
            "cvss_score" : "n/a",
            "pass_fail" : "FAIL"
        }
        
        passing_trails = []
        trails = []

        results["affected"] = self.account_id
     
        for region in self.regions:
            client = self.session.client('cloudtrail', region_name=region)
            trail_list = client.describe_trails()["trailList"]
            trails += trail_list
            for trail in trail_list:
                if trail["HomeRegion"] == region:
                    if trail["HasCustomEventSelectors"] == True:
                        trail_name = trail["Name"]
                        event_selectors = client.get_event_selectors(TrailName=trail_name)["EventSelectors"]
                        for selector in event_selectors:
                            if selector["ReadWriteType"] == "All" or selector["ReadWriteType"] == "ReadOnly":
                                for resources in selector["DataResources"]:
                                    if resources["Type"] == "AWS::S3::Object":
                                        passing_trails += [trail_name]
        
        if not trails:
            results["analysis"] = "no CloudTrails Trails in use"
            results["pass_fail"] = "FAIL"

        if passing_trails:
            results["analysis"] = "the following trails have S3 Object-Level logging enabled: {}".format(" ".join(passing_trails))
            #results["affected"] = ", ".join(passing_trails)
            results["pass_fail"] = "PASS"

        return results
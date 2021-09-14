import boto3
import json
import re

from utils.utils import get_account_id

class s3(object):

    def __init__(self):
        self.client = self.get_client()
        self.buckets = self.list_buckets()
        self.account_id = get_account_id()

    def run(self):
        findings = []
        findings += [ s3().s3_1() ]
        findings += [ s3().s3_2() ]
        findings += [ s3().s3_3() ]
        findings += [ s3().s3_4() ]
        findings += [ s3().s3_5() ]
        return findings

    def list_buckets(self):
        # returns list of s3 buckets names
        print("Getting Bucket List")
        return [ bucket["Name"] for bucket in self.client.list_buckets()["Buckets"] ]
    
    def get_client(self):
        # returns boto3 s3 client
        return boto3.client('s3')

    def s3_1(self):
        # Ensure all S3 buckets employ encryption-at-rest (Manual)

        results = {
            "id" : "s3_1",
            "ref" : "2.1.1",
            "compliance" : "cis",
            "level" : 2,
            "service" : "s3",
            "name" : "Ensure all S3 buckets employ encryption-at-rest",
            "affected": "",
            "analysis" : "All buckets have server side encryption enabled",
            "description" : "Amazon S3 provides a variety of no, or low, cost encryption options to protect data at rest. Encrypting data at rest reduces the likelihood that it is unintentionally exposed and can nullify the impact of disclosure if the encryption remains unbroken.",
            "remediation" : "Ensure all S3 buckets employ encryption-at-rest",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : "PASS"
        }

        print("running check: s3_1")

        failing_buckets = []

        for bucket in self.buckets:
            try:
                encryption = self.client.get_bucket_encryption(Bucket=bucket)    
            except boto3.exceptions.botocore.exceptions.ClientError:
                failing_buckets += [bucket]

        if failing_buckets:
            results["analysis"] = "the following buckets do not have server side encryption enabled: {}".format(" ".join(failing_buckets))
            results["affected"] = ", ".join(failing_buckets)
            results["pass_fail"] = "FAIL"

        return results
    
    def s3_2(self):
        # Ensure S3 Bucket Policy is set to deny HTTP requests (Manual)

        results = {
            "id" : "s3_2",
            "ref" : "2.1.2",
            "compliance" : "cis",
            "level" : 2,
            "service" : "s3",
            "name" : "Ensure S3 Bucket Policy is set to deny HTTP requests",
            "affected": "",
            "analysis" : "All buckets enforce HTTPS requests",
            "description" : "At the Amazon S3 bucket level, you can configure permissions through a bucket policy making the objects accessible only through HTTPS. By default, Amazon S3 allows both HTTP and HTTPS requests. To achieve only allowing access to Amazon S3 objects through HTTPS you also have to explicitly deny access to HTTP requests. Bucket policies that allow HTTPS requests without explicitly denying HTTP requests will not comply with this recommendation.",
            "remediation" : "Enforce HTTPS requests for all buckets within your account",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : "PASS"
        }
        
        # https://github.com/toniblyx/prowler/blob/3b6bc7fa64a94dfdfb104de6f3d32885c630628f/checks/check_extra764

        print("running check: s3_2")

        passing_buckets = []

        for bucket in self.buckets:
            try:
                policy = json.loads(self.client.get_bucket_policy(Bucket=bucket)["Policy"])
            # botocore.exceptions.ClientError: An error occurred (NoSuchBucketPolicy) when calling the GetBucketPolicy operation: The bucket policy does not exist
            except boto3.exceptions.botocore.exceptions.ClientError:
                # no bucket policy exists
                pass
            else:
                statements = policy["Statement"]
                for statement in statements:
                    try:
                        bool_secure_transport = statement["Condition"]["Bool"]["aws:SecureTransport"]
                    except KeyError:
                        pass
                    else:
                        effect = statement["Effect"]
                        action = statement["Action"]
                        resources = statement["Resource"]
                        if bool_secure_transport == "false":
                            if effect == "Deny":
                                if action == "s3:GetObject" or action == "s3:*":
                                    for resource in resources:
                                        if re.match("arn:aws:s3*|\*", resource):
                                            passing_buckets += [bucket]

        failing_buckets = [i for i in self.buckets if i not in passing_buckets]
        
        if failing_buckets:
            results["analysis"] = "the following buckets do enforce HTTPS only: {}".format(" ".join(failing_buckets))
            results["affected"] = ", ".join(failing_buckets)
            results["pass_fail"] = "FAIL"

        return results

    def s3_3(self):
        # Ensure MFA Delete is enable on S3 buckets (Automated)

        results = {
            "id" : "s3_3",
            "ref" : "2.1.3",
            "compliance" : "cis",
            "level" : 1,
            "service" : "s3",
            "name" : "Ensure MFA Delete is enable on S3 buckets",
            "affected": "",
            "analysis" : "All buckets have MFA Delete Enabled",
            "description" : "Once MFA Delete is enabled on your sensitive and classified S3 bucket it requires the user to have two forms of authentication. Adding MFA delete to an S3 bucket, requires additional authentication when you change the version state of your bucket or you delete and object version adding another layer of security in the event your security credentials are compromised or unauthorized access is granted.",
            "remediation" : "configure MFA delete on all S3 buckets within your account",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : "PASS"
        }

        print("running check: s3_3")

        passing_buckets = []

        for bucket in self.buckets:
            try:
                bucket_versioning = self.client.get_bucket_versioning(Bucket=bucket)
                if bucket_versioning["Status"] == "Enabled":
                    if bucket_versioning["MfaDelete"] == "Enabled": # need testing with mfadelete enabled bucket
                        passing_buckets += [bucket]
            except KeyError:
                pass
            
        failing_buckets = [i for i in self.buckets if i not in passing_buckets]
        
        if failing_buckets:
            results["analysis"] = "the following buckets do not have MFA Delete enabled: {}".format(" ".join(failing_buckets))
            results["affected"] = ", ".join(failing_buckets)
            results["pass_fail"] = "FAIL"
        
        return results


    def s3_4(self):
        # Ensure all data in Amazon S3 has been discovered, classified and secured when required. (Manual)

        results = {
            "id" : "s3_4",
            "ref" : "2.1.4",
            "compliance" : "cis",
            "level" : 1,
            "service" : "s3",
            "name" : "Ensure all data in Amazon S3 has been discovered classified and secured when required",
            "affected": "",
            "analysis" : "Manual Check",
            "description" : "Amazon S3 buckets can contain sensitive data, that for security purposes should be discovered, monitored, classified and protected. Macie along with other 3rd party tools can automatically provide an inventory of Amazon S3 buckets. Using a Cloud service or 3rd Party software to continuously monitor and automate the process of data discovery and classification for S3 buckets using machine learning and pattern matching is a strong defense in protecting that information. Amazon Macie is a fully managed data security and data privacy service that uses machine learning and pattern matching to discover and protect your sensitive data in AWS. ",
            "remediation" : "Enable AWS Macie",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "n/a",
            "cvss_score" : "n/a",
            "pass_fail" : "INFO"
        }

        #client = boto3.client('macie2', region_name="eu-west-2")
        print("running check: s3_4")

        results["affected"] = self.account_id

        return results

    def s3_5(self):
        # Ensure that S3 Buckets are configured with 'Block public access (bucket settings)' (Automated)

        results = {
            "id" : "cis26",
            "ref" : "2.1.5",
            "compliance" : "cis",
            "level" : 1,
            "service" : "s3",
            "name" : "Ensure that S3 Buckets are configured with Block public access (bucket settings)",
            "affected": "",
            "analysis" : "All Buckets block public access ",
            "description" : "Amazon S3 provides Block public access (bucket settings) and Block public access (account settings) to help you manage public access to Amazon S3 resources. By default, S3 buckets and objects are created with public access disabled. However, an IAM principal with sufficient S3 permissions can enable public access at the bucket and/or object level. While enabled, Block public access (bucket settings) prevents an individual bucket, and its contained objects, from becoming publicly accessible. Similarly, Block public access (account settings) prevents all buckets, and contained objects, from becoming publicly accessible across the entire account. Amazon S3 Block public access (bucket settings) prevents the accidental or malicious public exposure of data contained within the respective bucket(s). Amazon S3 Block public access (account settings) prevents the accidental or malicious public exposure of data contained within all buckets of the respective AWS account. Whether blocking public access to all or some buckets is an organizational decision that should be based on data sensitivity, least privilege, and use case.",
            "remediation" : "Ensure that S3 Buckets are configured with Block public access",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : "PASS"
        }

        print("running check: s3_5")

        passing_buckets = []      

        for bucket in self.buckets:
            try:
                public_access_block_configuration = self.client.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
            #botocore.exceptions.ClientError: An error occurred (NoSuchPublicAccessBlockConfiguration) when calling the GetPublicAccessBlock operation: The public access block configuration was not found
            except boto3.exceptions.botocore.exceptions.ClientError:
                # no public access block configuration exists
                pass
            else:
                if public_access_block_configuration["BlockPublicAcls"] == True:
                    if public_access_block_configuration["IgnorePublicAcls"] == True:
                        if public_access_block_configuration["BlockPublicPolicy"] == True:
                            if public_access_block_configuration["RestrictPublicBuckets"] == True:
                                passing_buckets += [bucket]

        failing_buckets = [i for i in self.buckets if i not in passing_buckets]
        
        if failing_buckets:
            results["analysis"] = "the following buckets do not block public access: {}".format(" ".join(failing_buckets))
            results["affected"] = ", ".join(failing_buckets)
            results["pass_fail"] = "FAIL"
        
        return results
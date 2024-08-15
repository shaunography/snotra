# Snotra
Snotra (pronounced "snow-trah” ) is a pure Python Cloud (AWS) Auditing Tool it uses boto3 to audit your AWS account against a list of common issues and compliance standards including the CIS benchmark. Snotra produces a results.json file that can be easily incorporated into existing reporting workflows.

## requirements
* Python3
* boto3

## permissions
The following AWS Managed Policies can be attached to the principal in order to grant the access keys the necessary permissions:
* ReadOnlyAccess
* ViewOnlyAccess
* SecurityAudit

## docker
from the cloned repo directory, run:

`docker build -t snotra .`

`docker run --rm -ti -v ~/.aws:/root/.aws/ snotra`

## usage
run full audit using default aws profile

`$ python3 snotra.py --results-dir ./snotra/`

run full audit with named profile

`$ python3 snotra.py --results-dir ./snotra/ --profile prod_web`

run CIS only audit with named profile

`$ python3 snotra.py --results-dir ./snotra/ --profile prod_web --cis`

## Lambda
It is also possible to deploy Snotra as a Lambda Function, see the following blog post for more info.

https://www.shaunography.com/snotra-lambda.html


## checks
### CIS Benchmark
- CIS Amazon Web Services Foundations Benchmark v3.0.0
- CIS AWS Compute Services Benchmark v1.0.0

Snotra currently completes checks included in the latest CIS Benchmarks. Although Snotra reports on them, a few of the checks can not be completed programatically - these are marked accordingly.

- "Ensure that IAM Access analyzer is enabled for all regions (CIS)"
- "Ensure EC2 Auto Scaling Groups Propagate Tags to EC2 Instances that it launches (CIS)"
- "Ensure Cloudwatch Lambda insights is enabled (CIS)"
- "Ensure every Lambda function has its own IAM Role (CIS)"
- "Ensure Lambda functions are not exposed to everyone (CIS)"
- "Ensure that Code Signing is enabled for Lambda functions (CIS)"
- "Ensure Lambda functions do not allow unknown cross account access via permission policies (CIS)"
- "Ensure that the runtime environment versions used for your Lambda functions do not have end of support dates (CIS)"
- "Ensure CloudTrail is enabled in all regions (CIS)"
- "Ensure CloudTrail log file validation is enabled (CIS)"
- "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (CIS)"
- "Ensure CloudTrail logs are encrypted at rest using KMS CMKs (CIS)"
- "Ensure that Object-level logging for write events is enabled for S3 bucket (CIS)"
- "Ensure that Object-level logging for read events is enabled for S3 bucket (CIS)"
- "Ensure unauthorized API calls are monitored (CIS)"
- "Ensure management console sign-in without MFA is monitored (CIS)"
- "Ensure usage of 'root' account is monitored (CIS)"
- "Ensure IAM policy changes are monitored (CIS)"
- "Ensure CloudTrail configuration changes are monitored (CIS)"
- "Ensure AWS Management Console authentication failures are monitored (CIS)"
- "Ensure disabling or scheduled deletion of customer created CMKs is monitored (CIS)"
- "Ensure S3 bucket policy changes are monitored (CIS)"
- "Ensure AWS Config configuration changes are monitored (CIS)"
- "Ensure security group changes are monitored (CIS)"
- "Ensure Network Access Control Lists (NACL) changes are monitored (CIS)"
- "Ensure changes to network gateways are monitored (CIS)"
- "Ensure route table changes are monitored (CIS)"
- "Ensure VPC changes are monitored (CIS)"
- "Ensure AWS Organizations changes are monitored (CIS)"
- "Ensure AWS Config is enabled in all regions (CIS)"
- "Ensure AWS Config is Enabled for Lambda and Serverless (CIS)(Manual)"
- "Ensure EBS Volume Encryption is Enabled in all Regions (CIS)"
- "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports (CIS)"
- "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports (CIS)"
- "Ensure the default security group of every VPC restricts all traffic (CIS)"
- "Ensure routing tables for VPC peering are least access (CIS)(Manual)"
- "Ensure there are no Public EBS Snapshots (CIS)"
- "Unused Network Interfaces (CIS)"
- "Ensure running instances are not more than 180 days old (CIS)"
- "Ensure EC2 Instance Metadata Service Version 2 (IMDSv2) is Enabled and Required (CIS)"
- "EC2 Instances Not Managed By AWS Systems Manager (CIS)"
- "Unencrypted EBS Snapshots (CIS)"
- "Ensure no security groups allow ingress from ::/0 to remote server administration ports (CIS)"
- "Ensure Secrets and Sensitive Data are not stored directly in EC2 User Data (CIS)(Manual)"
- "EC2 Instances Without Detailed Monitoring Enabled (CIS)"
- "Stopped EC2 Instances (CIS)"
- "Ensure Consistent Naming Convention is used for Organizational AMI (CIS)"
- "Ensure Images (AMI's) are encrypted (CIS)"
- "Ensure unused EBS volumes are removed (CIS)"
- "Ensure Default EC2 Security groups are not being used (CIS)"
- "Ensure EBS volumes attached to an EC2 instance is marked for deletion upon instance termination (CIS)"
- "Ensure that encryption is enabled for EFS file systems (CIS)"
- "Ensure Managed Platform updates is configured (CIS)"
- "Ensure Persistent logs is setup and configured to S3 (CIS)"
- "Maintain current contact details (CIS)"
- "Ensure security contact information is registered (CIS)"
- "Ensure security questions are registered in the AWS account (CIS)"
- "Ensure no root user account access key exists (CIS)"
- "Ensure MFA is enabled for the root user account (CIS)"
- "Ensure hardware MFA is enabled for the root user account (CIS)"
- "Eliminate use of the 'root' user for administrative and daily tasks (CIS)"
- "Ensure IAM password policy requires minimum length of 14 or greater (CIS)"
- "Ensure IAM password policy prevents password reuse (CIS)"
- "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (CIS)"
- "Do not setup access keys during initial user setup for all IAM users that have a console password (CIS)"
- "Ensure credentials unused for 45 days or greater are disabled (CIS)"
- "Ensure there is only one active access key available for any single IAM user (CIS)"
- "Ensure access keys are rotated every 90 days or less (CIS)"
- "Ensure IAM Users Receive Permissions Only Through Groups (CIS)"
- "Ensure Custom IAM policies that allow full *:* administrative privileges are not attached (CIS)"
- "Ensure a support role has been created to manage incidents with AWS Support (CIS)"
- "Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed (CIS)"
- "Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments (CIS)"
- "Ensure access to AWSCloudShellFullAccess is restricted (CIS)"
- "Ensure there are no Lambda functions with admin privileges within your AWS account (CIS)"
- "Ensure rotation for customer created CMKs is enabled (CIS)"
- "Ensure Tag Policies are Enabled (CIS)"
- "Ensure an Organizational EC2 Tag Policy has been Created (CIS)(Manual)"
- "Ensure that encryption is enabled for RDS Instances (CIS)"
- "RDS Instances Do Not Have Deletion Protection Enabled (CIS)"
- "Ensure Auto Minor Version Upgrade feature is Enabled for RDS Instances (CIS)"
- "Ensure that public access is not given to RDS Instance (CIS)"
- "Ensure S3 Bucket Policy is set to deny HTTP requests (CIS)"
- "Ensure MFA Delete is enable on S3 buckets (CIS)"
- "Ensure all data in Amazon S3 has been discovered classified and secured when required (CIS)"
- "Ensure that S3 Buckets are configured with Block public access (bucket settings) (CIS)"
- "Ensure AWS Secrets manager is configured and being used by Lambda for databases (CIS)(Manual)"
- "Ensure AWS Security Hub is enabled (CIS)"

### other
Additional checks beyond the CIS benchmark

- "ACM Certificate with Transparency Logging Set to Disabled"
- "Expired ACM Certificates"
- "RSA certificates managed by ACM should use a key length of at least 2048 bits,"
- "ACM certificates should be tagged"
- "API Gateways In Use"
- "API Gateways Using Lambda Authorizers"
- "API Gateway REST and WebSocket API execution logging should be enabled"
- "API Gateway REST API stages should have AWS X-Ray tracing enabled"
- "API Gateway REST API cache data should be encrypted at rest"
- "API Gateway routes should specify an authorization type"
- "Access logging should be configured for API Gateway V2 Stages"
- "Ensure that encryption at rest is enabled for Amazon Athena query results stored in Amazon S3"
- "Auto Scaling groups associated with a load balancer should use ELB health checks"
- "Amazon EC2 Auto Scaling group should cover multiple Availability Zones"
- "Auto Scaling group launch configurations should configure EC2 instances to require Instance Metadata Service Version 2 (IMDSv2)"
- "Amazon EC2 instances launched using Auto Scaling group launch configurations should not have Public IP addresses"
- "Auto Scaling groups should use multiple instance types in multiple Availability Zones"
- "Amazon EC2 Auto Scaling groups should use Amazon EC2 launch templates"
- "EC2 Auto Scaling groups should be tagged"
- "Lambda Function Environment Variables (Check for Secrets)"
- "Lambda Functions With Resource Based Policies Configured (Manual)"
- "Ensure that the latest runtime environment versions used for your Lambda functions"
- "CloudFormation Stacks Output (Check For Secrets)"
- "CloudFormation Stacks Do Not Have Termination Protection Enabled"
- "Role Passed To CLoud Formation Stack"
- "Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible"
- "Ensure CloudTrail trails are integrated with CloudWatch Logs"
- "CloudWatch Alarms with no actions"
- "Codebuild Projects Environment Variables (Check For Secrets)"
- "Dynamo DB Tables Without Deletion Protection Enabled"
- "Unused Dynamo DB Tables"
- "Dynamo DB Tables Without Point In Time Recovery Enabled"
- "Ensure IAM instance roles are used for AWS resource access from instances"
- "Ensure VPC flow logging is enabled in all VPCs"
- "Unused Security Groups"
- "Unused Elastic IPs"
- "Ensure there are no Public EC2 AMIs"
- "Ensure no security groups allow ingress from 0.0.0.0/0 to database ports"
- "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to database ports"
- "Ensure default Network ACLs are not default allow"
- "Ensure custom Network ACLs do not allow all traffic"
- "Unencrypted EBS Volumes"
- "Snapshots Older Than 30 days"
- "Default VPCs in use"
- "Overly Permissive VPC Endpoint Policy"
- "Ensure All Security Group Rules Have A Description"
- "EC2 Instances with a Public IP Address"
- "ECR Image Scan on Push is not Enabled"
- "ECR Image Repositories Do Not Have a LifeCycle Policy Applied"
- "EFS Grants Access To All Clients"
- "Internet Facing Load Balancers"
- "Internet Facing Load Balancers Using Unencrypted HTTP Listeners"
- "ELB Listeners with Weak TLS Configuration"
- "ALBs Not Configured To Drop Invalid Headers"
- "ALB HTTP Desync Mitigation Mode Not Enabled"
- "Lack of ELB Access Logging"
- "Load Balancer Deletion Protection not Configured"
- "GuardDuty Not Enabled In All Regions"
- "High Risk GuardDuty findings"
- "Unused IAM Groups"
- "Cross-Account AssumeRole Policy Lacks External ID"
- "Groups Granting Full Admin Access"
- "Group Name does not Indicate Admin Access"
- "Group With Inline Policies"
- "Overly permissive Cross Account Assume Role Trust Policy"
- "Incorrect policy used to attempt to enforce MFA"
- "AmazonEC2RoleforSSM Managed Policy In Use"
- "Overly permissive Cross Account Assume Role Trust Policy GitHub OIDC"
- "Insecure Cross-Service Trust"
- "Users Granted Full Admin Access via Directly Attached Policy"
- "Ensure Access Keys are Protected with MFA"
- "Resource Explorer Indexes Not Found"
- "Ensure Tags Do Not Contain Sensitive or PII Data (Manual)"
- "All Resources"
- "Domain Does Not Have Domain Transfer Lock Set"
- "Domain Does Not Have Auto Renew Enabled"
- "Ensure all S3 buckets employ encryption-at-rest"
- "S3 buckets without object versioning enabled"
- "S3 Buckets Grant Public Access Via ACL"
- "S3 Buckets Grant Public Access Via Policy"
- "S3 Buckets Grant Public Access Via Policy"
- "S3 Buckets with Bucket Policy Attached"
- "Security Hub Auto Enable Controls"
- "SNS Topic Allows Actions To All AWS Principals"
- "Unencrypted SNS Topics"
- "SSM Parameter Store Parameters (Check For Secrets)"

## results JSON
The results JSON file that Snotra produces is in the following format:
```
{
    "account" : account_id,                     # account ID e.g. 123456789123
    "user" : user_arn,                          # ARN of user used to run test e.g. arn:aws:iam::123456789123:user/shaun
    "datetime" : datetime.today(),              # datetime of scan e.g. 2021-09-11 13:14:34.562040
    "findings" : [
        {                                       # each check function returns a results dictionary in this format
            "id": id,                           # finding ID e.g "iam_3" (string)
            "ref": ref,                         # finding reference CIS etc e.g "2.3.1" (string)
            "compliance": compliance,           # is the finding from a compliance standard e.g. "cis" (string)
            "level": level,                     # CIS level e.g 1 (int)
            "service": service,                 # AWS service e.g "iam" (string)
            "name": name,                       # finding name e.g. "Ensure that encryption is enabled for RDS Instances" (string)
            "affected": affected,               # affected resources e.g. ["eu-west-2", "eu-west-1"] (list)
            "analysis": analysis,               # technical analysis e.g. "AWS config is not enabled in eu-west-1" (string)
            "description": description,         # description of issue e.g. "AWS Config is a web service that performs ..." (string)
            "remediation": remediation,         # remediation advice e.g. "enable AWS Config in all regions" (string)
            "impact": impact,                   # impact rating (high|medium|low|info) e.g. "medium" (string)
            "probability": probability,         # probably rating (high|medium|low|info) e.g. "low" (string)
            "cvss_vector": cvss_vector,         # CVSS v3 vector e.g "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N" (string)
            "cvss_score": cvss_score,           # CVSS v3 score e.g. "4.8" (string)
            "pass_fail": pass_fail              # finding results (pass|fail) e.g. "FAIL" (string)
        },
        ...
    ]
}
```
## reporting tools
* [snotra_to_table](https://github.com/shaunography/snotra_to_table) - Converts Snotra results JSON file into a simple CSV table for pasting into reports.
* [snotra_to_md](https://github.com/shaunography/snotra_to_md) - Converts Snotra results JSON file to a simple Mark Down file.

## contributions
### code
Pull requests, bug reports and enhancement suggestions are more than welcome.

### checks
All checks are a function/method of the relevent class and are in the following format:

```
    def service_n(self):
        # name of check
        
        results = {
            "id" : "service_n",
            "ref" : "n/a",
            "compliance" : "n/a",
            "level" : "n/a",
            "service" : "service",
            "name" : "name of check",
            "affected": [],
            "analysis" : "",
            "description" : "this is a check template",
            "remediation" : "hack all the things",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "n/a",
            "cvss_score" : "n/a",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        # actual check logic here

        return results
```

All methods contain the results dictionary object, print the name of the check on start up and retun the results dict after completing the check logic and populating it (affected, analysis and pass_fail) with the results of the check. 

### donations
If you appreciate my work and gain value from using Snotra feel free to donate some sats at https://coinos.io/shaunwebber

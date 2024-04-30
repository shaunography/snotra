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
### CIS Benchmark v3.0.0
Snotra currently completes all checks included in the latest CIS Benchmark. Although Snotra reports on them, a few of the checks can not be completed programatically - these are marked accordingly.

### other
Additional checks beyond the CIS benchmark

- "ACM Certificate with Transparency Logging Set to Disabled"
- "Expired ACM Certificates"
- "API Gateways In Use"
- "API Gateways Using Lambda Authorizers"
- "Ensure that encryption at rest is enabled for Amazon Athena query results stored in Amazon S3"
- "Lambda Function Environment Variables (Check for Secrets)"
- "CloudFormation Stacks Output (Check For Secrets)"
- "CloudFormation Stacks Do Not Have Termination Protection Enabled"
- "Role Passed To CLoud Formation Stack"
- "Codebuild Projects Environment Variables (Check For Secrets)"
- "Dynamo DB Tables Without Deletion Protection Enabled"
- "Unused Dynamo DB Tables"
- "Dynamo DB Tables Without Point In Time Recovery Enabled"
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
- "Resource Explorer Indexes Not Found"
- "Ensure Tags Do Not Contain Sensitive or PII Data"
- "All Resources"
- "Domain Does Not Have Domain Transfer Lock Set"
- "Domain Does Not Have Auto Renew Enabled"
- "Security Hub Auto Enable Controls"
- "SNS Topic Allows Actions To All AWS Principals"
- "Unencrypted SNS Topics"
- "SSM Parameter Store Parameters (Check For Secrets)"
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
- "Ensure all S3 buckets employ encryption-at-rest"
- "S3 buckets without object versioning enabled"
- "S3 Buckets Grant Public Access Via ACL"
- "S3 Buckets Grant Public Access Via Policy"
- "S3 Buckets Grant Public Access Via Policy"
- "S3 Buckets with Bucket Policy Attached"
- "Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible"
- "Ensure CloudTrail trails are integrated with CloudWatch Logs"
- "CloudWatch Alarms with no actions"
- "Ensure IAM instance roles are used for AWS resource access from instances"
- "Ensure VPC flow logging is enabled in all VPCs"
- "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports"
- "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports"
- "Ensure the default security group of every VPC restricts all traffic"
- "Ensure routing tables for VPC peering are least access"
- "Unused Security Groups"
- "Unused Elastic IPs"
- "Ensure there are no Public EBS Snapshots"
- "Ensure there are no Public EC2 AMIs"
- "Ensure no security groups allow ingress from 0.0.0.0/0 to database ports"
- "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to database ports"
- "Ensure default Network ACLs are not default allow"
- "Ensure custom Network ACLs do not allow all traffic"
- "Unused Network Interfaces"
- "Ensure running instances are not more than 365 days old"
- "Ensure EC2 Instance Metadata Service Version 2 (IMDSv2) is Enabled and Required"
- "EC2 Instances Not Managed By AWS Systems Manager"
- "Unencrypted EBS Volumes"
- "Unencrypted EBS Snapshots"
- "Snapshots Older Than 30 days"
- "Default VPCs in use"
- "Overly Permissive VPC Endpoint Policy"
- "Ensure no security groups allow ingress from ::/0 to remote server administration ports"
- "EC2 Instance User Data (Check For Secrets)"
- "Ensure All Security Group Rules Have A Description"
- "EC2 Instances Without Detailed Monitoring Enabled"
- "EC2 Instances with a Public IP Address"
- "Stopped EC2 Instances"

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

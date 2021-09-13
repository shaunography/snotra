# Snotra
Snotra (pronounced "snow-trah” ) is a pure Python Cloud (AWS) Auditing Tool it uses boto3 to audit your AWS account against a list of common issues and compliance standards including the CIS benchmark. Snotra produces a results.json file that can be easily incorporated into existing reporting workflows.

## usage
`$ python3 snotra.py --output-dir ./snotra/`

## Checks
### CIS
v1.4.0
### other

# requirements
* Python3
* boto3

## results JSON
The results JSON file that Snotra produces is in the following format:
```
{
    "account" : account_id,                     # account ID e.g. 123456789123
    "user" : user_arn,                          # ARN of user used to run test e.g. arn:aws:iam::123456789123:user/shaun
    "datetime" : datetime.today(),              # datetime of scan e.g. 2021-09-11 13:14:34.562040
    "findings" : [
        {                                       # each check function returns a results dictionary in this format
            "id": id,                           # finding ID e.g iam_3
            "ref": ref,                         # finding reference CIS etc e.g 2.3.1
            "compliance": "cis",                # is the finding from a compliance standard e.g. cis
            "level": level,                     # CIS level e.g 1
            "service": service,                 # AWS service e.g iam
            "name": name,                       # finding name e.g. "Ensure that encryption is enabled for RDS Instances"
            "affected": affected,               # affected resources e.g. eu-west-2
            "analysis": analysis,               # technical analysis e.g. AWS config is not enabled in eu-west-1
            "description": description,         # description of issue e.g. AWS Config is a web service that performs ...
            "remediation": remediation,         # remediation advice e.g. enable AWS Config in all regions
            "impact": impact,                   # impact rating (high|medium|low|info) e.g. medium
            "probability": probability,         # probably rating (high|medium|low|info) e.g. low
            "cvss_vector": cvss_vector,         # CVSS v3 vector e.g AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N
            "cvss_score": cvss_score,           # CVSS v3 score e.g. 4.8
            "pass_fail": pass_fail              # finding results (pass|fail) e.g. fail
        },
        ...
    ]
}
```
## reporting tools
* [snotra_to_table](https://github.com/shaunography/snotra_to_table) - Converts Snotra results JSON file into a simple CSV table for pasting into reports.


## todo
### features
- [x] CIS benchmark
    - [ ] pass/fail percentage
- [ ] non-CIS checks
    - [ ] external attack surface
- [x] JSON results file for consumption by other tools
- [ ] AWS profiles
- [ ] specifiy regions
- [ ] specify checks by groups (i.e. CIS, IAM, EC2, CIS_level_1 etc)
- [ ] additional compliance standards
- [ ] dockerfile
- [ ] dockerhub
- [ ] Azure
- [ ] git gud

### improvements
- [ ] better error handling
- [ ] actually test CIS1_19
- [ ] test CIS2_1_3 with mfa enabled buckets
- [ ] hardware MFA check
- [x] cacheing / minimise requests to API
    - [ ] moar

### bugs


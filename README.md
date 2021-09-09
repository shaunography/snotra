# Snotra
Snotra (pronounced "snow-trah” ) is a pure Python Cloud (AWS) Auditing Tool it currently creates a CSV file in --output-dir containing results from a CIS Audit. It will use the default AWS Profile as configure in your ~/.aws/credentials file.

## usage
`$ python3 snotra.py --output-dir ./snotra/`

---
## CIS
v1.4.0

---
# requirements
Python3
boto3

---
## todo

### features
- [ ] CIS benchmark
    - [ ] pass/fail percentage
- [ ] non-CIS checks
    - [ ] external attack surface
- [ ] JSON results file for consumption by other tools
- [ ] CSV results file for consumption by other tools
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

### bugs


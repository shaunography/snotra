Snotra
======
Snotra (pronounced "snow-trah” ) is a pure Python Cloud (AWS and Azure) Auditing Tool whihc will check your accounts against a list of common issues and compliance standards including the CIS benchmark. Snotra produces a results.json file that can be easily incorporated into existing reporting workflows.

AWS is on the main branch, Azure is on this branch.

permissions
===========
The user account or service principal will need to have the "reader" role in Azure RBAC at the subscription level.

usage
=====

authentication
--------------
Snotra uses the DefaultAzureCredential() to authenticate and will handle most authentication scenarios including CLI, Powershell and Environmentvariables. 


service principal (environment vars)::

    export AZURE_TENANT_ID=<tenant_id>
    export AZURE_CLIENT_ID=<client_id)
    export AZURE_CLIENT_SECRET=<secret_value>

cli::

    az login

scan
----
full scan::

    python3 snotra.py -r <results_dir> -t <tenant_id>

checks
======
compliance
----------
CIS Benchmark v2.1.0

snotra checks
-------------
Additional checks beyond the CIS benchmark

- "Azure App Services",
- "App Services Lacking Network Access Restrictions",
- "Web Apps With Managed Identity Assigned",
- "Web Apps With Remote Debugging Enabled",
- "App Services Without Always On Enabled",
- "Virtual Machines",
- "Unencrpyted Disks",
- "Disks With Public Network Access Enabled",
- "Unattached Disks",
- "Virtual Machines With User Data",
- "Stopped Virtual Machines",
- "Snapshots With Public Network Access Enabled",
- "Old Snapshots",
- "Unencrypted Snapshots",
- "Key Based SSH Authentication Not Enforced",
- "Ensure that 'Public Network Access' is `Disabled' for Container Registries",
- "Ensure that 'Public Network Access' is `Disabled' for AKS Clusters",
- "Outdated/Unsuported Version of Kubernetes In Use",
- "Ensure that 'Public Network Access' is `Disabled' for Event Hub Namespaces",
- "Event Hubs Without Entra ID Authentication (Manual)",
- "Privileged Identity Management (Manual)",
- "Ensure 'Self service password reset enabled' is set to 'All'",
- "Shadow Admin via Highly Privileged Service Principal (via Role Assignment)",
- "Service Principals with Directory Roles (Manual)",
- "Cloud Application And Application Administrators",
- "Azure Key Vaults",
- "Key Vault Lacking Network Access Restrictions",
- "Ensure that 'Public Network Access' is `Disabled' for MySQL servers",
- "Unused Public IP Addresses",
- "Unused Network Security Groups",
- "Ensure that 'Public Network Access' is `Disabled' for postgresql servers",
- "Resource Groups",
- "All Resources",
- "Resource Types",
- "Secure Score",
- "Ensure the Minimum TLS version for SQL Servers is set to Version 1.2",
- "Ensure that 'Public Network Access' is `Disabled' for sql servers",
- "SQL Servers with Managed Identity Attached",
- "Storage Account Allows Anonymous/Public Container Access",
- "Storage Account Allows Anonymous/Public Blob Access",
- "Ensure the Minimum TLS version for Cosmos DB Accounts is set to Version 1.2",

results JSON
============
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
reporting tools
===============
* [snotra_to_table](https://github.com/shaunography/snotra_to_table) - Converts Snotra results JSON file into a simple CSV table for pasting into reports.
* [snotra_to_md](https://github.com/shaunography/snotra_to_md) - Converts Snotra results JSON file to a simple Mark Down file.

contributions
=============
code
----
Pull requests, bug reports and enhancement suggestions are more than welcome.

checks
------
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

donations
=========
If you appreciate my work and gain value from using Snotra feel free to donate some sats at https://coinos.io/shaunwebber

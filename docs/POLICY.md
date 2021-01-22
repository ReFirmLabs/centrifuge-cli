# Binwalk Policy Check

The `policy` subcommand is a tool that enables users to apply their own policy rules against a Binwalk report.

This command line tool takes a policy file that defines the policy rules that you want to apply. It gathers report data via the Binwalk REST API, for which you have to supply your Binwalk API authentication token, and generates an output file containing the results of the policy as it applies to the given Binwalk report.

Optionally, the policy rules can be mapped against a standard such as the OWASP IoT Top 10. See the section below
on defining a standard for more details

## Prerequisites

Before you begin, ensure you have met the following requirements:

* You have python 3 installed (tested with python 3.7)
* You have an active Binwalk account with a valid API authtoken
* You have a completed Binwalk report that you wish to check
* You have installed the latest version of the Binwalk command line tool (version 0.2.2 or later)

## Installing the Binwalk CLI

Tested on Linux with python 3.7
```
pip3 install centrifuge-cli
```

## Using Binwalk Policy Check

```
# Command options:
--policy-yaml : location of policy rules file (see below)
--report-template : location of mustache-based template for compliance report

# Check your policy against Binwalk report 1234 and output CSV format (default)
centrifuge report --ufid=<REPORT ID> check-policy --policy-yaml my-policy.yml

# Check your policy against Binwalk report 1234 and output json format
centrifuge --outfmt json report --ufid=<REPORT ID> check-policy --policy-yaml my-policy.yml

# Check your policy against Binwalk report 1234 and output full html compliance report using example template
centrifuge report --ufid=<REPORT ID> check-policy --policy-yaml my-policy.yml --report-template example-policy-report.mustache > compliance_report.htm
```

## Policy Rule Definition

A policy rules file must be specified in order for this tool to function.

The rules file follows a specific YAML format and allows the user to fully customize which rules to apply.  Only rules that are specified in the file will show passing or failing results. Rules that are not specified will show a result of `No policy specified`

The top level of the rules YAML specification contains the policy version and the rules object:
```
policyVersion: 1.0
rules: {}
```

Current policy schema version: `1.1`

Refer to example rule definition files included in this repository for more examples.

### Rule exceptions

You may only want to apply a rule to a certain set of files rather than all the files in the firmware image, or apply the rule to all files except a certain set of files you wish to ignore. Many (if not all) of the rules can be defined in this way for maximum flexibility.

For example, this rule specification disallows all private keys:
```
  privateKeys:
    allowed: false
```
But you can also define it to disallow all private keys except those in the directory `/etc/ssl`:
```
  privateKeys:
    allowed: false
    exceptions:
      - /etc/ssl/*
```
Or you can define the rule to allow all private keys except those in the `/root` or `/opt/vendor` directories:
```
  privateKeys:
    allowed: true
    exceptions:
      - /root/*
      - /opt/vendor/*
 ```
 
## Rules

The following is a list of rules and their corresponding definition syntax.

### Rule: Expired Certificates

Firmware images with reported SSL certificates that are expired will fail this policy check.
```
  certificates:
    expired:
      allowed: false

      # also check for certificates expiring in upcoming period
      prevent_expiring: in 6 months

      # optional list of files exempt from this rule (i.e. expired certificates in /etc/ssl are ok).
      exceptions:
        - /etc/ssl/*
```

### Rule: Private Keys

Firmware images containing any private keys will fail this policy check.
```
  privateKeys:
    allowed: false
    # optional list of files that are allowed to have private keys
    exceptions:
      - /etc/ssl/*
```

### Rule: Weak Password Hashes

Firmware images containing any password hashes with the algorithms defined below will fail.
Set `allowUserAccounts: false` to fail if any user accounts are present, regardless of hash algorithm.
```
  passwordHashes:
    # whether defined user accounts are allowed or not
    allowUserAccounts: true

    # any hashes with the following algorithms will fail the policy check
    weakAlgorithms:
      - des
      - md5
```

### Rule: Code Flaws

Firmware images containing any high risk executables with code flaws will fail this policy check.
Set `allowed: false` to check against all files (except those omitted in the `exceptions` modifier).
Set `allowCritical: false` to check for only critical (emulated) flaws (except those omitted in the `exceptions` modifier)
```
  code:
    flaws:
      # allow any potential flaws
      allowed: true

      # allow critical (emulated) flaws
      allowCritical: false

    # optional list of files that are omitted from this rule
    exceptions:
      - /usr/local/bin/*
      - /opt/vendor/*
```

### Rule: Guardian

Firmware images containing any CVEs with a CVSS rating at or above the given threshold or age will fail the policy check.
Use exceptions to exclude specific files from the policy check
```
  guardian:
    # any CVEs found at or above this threshold will cause the policy check to fail
    cvssScoreThreshold: 7.0

    # any CVEs from this year or older will cause the policy check to fail
    # either put year (i.e., 2017) or # years (i.e., 2 would fail 2018 or earlier CVEs in 2020)
    cveAgeThreshold: 2

    # optional list of files that are omitted from this rule
    exceptions:
      - cpio-root/bin/busybox
```

### Rule: Binary Hardness

Firmware images containing ELF binaries that lack the specified hardening features will fail the policy check.
In order to limit this check to a certain list of files, use the `include` modifier
```
  binaryHardening:
    requiredFeatures:
      - NX
      - PIE
      - RELRO
      - CANARY
      - STRIPPED
    # optional whitelist of binaries to check for above features. if omitted, all binaries will be checked
    include:
      - /opt/vendor/*
      - /root/*
```

### Rule: Security Checklist

Firmware images can contain pre existing known threats such as backdoors, malware or known exploits. Security
checklist looks for these direct indicators of compromise. We recommend all policies not allow for any Security
Checklist results.
```
  securityChecklist:
    allowed: false
```

### Rule: SBOM

Software Bill of Materials (SBOM) identifies open source components that are used in firmware images.
`prohbitedComponents` can list components that should not be present in final firmware images, such as gdbserver
or tcpdump.
`prohibitedLicenses` defines software licenses which are prohibited in the identified components in the firmware.
The license identifiers match those in the SPDX standard. A common use case could be to block restrictive licenses
like GPL, but define exceptions for specific components that have been approved for distribution.
```
  sbom:
    # components that are not allowed in firmware
    prohibitedComponents:
      - tcpdump
      - libpcap
      - gdbserver

    # components using prohibited licenses
    licenses:
      # use SPDX license identifiers (https://spdx.org/licenses/)
      # can use regex
      prohibitedLicenses:
        - GPL-1.0-or-later
        - GPL-*

      # components approved to use prohibited licenses
      exceptions:
        - busybox
        - dnsmasq
```

### Mapping policy results to a standard

Policy results can be mapped to a security standard. Each element of a standard that relates to a Binwalk
analysis result can be defined, and then the policy rules that apply to that standard are listed. If the
policy rule fails, then the element of the standard also fails.

This is optional - standard mapping is only performed if the `standard` tag is present.

Here is an example mapping the two of the elements of the OWASP IoT Top 10 to Binwalk policy results:
```
standard:
  name: IoT OWASP Top 10

  description: >
    The OWASP Foundation publishes a list of the Top 10 things to
    avoid when building, deploying or managing IoT systems 
    (https://owasp.org/www-project-internet-of-things/). Binwalk
    security policies map to a subset of the Top 10 rules.
  
  mappings:
    - item: I1
      title: I1 - Weak, Guessable, or Hardcoded Passwords
      description: >
        Binwalk detects hard coded accounts and weak passwords.
      policies:
        - passwordHashes

    - item: I2
      title: I2 - Insecure Network Services
      description: >
        Binwalk detects a number of issues which can be a source
        of insecure networking services, including expired certificates,
        use of private keys, poor code, lack of binary hardening, or
        known backdoors and exploits. 
      policies:
        - certificates
        - privateKeys
        - code
        - binaryHardening
        - securityChecklist
```

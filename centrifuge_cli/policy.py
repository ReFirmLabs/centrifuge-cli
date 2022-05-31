#!/usr/bin/env python3
import re
import os
import io
import csv
import sys
import json
import time
import yaml
import click
from datetime import datetime
import chevron
import dateparser

CSV_HEADER = ["Policy Name", "Compliant"]
POLICY_DETAIL_MAPPING = {
    "certificates": {
        "name": "Expired Certificates",
        "method": "checkCertificateRule",
        "status": "Fail",
        "reasons": []
    },
    "privateKeys": {
        "name": "Private Keys",
        "method": "checkPrivateKeyRule",
        "status": "Fail",
        "reasons": []
    },
    "passwordHashes": {
        "name": "Weak Password Algorithms",
        "method": "checkPasswordHashRule",
        "status": "Fail",
        "reasons": []
    },
    "code": {
        "name": "Code Flaws",
        "method": "checkCodeFlawsRule",
        "status": "Fail",
        "reasons": []
    },
    "guardian": {
        "name": "CVE Threshold",
        "method": "checkGuardianRule",
        "status": "Fail",
        "reasons": []
    },
    "binaryHardening": {
        "name": "Binary Hardness",
        "method": "checkBinaryHardeningRule",
        "status": "Fail",
        "reasons": []
    },
    "securityChecklist": {
        "name": "Security Checklist",
        "method": "checkSecurityChecklistRule",
        "status": "Fail",
        "reasons": []
    },
    "sbom": {
        "name": "SBOM Components",
        "method": "checkSBOMRule",
        "status": "Fail",
        "reasons": []
    }
}
POLICIES = [
    'certificates',
    'privateKeys',
    'passwordHashes',
    'code',
    'guardian',
    'binaryHardening',
    'securityChecklist',
    'sbom'
]


class CentrifugePolicyCheck(object):
    """
    A class to process POLICIES specified in YAML file.
    """
    def __init__(self,
                 certificates_json,
                 private_keys_json,
                 binary_hardening_json,
                 guardian_json,
                 code_summary_json,
                 passhash_json,
                 checklist_json,
                 sbom_json,
                 info_json,
                 verbose=False):
        self.certificates_json = certificates_json
        self.private_keys_json = private_keys_json
        self.binary_hardening_json = binary_hardening_json
        self.guardian_json = guardian_json
        self.code_summary_json = code_summary_json
        self.passhash_json = passhash_json
        self.checklist_json = checklist_json
        self.sbom_json = sbom_json
        self.info_json = info_json
        self.verbose = verbose
        self.yaml_config = None

    def verboseprint(self, *args):
        """
        Wrapper to print function which only prints data if verbose flag is specified.
        """
        if self.verbose:
            print(*args)

    def match_regex_against_path(self, exception_regex, path_list):
        """
        Method to match the list of regexes with list of paths. Paths are unix system path.
        """
        exceptions_in_path = []
        if exception_regex:
            for regex in exception_regex:
                if regex:
                    exceptions = list(
                        filter(lambda path: re.search(regex, path), path_list))
                    exceptions_in_path = exceptions_in_path + exceptions
        return exceptions_in_path
    
    def reason(self, rule, msg, uri=""):
        return {
            'msg': msg,
            'rule': rule,
            'uri': uri
        }
    
    def reasons_just_msg(self, reasons):
        msgs = []
        for reason in reasons:
            msgs.append(reason['msg'])
        return msgs

    def checkSecurityChecklistRule(self, value):
        if not value.get('allowed'):
            json_data = self.checklist_json
            passing = json_data['summary']['passing']
            total = json_data['summary']['total']
            if (total - passing) > 0:
                reasons = []
                for result in json_data['results']:
                    if result['statusCode'] == 1:
                        name = result['Analyzer']['name']
                        reasons.append(self.reason('security-checklist', f'{name} was found during Security Checklist scan'))
                return False, reasons

        return True, []

    def checkCertificateRule(self, value):
        self.verboseprint("Checking Certificate Rule...")
        rule_passed = True
        reasons = []
        json_data = self.certificates_json
        if not value.get('expired', {}).get('allowed'):
            if json_data.get("count") > 0:
                expired_check_time = int(time.time())
                expiring_within_threshold = value.get('expired', {}).get('prevent_expiring', '')
                if expiring_within_threshold:
                    dt = dateparser.parse(expiring_within_threshold)
                    if dt < datetime.now():
                        raise RuntimeError('Certificate expiring_within policy date is in the past, be sure to use "in" if specifying a time interval i.e. "in 2 weeks"')
                    expired_in_future_time = int(dt.timestamp())
                else:
                    expired_in_future_time = expired_check_time
                # Remove exceptions from results if any
                for cert in json_data.get("results"):
                    exceptions = value.get("exceptions", [])
                    exceptions_in_path = self.match_regex_against_path(exceptions, cert["paths"])
                    if exceptions_in_path:
                        for path_ex in exceptions_in_path:
                            self.verboseprint(f'...skipping certificate found at {path_ex}')
                            cert["paths"].remove(path_ex)
                    if cert["paths"]:
                        # Check if certificate is expired.
                        cert_expiry_timestamp = int(cert["validityEnd"][:-3])
                        if expired_in_future_time > cert_expiry_timestamp:
                            rule_passed = False
                            subject = cert["subject"]["commonName"]
                            for path in cert["paths"]:
                                if expired_check_time > cert_expiry_timestamp:
                                    reason = self.reason('certificate-expired', f'Certificate "{subject}" expired at {path}', path)
                                else:
                                    reason = self.reason('certificate-expiring', f'Certificate "{subject}" will expire before "{expiring_within_threshold}" at {path}', path)
                                reasons.append(reason)
                                self.verboseprint(f'...failing: {reason["msg"]}')
        return rule_passed, reasons

    def checkPrivateKeyRule(self, value):
        self.verboseprint("Checking Private Key Rule...")
        rule_passed = True
        reasons = []
        json_data = self.private_keys_json
        if not value.get('allowed'):
            if json_data.get("count") > 0:
                # Remove exceptions from results if any
                for pk in json_data.get("results"):
                    exceptions = value.get("exceptions", [])
                    exceptions_in_path = self.match_regex_against_path(exceptions, pk["paths"])
                    if exceptions_in_path:
                        for path_ex in exceptions_in_path:
                            self.verboseprint(f'...skipping key found at {path_ex}')
                            pk["paths"].remove(path_ex)
                    if pk["paths"]:
                        rule_passed = False
                        for path in pk["paths"]:
                            reason = self.reason('private-key', f'private key found at {path}', path)
                            reasons.append(reason)
                            self.verboseprint(f'...failing: {reason["msg"]}')
        return rule_passed, reasons

    def check_files_for_binary_hardening(self, obj, value):
        boolean_feature = ("nx", "canary", "pie", "stripped")
        for feature in value.get("requiredFeatures", []):
            if feature.lower() in boolean_feature:
                if not obj.get(feature.lower()):
                    return False
            elif feature.lower() == "relro":
                if obj.get(feature.lower()) != "full":
                    return False
            else:
                self.verboseprint(f'{feature} feature is not a valid one')
        return True

    def checkBinaryHardeningRule(self, value):
        self.verboseprint("Checking Binary Hardening Rule...")
        rule_passed = True
        reasons = []
        includes = value.get("include", [])
        json_data = self.binary_hardening_json
        if json_data.get("count") > 0:
            for obj in json_data.get("results"):
                if includes:
                    path_included = self.match_regex_against_path(includes, obj["paths"])
                    if not path_included:
                        continue
                if not self.check_files_for_binary_hardening(obj, value):
                    path = obj["paths"][0]
                    reason = self.reason('binary-hardening', f'invalid binary hardening settings at {path}', path)
                    reasons.append(reason)
                    self.verboseprint(f'...failing: {reason["msg"]}')
                    rule_passed = False
        return rule_passed, reasons

    def checkGuardianRule(self, value):
        self.verboseprint("Checking Guardian Rule...")
        rule_passed = True
        reasons = []
        json_data = self.guardian_json
        cvssScoreThreshold = value.get("cvssScoreThreshold", 10.0)
        cveAgeThreshold = value.get("cveAgeThreshold", 0)
        if cveAgeThreshold > 0 and cveAgeThreshold < 1999:
            current_year = int(datetime.now().year)
            cveAgeThreshold = current_year - cveAgeThreshold
        if json_data["count"] > 0:
            for guardian_obj in json_data.get("results"):
                if value.get("exceptions", []):
                    matched_path = list(
                        filter(lambda regex: re.search(regex, guardian_obj["path"]), value.get("exceptions"))
                    )
                    if matched_path:
                        self.verboseprint(f'...skipping exception {guardian_obj["path"]}')
                        continue
                if float(guardian_obj["severity"]) > cvssScoreThreshold:
                    reason = self.reason(
                        'cvss-score-threshold',
                        f'CVE Score threshold exceeded for {guardian_obj["name"]} ({guardian_obj["severity"]}) for {guardian_obj["component"]} at {guardian_obj["path"]}',
                        guardian_obj["path"])
                    reasons.append(reason)
                    self.verboseprint(f'...failing: {reason["msg"]}')
                    rule_passed = False
                cveAge = int(guardian_obj["name"][4:8])
                if cveAge <= cveAgeThreshold:
                    reason = self.reason(
                        'cvss-age',
                        f'CVE Age threshold exceeded for {guardian_obj["name"]} ({cveAge}) for {guardian_obj["component"]} at {guardian_obj["path"]}',
                        guardian_obj["path"]
                    )
                    reasons.append(reason)
                    self.verboseprint(f'...failing: {reason["msg"]}')
                    rule_passed = False
        return rule_passed, reasons

    def checkCodeFlawsRule(self, value):
        self.verboseprint("Checking Code Flaws Rule...")
        rule_passed = True
        reasons = []
        json_data = self.code_summary_json
        allowed = value.get("flaws", {}).get("allowed")
        critical = value.get("flaws", {}).get("allowCritical")
        if not allowed or not critical:
            if json_data.get("count") > 0:
                for code_obj in json_data.get("results"):
                    if value.get("exceptions", []):
                        matched_path = list(
                            filter(lambda regex: re.search(regex, code_obj["path"]), value.get("exceptions"))
                        )
                        if matched_path:
                            self.verboseprint(f'...skipping exception {code_obj["path"]}')
                            continue
                    if not allowed and code_obj["totalFlaws"] > 0:
                        reason = self.reason(
                            'code-total-flaws',
                            f'{code_obj["totalFlaws"]} total flaws in {code_obj["path"]}',
                            code_obj["path"]
                        )
                        reasons.append(reason)
                        self.verboseprint(f'...failing: {reason["msg"]}')
                        rule_passed = False
                    elif not critical and code_obj["emulatedFunctionCount"] > 0:
                        reason = self.reason(
                            'code-critical-flaws',
                            f'{code_obj["emulatedFunctionCount"]} critical flaws in {code_obj["path"]}',
                            code_obj["path"]
                        )
                        reasons.append(reason)
                        self.verboseprint(f'...failing: {reason["msg"]}')
                        rule_passed = False
        return rule_passed, reasons

    def checkPasswordHashRule(self, value):
        self.verboseprint("Checking Password Hash Rule...")
        rule_passed = True
        reasons = []
        json_data = self.passhash_json
        if json_data.get("count") > 0:
            if not value.get("allowUserAccounts", True):
                reason = self.reason(
                    'allow-user-accounts',
                    f'allowUserAccounts - identified {json_data.get("count")} accounts',
                )
                reasons.append(reason)
                self.verboseprint(f'...failing: {reason["msg"]}')
                rule_passed = False
            for hash_obj in json_data.get("results"):
                if hash_obj.get("algorithm") in value.get("weakAlgorithms", []):
                    reason = self.reason(
                        'weak-user-account-password-algorithm',
                        f'weakAlgorithm {hash_obj["algorithm"]} for user {hash_obj["username"]}',
                    )
                    reasons.append(reason)
                    self.verboseprint(f'...failing: {reason["msg"]}')
                    rule_passed = False
        return rule_passed, reasons

    def checkSBOMRule(self, value):
        self.verboseprint("Checking SBOM Rule...")
        rule_passed = True
        reasons = []
        sbom = self.sbom_json
        prohibitedComponents = value.get("prohibitedComponents")
        prohibitedLicenses = []
        for r in value.get("licenses", {}).get("prohibitedLicenses", []) or []:
            prohibitedLicenses.append(re.compile(r))
        exceptedLicenseComponents = value.get("licenses", {}).get("exceptions", []) or []
        if sbom.get("count") > 0:
            for component in sbom.get("results"):
                if component.get("name") in prohibitedComponents:
                    reason = self.reason(
                        'sbom-prohibited-component',
                        f'SBOM Component {component["name"]} is prohibited at {component["paths"][0]}',
                        component["paths"][0]
                    )
                    reasons.append(reason)
                    self.verboseprint(f'...failing: {reason["msg"]}')
                    rule_passed = False
                if not component.get("name") in exceptedLicenseComponents:
                    licenseUsed = component.get('license')
                    for r in prohibitedLicenses:
                        if re.match(r, licenseUsed):
                            reason = self.reason(
                                'sbom-prohibited-license',
                                f'SBOM Component {component["name"]} uses prohibited license {component["license"]} at {component["paths"][0]}',
                                component["paths"][0]
                            )
                            reasons.append(reason)
                            self.verboseprint(f'...failing: {reason["msg"]}')
                            rule_passed = False
                            break
        return rule_passed, reasons

    def call_policy_method(self, policy_name, ruledef):
        policy_method = getattr(self, POLICY_DETAIL_MAPPING.get(policy_name).get("method"))
        return policy_method(ruledef)

    def checkRule(self, name, ruledef):
        """
        Method which calls the respective rule checking function for rule name and populates the
        compliant of policy.
        """
        if name in POLICY_DETAIL_MAPPING:
            rule_passed, reasons = self.call_policy_method(name, ruledef)
            policy_status = "Pass" if rule_passed else "Fail"
            POLICY_DETAIL_MAPPING.get(name).update({"status": policy_status})
            POLICY_DETAIL_MAPPING.get(name).update({"reasons": reasons})
        else:
            raise RuntimeError(f'Invalid Rule name {name}')

    def generate_csv(self):
        output = io.StringIO()
        field_names = CSV_HEADER
        field_names.append("Reasons")
        writer = csv.DictWriter(output, fieldnames=field_names)
        writer.writeheader()
        for _, policy_detail in POLICY_DETAIL_MAPPING.items():
            row_data = {"Policy Name": policy_detail.get("name"), "Compliant": policy_detail.get("status")}
            row_data.update({"Reasons": self.reasons_just_msg(policy_detail.get("reasons"))})
            writer.writerow(row_data)
        return output.getvalue()

    def build_json(self):
        final_result_dict = {
            "finalResult": "Pass",
            "results": []
        }
        final_result_dict.update({
            "info": {
                "vendor": self.info_json["vendor"],
                "device": self.info_json["device"],
                "version": self.info_json["version"]
            }
        })
        for policy, policy_detail in POLICY_DETAIL_MAPPING.items():
            if policy_detail.get("status") != "Pass":
                final_result_dict["finalResult"] = "Fail"
            final_result = {
                "rule": policy,
                "name": policy_detail.get("name"),
                "compliant": policy_detail.get("status")
            }
            final_result.update({"reasons": self.reasons_just_msg(policy_detail.get("reasons"))})
            final_result_dict.get("results").append(final_result)

        if "standard" in self.yaml_config:
            standard = self.yaml_config["standard"]
            sr = {
                "name": standard["name"],
                "description": standard["description"],
                "compliant": "Pass",
                "items": []
            }
            for mapping in standard["mappings"] or []:
                item = {
                    "item": mapping["item"],
                    "title": mapping["title"],
                    "description": mapping["description"],
                    "compliant": "Pass",
                    "results": []
                }
                for policy in mapping["policies"] or []:
                    # Check if policy passed or failed
                    if policy in POLICY_DETAIL_MAPPING:
                        compliant = POLICY_DETAIL_MAPPING[policy].get("status")
                        item.get("results").append({
                            "policy": POLICY_DETAIL_MAPPING[policy].get("name"),
                            "compliant": compliant
                        })
                        if compliant != "Pass":
                            item["compliant"] = "Fail"
                            sr["compliant"] = "Fail"
                sr.get("items").append(item)
            final_result_dict["standard"] = sr
        return final_result_dict

    def generate_json(self):
        json_results = self.build_json()
        return json.dumps(json_results, indent=2, sort_keys=True)

    def generate_report(self, report_template):
        json_results = self.build_json()
        with open(report_template, 'r') as f:
            return chevron.render(f, json_results)

    def generate_sarif(self, report_url):
        # Sarif header
        sarif = {
            "version": "2.1.0",
            "$schema": "http://json.schemastore.org/sarif-2.1.0-rtm.4",
            "runs": [
                {
                  "tool": {
                        "driver": {
                            "name": "Binwalk Enterprise",
                            "informationUri": "https://www.refirmlabs.com",
                            "rules": [
                                {
                                    "id": "security-checklist",
                                    "shortDescription": {
                                        "text": "Known malware, exploits or backdoors"
                                    }
                                },
                                {
                                    "id": "certificate-expired",
                                    "shortDescription": {
                                        "text": "Expired certificates"
                                    }
                                },
                                {
                                    "id": "certificate-expiring",
                                    "shortDescription": {
                                        "text": "Certificates expiring within x months by policy"
                                    }
                                },
                                {
                                    "id": "private-key",
                                    "shortDescription": {
                                        "text": "Contains private keys"
                                    }
                                },
                                {
                                    "id": "binary-hardening",
                                    "shortDescription": {
                                        "text": "Compiler binary hardening settings must meet policy"
                                    }
                                },
                                {
                                    "id": "cvss-score-threshold",
                                    "shortDescription": {
                                        "text": "Known CVEs above policy threshold"
                                    }
                                },
                                {
                                    "id": "cvss-age",
                                    "shortDescription": {
                                        "text": "Known CVEs older than policy age"
                                    }
                                },
                                {
                                    "id": "code-total-flaws",
                                    "shortDescription": {
                                        "text": "Potential code flaws (buffer overflow / command injection)"
                                    }
                                },
                                {
                                    "id": "code-critical-flaws",
                                    "shortDescription": {
                                        "text": "Contains critical (emulated) code flaws"
                                    }
                                },
                                {
                                    "id": "allow-user-accounts",
                                    "shortDescription": {
                                        "text": "Contains hard coded user accounts"
                                    }
                                },
                                {
                                    "id": "weak-user-account-password-algorithm",
                                    "shortDescription": {
                                        "text": "User accounts use weak password algorithms"
                                    }
                                },
                                {
                                    "id": "sbom-prohibited-component",
                                    "shortDescription": {
                                        "text": "Contains prohibited SBOM components"
                                    }
                                },
                                {
                                    "id": "sbom-prohibited-license",
                                    "shortDescription": {
                                        "text": "Contains SBOM components with prohibited licenses"
                                    }
                                },
                        ]
                        }
                    },
                    "artifacts": [],
                    "results": []
                }
            ]
        }

        # Add results
        results = []
        for _, policy_detail in POLICY_DETAIL_MAPPING.items():
            reasons = policy_detail.get("reasons")
            for reason in reasons:
                results.append({
                    "ruleId": reason["rule"],
                    "level": "error",
                    "message": {
                        "text": f'{reason["msg"]} - [details]({report_url})'
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                "uri": f'file://{reason["uri"]}'
                                }
                            }
                        }
                    ]
                })
        sarif.get("runs")[0].update({ "results": results })

        return json.dumps(sarif, indent=2, sort_keys=False)

    def check_rules(self, config_file):
        with open(config_file, 'r') as stream:
            try:
                self.yaml_config = yaml.safe_load(stream)
                for _, rule in enumerate(POLICY_DETAIL_MAPPING):
                    if rule in self.yaml_config['rules']:
                        self.checkRule(rule, self.yaml_config['rules'][rule])
                    else:
                        POLICY_DETAIL_MAPPING.get(rule).update({"status": "No Policy Specified"})
            except yaml.YAMLError as exc:
                click.echo(f'Error occurred while loading YAML file. {str(exc)}')

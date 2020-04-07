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

CSV_HEADER = ["Policy Name", "Compliant"]
POLICY_DETAIL_MAPPING = {
    "certificates": {
        "name": "Expired Certificates",
        "method": "checkCertificateRule",
        "status": "Fail"
    },
    "privateKeys": {
        "name": "Private Keys",
        "method": "checkPrivateKeyRule",
        "status": "Fail"
    },
    "passwordHashes": {
        "name": "Weak Password Algorithms",
        "method": "checkPasswordHashRule",
        "status": "Fail"
    },
    "code": {
        "name": "Code Flaws",
        "method": "checkCodeFlawsRule",
        "status": "Fail"
    },
    "guardian": {
        "name": "CVE Threshold",
        "method": "checkGuardianRule",
        "status": "Fail"
    },
    "binaryHardening": {
        "name": "Binary Hardness",
        "method": "checkBinaryHardeningRule",
        "status": "Fail"
    }
}
POLICIES = [
    'certificates',
    'privateKeys',
    'passwordHashes',
    'code',
    'guardian',
    'binaryHardening'
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
                 verbose=False):
        self.certificates_json = certificates_json
        self.private_keys_json = private_keys_json
        self.binary_hardening_json = binary_hardening_json
        self.guardian_json = guardian_json
        self.code_summary_json = code_summary_json
        self.passhash_json = passhash_json
        self.verbose = verbose

    def verboseprint(self, *args):
        """
        Wrapper to print function which only prints data if verbose flag is specified.
        """
        if self.verbose:
            print(*args)

    def match_regex_against_path(self, exception_regex, path_list):
        """
        Method to match the regex with list of paths. Paths are unix system path.
        """
        exception_in_path = []
        if exception_regex:
            for regex in exception_regex:
                if regex:
                    exception_in_path = list(
                        filter(lambda path: re.search(regex, path),
                               list(map(lambda path: path, path_list)))
                    )
        return exception_in_path

    def checkCertificateRule(self, value):
        count = 0

        self.verboseprint("Checking Certificate Rule..")
        json_data = self.certificates_json
        if not value.get('expired', {}).get('allowed'):
            if json_data.get("count") > 0:
                # Remove exceptions from results if any
                for cert in json_data.get("results"):
                    exceptions = value.get("exceptions", [])
                    exception_in_path = self.match_regex_against_path(exceptions, cert["paths"])
                    if exception_in_path:
                        for path_ex in exception_in_path:
                            cert["paths"].remove(path_ex)
                    if cert["paths"]:
                        # Check if certificate is expired.
                        cert_expiry_timestamp = int(cert["validityEnd"][:-3])
                        if int(time.time()) > cert_expiry_timestamp:
                            count += 1
                    else:
                        raise RuntimeError(f'Certificate {cert["rflid"]} is exception')
                if count > 0:
                    return "Fail"
                else:
                    return "Pass"
            else:
                return "Pass"

    def checkPrivateKeyRule(self, value):
        count = 0

        json_data = self.private_keys_json
        if not value.get('allowed'):
            if json_data.get("count") > 0:
                # Remove exceptions from results if any
                for pk in json_data.get("results"):
                    exceptions = value.get("exceptions", [])
                    exception_in_path = self.match_regex_against_path(exceptions, pk["paths"])
                    if exception_in_path:
                        for path_ex in exception_in_path:
                            pk["paths"].remove(path_ex)
                    if not pk["paths"]:
                        count += 1
                if len(json_data["results"]) != count:
                    return "Fail"
                else:
                    return "Pass"
            else:
                return "Pass"
        else:
            return "Pass"

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
        count = 0
        json_data = self.binary_hardening_json
        if json_data.get("count") > 0:
            for obj in json_data.get("results"):
                exceptions = value.get("include", [])
                path_included = self.match_regex_against_path(exceptions, obj["paths"])
                if path_included:
                    rule_passed = self.check_files_for_binary_hardening(obj, value)
                    if not rule_passed:
                        count += 1
                else:
                    # Check each and every file against binary hardening
                    rule_passed = self.check_files_for_binary_hardening(obj, value)
                    if not rule_passed:
                        count += 1
            if count > 0:
                return "Fail"
            else:
                return "Pass"
        else:
            return "Pass"

    def checkGuardianRule(self, value):
        count = 0
        json_data = self.guardian_json
        if json_data["count"] > 0:
            for guardian_obj in json_data.get("results"):
                if float(guardian_obj["severity"]) > value["cvssScoreThreshold"]:
                    count += 1
            if count > 0:
                return "Fail"
            else:
                return "Pass"
        else:
            return "Pass"

    def checkCodeFlawsRule(self, value):
        count = 0
        json_data = self.code_summary_json
        if not value.get("flaws", {}).get("allowed"):
            if json_data.get("count") > 0:
                for code_obj in json_data.get("results"):
                    if value.get("exceptions", []):
                        matched_path = list(
                            filter(lambda regex: re.search(regex, code_obj["path"]), value.get("exceptions"))
                        )
                        # Check total flaws if code path is specified in YAML file
                        if matched_path and code_obj["totalFlaws"] > 0:
                            count += 1
                    else:
                        if code_obj["totalFlaws"] > 0:
                            count += 1
                if count > 0:
                    return "Fail"
                else:
                    return "Pass"
            else:
                return "Pass"
        else:
            return "Pass"

    def checkPasswordHashRule(self, value):
        count = 0
        json_data = self.passhash_json
        if json_data.get("count") > 0:
            for hash_obj in json_data.get("results"):
                if hash_obj.get("algorithm") in value.get("weakAlgorithms", []):
                    count += 1
            if count > 0:
                return "Fail"
            else:
                return "Pass"
        else:
            return "Pass"

    def call_policy_method(self, policy_name, ruledef):
        policy_method = getattr(self, POLICY_DETAIL_MAPPING.get(policy_name).get("method"))
        return policy_method(ruledef)

    def checkRule(self, name, ruledef):
        """
        Method which calls the respective rule checking function for rule name and populates the
        compliant of policy.
        """
        if name == 'privateKeys':
            policy_status = self.call_policy_method(name, ruledef)
            POLICY_DETAIL_MAPPING.get(name).update({"status": policy_status})
        elif name == 'certificates':
            policy_status = self.call_policy_method(name, ruledef)
            POLICY_DETAIL_MAPPING.get(name).update({"status": policy_status})
        elif name == 'passwordHashes':
            policy_status = self.call_policy_method(name, ruledef)
            POLICY_DETAIL_MAPPING.get(name).update({"status": policy_status})
        elif name == 'code':
            policy_status = self.call_policy_method(name, ruledef)
            POLICY_DETAIL_MAPPING.get(name).update({"status": policy_status})
        elif name == 'guardian':
            policy_status = self.call_policy_method(name, ruledef)
            POLICY_DETAIL_MAPPING.get(name).update({"status": policy_status})
        elif name == 'binaryHardening':
            policy_status = self.call_policy_method(name, ruledef)
            POLICY_DETAIL_MAPPING.get(name).update({"status": policy_status})
        else:
            raise RuntimeError(f'Invalid Rule name {name}')

    def generate_csv(self):
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=CSV_HEADER)
        writer.writeheader()
        for policy, policy_detail in POLICY_DETAIL_MAPPING.items():
            writer.writerow({"Policy Name": policy_detail.get("name"), "Compliant": policy_detail.get("status")})
        return output.getvalue()

    def generate_json(self):
        final_result_dict = {
            "finalResult": "Pass",
            "results": []
        }
        for policy, policy_detail in POLICY_DETAIL_MAPPING.items():
            if policy_detail.get("status") != "Pass":
                final_result_dict["finalResult"] = "Fail"
            final_result_dict.get("results").append(
                {
                    "rule": policy,
                    "name": policy_detail.get("name"),
                    "compliant": policy_detail.get("status")
                }
            )
        return json.dumps(final_result_dict, indent=2, sort_keys=True)

    def check_rules(self, config_file):
        with open(config_file, 'r') as stream:
            try:
                res = yaml.safe_load(stream)
                for i, rule in enumerate(POLICIES):
                    if rule in res['rules']:
                        self.checkRule(rule, res['rules'][rule])
                    else:
                        POLICY_DETAIL_MAPPING.get(rule).update({"status": "No Policy Specified"})
            except yaml.YAMLError as exc:
                click.echo(f'Error occurred while loading YAML file. {str(exc)}')

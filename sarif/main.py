#!/usr/bin/env python

import json
import os
import re
import requests
from requests.auth import HTTPBasicAuth
import time

DEFAULT_TIMEOUT_SECONDS = 300
POLL_INTERVAL_SECONDS = 5


def get_file_path(components, file_key):
    return next((item['path'] for item in components if item['key'] == file_key), None)


def to_artifact(component):
    return {
        'location': {
            'uri': component['path'],
            'uriBaseId': '%SRCROOT%'
        }
    }


def to_artifacts(components):
    files_component = filter(lambda c: c['qualifier'] == 'FIL', components)
    return [to_artifact(issue) for issue in files_component]


def to_rule(rule):
    return {
        'id': rule['key'],
        'name': rule['key'],
        'shortDescription': {
            'text': rule['name']
        }
    }


def to_rules(issues):
    return [to_rule(rule) for rule in issues]


def to_result(issue, components):
    file_uri = next((item['path'] for item in components if item['key'] == issue['component']), None)
    return {
        'ruleId': issue['rule'],
        'message': {
            'text': issue['message']
        },
        'locations': [{
            'physicalLocation': {
                'artifactLocation': {
                    'uri': file_uri,
                    'uriBaseId': '%SRCROOT%'
                },
                'region': {
                    'startLine': issue['textRange']['startLine'],
                    'endLine': issue['textRange']['endLine']
                }
            }
        }]
    }


def to_results(issues):
    return [to_result(issue, issues['components']) for issue in issues['issues']]


def create_report(issues):
    artifacts = to_artifacts(issues['components'])
    return {
        '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'SonarCloud',
                    'organization': 'SonarSource',
                    'rules': to_rules(issues['rules'])
                }
              },
            'artifacts': artifacts,
            'results': to_results(issues),
            'newlineSequences': ['\r\n', '\n', 'â€¨', 'â€©'],
            'columnKind': 'utf16CodeUnits'
        }]
    }


class QualityCheckError(BaseException):
    def __init__(self, message):
        self.message = message


class ReportTask:
    def __init__(self, path):
        with open(path, "r") as file:
            content = file.read()
            self.organization = self._extract_property("organization", content)
            self.project_key = self._extract_property("projectKey", content)
            self.task_id = self._extract_property("ceTaskId", content)
            self.ce_task_url = self._extract_property("ceTaskUrl", content)

    @staticmethod
    def _extract_property(key, scanner_report):
        match = re.search(rf'{key}=(.*)', scanner_report)
        if match:
            return match.group(1)

        raise Exception(f"Could not find property {key} from scanner report")


def compute_max_retry_count(poll_interval_seconds, timeout_seconds):
    return timeout_seconds // poll_interval_seconds


class QualityGateStatus:
    def __init__(self, obj):
        try:
            self.status = obj['projectStatus']['status']
        except:
            raise QualityCheckError("Could not parse quality gate status from json: {}".format(json.dumps(obj)))


class CeTask:
    def __init__(self, obj):
        """
        >>> CeTask({"task": {"status": "IN_PROGRESS"}}).is_completed()
        False
        """
        try:
            self.status = obj['task']['status']
            self.completed = self.status not in ('IN_PROGRESS', 'PENDING')
            self.analysis_id = obj['task'].get('analysisId')
        except:
            raise QualityCheckError("Could not parse compute engine task from json: {}".format(json.dumps(obj)))

    def is_completed(self):
        return self.completed


class SonarCloudClient:
    def __init__(self, sonar_token):
        self.sonar_token = sonar_token

    def _get_response_as_dict(self, url, error_message_prefix):
        req = requests.get(url, auth=HTTPBasicAuth(self.sonar_token, ''))
        if req.status_code != 200:
            try:
                errors_as_dict = req.json()
                errors_summary = '; '.join([e['msg'] for e in errors_as_dict['errors']])
                raise QualityCheckError("{}: {}".format(error_message_prefix, errors_summary))
            except:
                content = req.content
                raise QualityCheckError("{}: {}".format(error_message_prefix, content))

        return req.json()

    def get_ce_task(self, url):
        return CeTask(self._get_response_as_dict(url, "Could not fetch compute engine task"))

    def get_issues(self, organization, project):
        url = f'https://sonarcloud.io/api/issues/search?organization={organization}&projects={project}&additionalFields=rules&resolved=false'
        return self._get_response_as_dict(url, "Could not fetch issue list")

    def get_quality_gate_status(self, url):
        return QualityGateStatus(self._get_response_as_dict(url, "Could not fetch quality gate status"))


def create_ce_task_getter(client, ce_task_url):
    return lambda: client.get_ce_task(ce_task_url)


def wait_for_completed_ce_task(ce_task_getter, max_retry_count, poll_interval_seconds=POLL_INTERVAL_SECONDS):
    for _ in range(1 + max_retry_count):
        ce_task = ce_task_getter()
        if ce_task.is_completed():
            return ce_task

        print('.', end='')

        time.sleep(poll_interval_seconds)

    raise QualityCheckError("Compute engine task did not complete within time")


def get_quality_gate_status_url(ce_task):
    return "https://sonarcloud.io/api/qualitygates/project_status?analysisId={}".format(ce_task.analysis_id)


def get_variable(name, required=False, default=None):
    value = os.getenv(name)
    if required and (value is None or not value.strip()):
        raise Exception('{} variable missing.'.format(name))
    return value if value else default


def main():
    sonar_token = get_variable('SONAR_TOKEN', required=True)
    report_path = get_variable('REPORT_PATH', required=True)
    timeout_seconds = get_variable('SONAR_QUALITY_GATE_TIMEOUT', required=False, default=DEFAULT_TIMEOUT_SECONDS)

    client = SonarCloudClient(sonar_token)

    scanner_report = ReportTask(report_path)

    max_retry_count = compute_max_retry_count(POLL_INTERVAL_SECONDS, timeout_seconds)
    ce_task = wait_for_completed_ce_task(create_ce_task_getter(client, scanner_report.ce_task_url), max_retry_count)

    quality_gate_status_url = get_quality_gate_status_url(ce_task)
    quality_gate_status = client.get_quality_gate_status(quality_gate_status_url)

    if quality_gate_status.status == 'OK' or quality_gate_status.status == 'ERROR':
        print(f"QG {quality_gate_status.status}")
        issues = client.get_issues(scanner_report.organization, scanner_report.project_key)

        print(json.dumps(issues, indent=2))
        create_report(issues)
        with open('sonarcloud-output.sarif.json', 'w') as output:
            output.write(json.dumps(create_report(issues), indent=2))
    else:
        print("QG error")


if __name__ == '__main__':
    main()

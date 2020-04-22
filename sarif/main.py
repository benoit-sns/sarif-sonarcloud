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


def to_level(severity):
    severity_to_level = {
        'INFO': 'note',
        'MINOR': 'note',
        'MAJOR': 'warning',
        'CRITICAL': 'error',
        'BLOCKER': 'error'
    }
    return severity_to_level.get(severity)


def to_rule(rule):
    return {
        'id': rule['key'],
        'name': rule['key'],
        'shortDescription': {
            'text': rule['name']
        },
        'fullDescription': {
            'text': rule['name']
        },
        'help': {
            'text': rule['mdDesc']
        },
        'properties': {
            'tags': rule['sysTags']
        },
        'defaultConfiguration': {
            'level': to_level(rule['severity'])
        },
    }


def to_rules(client, issues):
    return [to_rule(client.get_rule(rule['key'])) for rule in issues]


def region(issue):
    return {
        'startLine': issue['textRange']['startLine'],
        'endLine': issue['textRange']['endLine'],
        'startColumn': issue['textRange']['startOffset'] + 1,
        'endColumn': issue['textRange']['endOffset'] + 1
    }


def to_flow(flow, components, index):
    return {
        'location': {
            'id': index + 1,
            'physicalLocation': {
                'region': region(flow),
                'artifactLocation': {
                    'uriBaseId': '%SRCROOT%',
                    'uri': get_file_path(components, flow['component'])
                }
            },
            'message': {
                'text': flow.get('msg', "")
            }
        }
      }


def has_multi_location(issue):
    return 'flows' in issue and len(issue['flows']) > 0


def create_multi_locations(issue, components):
    return [to_flow(flow, components, i) for i, flow in enumerate(reversed(issue['flows'][0]['locations']))]


def to_location(issue, components):
    file_uri = next((item['path'] for item in components if item['key'] == issue['component']), None)
    return {
        'physicalLocation': {
            'artifactLocation': {
                'uri': file_uri,
                'uriBaseId': '%SRCROOT%'
            },
            'region': region(issue)
        }
    }


def to_result(issue, components):
    result = {
        'ruleId': issue['rule'],
        'message': {
            'text': issue['message']
        },
        'locations': [to_location(issue, components)]
    }

    if has_multi_location(issue):
        multi_locations = create_multi_locations(issue, components)
        result['codeFlows'] = [{
            'threadFlows': [{
                'locations': multi_locations
            }]
        }]

    return result


def issue_has_location(issue, components):
    component = next((file for file in components if file['key'] == issue['component']), None)

    return 'path' in component and 'textRange' in issue


def to_results(issues):
    return [to_result(issue, issues['components']) for issue in issues['issues'] if issue_has_location(issue, issues['components'])]


def create_report(client, scanner_report):
    issues = client.get_issues(scanner_report.project_key)

    artifacts = to_artifacts(issues['components'])
    return {
        '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'SonarCloud',
                    'organization': 'SonarSource',
                    'rules': to_rules(client, issues['rules'])
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
        with open(path, 'r') as file:
            content = file.read()
            self.organization = self._extract_property('organization', content)
            self.project_key = self._extract_property('projectKey', content)
            self.task_id = self._extract_property('ceTaskId', content)
            self.ce_task_url = self._extract_property('ceTaskUrl', content)
            self.dashboard_url = self._extract_property('dashboardUrl', content)

    @staticmethod
    def _extract_property(key, scanner_report):
        match = re.search(rf'{key}=(.*)', scanner_report)
        if match:
            return match.group(1)

        raise Exception(f'Could not find property {key} from scanner report')


def compute_max_retry_count(poll_interval_seconds, timeout_seconds):
    return timeout_seconds // poll_interval_seconds


class QualityGateStatus:
    def __init__(self, obj):
        try:
            self.status = obj['projectStatus']['status']
        except:
            raise QualityCheckError('Could not parse quality gate status from json: {}'.format(json.dumps(obj)))


class CeTask:
    def __init__(self, obj):
        '''
        >>> CeTask({'task': {'status': 'IN_PROGRESS'}}).is_completed()
        False
        '''
        try:
            self.status = obj['task']['status']
            self.completed = self.status not in ('IN_PROGRESS', 'PENDING')
            self.analysis_id = obj['task'].get('analysisId')
        except:
            raise QualityCheckError('Could not parse compute engine task from json: {}'.format(json.dumps(obj)))

    def is_completed(self):
        return self.completed


class SonarCloudClient:
    def __init__(self, sonar_token, scanner_report):
        self.sonar_token = sonar_token
        self.organization = scanner_report.organization
        self.pr = self._extract_pr(scanner_report.dashboard_url)

    @staticmethod
    def _extract_pr(dashboard_url):
        match = re.search(rf'.*pullRequest=(.*)', dashboard_url)
        if match:
            print(match.group(1))
            return match.group(1)

    def _get_response_as_dict(self, url, error_message_prefix):
        req = requests.get(url, auth=HTTPBasicAuth(self.sonar_token, ''))
        if req.status_code != 200:
            try:
                errors_as_dict = req.json()
                errors_summary = '; '.join([e['msg'] for e in errors_as_dict['errors']])
                raise QualityCheckError('{}: {}'.format(error_message_prefix, errors_summary))
            except:
                content = req.content
                raise QualityCheckError('{}: {}'.format(error_message_prefix, content))

        return req.json()

    def get_ce_task(self, url):
        return CeTask(self._get_response_as_dict(url, 'Could not fetch compute engine task'))

    def get_issues(self, project):
        url = f'https://sonarcloud.io/api/issues/search?organization={self.organization}&projects={project}&additionalFields=rules&resolved=false'

        if self.pr is not None:
            print(f'Loading issues from PR #{self.pr}')
            url += f'&pullRequest={self.pr}'
        else:
            print('Loading issues from master')

        return self._get_response_as_dict(url, 'Could not fetch issue list')

    def get_quality_gate_status(self, url):
        return QualityGateStatus(self._get_response_as_dict(url, 'Could not fetch quality gate status'))

    def get_rule(self, rule_key):
        url = f'https://sonarcloud.io/api/rules/search?organization={self.organization}&rule_key={rule_key}'
        return self._get_response_as_dict(url, f'Could not fetch rule {rule_key}')['rules'][0]


def create_ce_task_getter(client, ce_task_url):
    return lambda: client.get_ce_task(ce_task_url)


def wait_for_completed_ce_task(ce_task_getter, max_retry_count, poll_interval_seconds=POLL_INTERVAL_SECONDS):
    for _ in range(1 + max_retry_count):
        ce_task = ce_task_getter()
        if ce_task.is_completed():
            return ce_task

        print('.', end='')

        time.sleep(poll_interval_seconds)

    raise QualityCheckError('Compute engine task did not complete within time')


def get_quality_gate_status_url(ce_task):
    return 'https://sonarcloud.io/api/qualitygates/project_status?analysisId={}'.format(ce_task.analysis_id)


def get_variable(name, required=False, default=None):
    value = os.getenv(name)
    if required and (value is None or not value.strip()):
        raise Exception('{} variable missing.'.format(name))
    return value if value else default


def main():
    sonar_token = get_variable('SONAR_TOKEN', required=True)
    report_path = get_variable('REPORT_PATH', required=True)
    timeout_seconds = get_variable('SONAR_QUALITY_GATE_TIMEOUT', required=False, default=DEFAULT_TIMEOUT_SECONDS)

    scanner_report = ReportTask(report_path)

    client = SonarCloudClient(sonar_token, scanner_report)

    max_retry_count = compute_max_retry_count(POLL_INTERVAL_SECONDS, timeout_seconds)
    ce_task = wait_for_completed_ce_task(create_ce_task_getter(client, scanner_report.ce_task_url), max_retry_count)

    quality_gate_status_url = get_quality_gate_status_url(ce_task)
    quality_gate_status = client.get_quality_gate_status(quality_gate_status_url)

    if quality_gate_status.status == 'OK' or quality_gate_status.status == 'ERROR':
        print(f'QG {quality_gate_status.status}')

        with open('sonarcloud-output.sarif.json', 'w') as output:
            output.write(json.dumps(create_report(client, scanner_report), indent=2))
    else:
        print('QG error')


if __name__ == '__main__':
    main()

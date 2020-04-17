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

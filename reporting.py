"""Versioned scan results and shared, atomic report exporters."""

import csv
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def now():
    return datetime.now(timezone.utc).isoformat()


def json_value(value):
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


def write_csv(path, headers, rows):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('w', newline='', encoding='utf-8') as stream:
        writer = csv.writer(stream)
        writer.writerow(headers)
        for row in rows:
            writer.writerow([
                json.dumps(value, default=json_value, ensure_ascii=False)
                if isinstance(value, (dict, list, tuple)) else value
                for value in row
            ])
    os.replace(temporary, path)


class Report:
    def __init__(self, directory, target, engine, login, options):
        self.directory = Path(directory)
        if self.directory.exists() and any(self.directory.iterdir()):
            raise ValueError(f'Output directory must be empty: {self.directory}')
        self.directory.mkdir(parents=True, exist_ok=True)
        self.data = {
            'schema_version': 1,
            'target': target,
            'engine': engine,
            'original_login': login,
            'started_at': now(),
            'finished_at': None,
            'status': 'running',
            'options': options,
            'checks': [],
            'findings': [],
            'inventory': {'databases': [], 'tables': [], 'columns': []},
        }

    def check(self, name, status, identity, database=None, schema=None,
              object_name=None, evidence=None, error=None):
        item = {
            'name': name, 'status': status, 'database': database,
            'schema': schema, 'object': object_name,
            'original_login': self.data['original_login'],
            'effective_identity': identity, 'evidence': evidence,
            'error': error, 'recorded_at': now(),
        }
        self.data['checks'].append(item)
        return item

    def finding(self, title, category, severity, confidence, identity,
                explanation, evidence, database=None, schema=None,
                object_name=None, rule_ids=None, categories=None):
        item = {
            'id': f"F{len(self.data['findings']) + 1:04d}",
            'title': title, 'category': category,
            'categories': categories or [category],
            'severity': severity, 'confidence': confidence,
            'target': self.data['target'], 'database': database,
            'schema': schema, 'object': object_name,
            'original_login': self.data['original_login'],
            'effective_identity': identity, 'explanation': explanation,
            'evidence': evidence, 'rule_ids': rule_ids or [],
        }
        self.data['findings'].append(item)
        return item

    def save(self):
        destination = self.directory / 'report.json'
        temporary = destination.with_suffix('.json.tmp')
        temporary.write_text(json.dumps(self.data, indent=2, default=json_value,
                                        ensure_ascii=False) + '\n', encoding='utf-8')
        os.replace(temporary, destination)
        markdown = self.directory / 'report.md'
        temporary = markdown.with_suffix('.md.tmp')
        temporary.write_text(self.markdown(), encoding='utf-8')
        os.replace(temporary, markdown)
        headers = ['id', 'title', 'category', 'categories', 'severity', 'confidence', 'target',
                   'database', 'schema', 'object', 'original_login',
                   'effective_identity', 'explanation', 'rule_ids', 'evidence']
        write_csv(self.directory / 'findings.csv', headers,
                  ([item[key] for key in headers] for item in self.data['findings']))

    def finish(self, status):
        self.data['status'] = status
        self.data['finished_at'] = now()
        self.save()

    def summary(self):
        statuses = Counter(check['status'] for check in self.data['checks'])
        counts = ', '.join(f'{count} {status}' for status, count in sorted(statuses.items()))
        severities = Counter(item['severity'] for item in self.data['findings'])
        priorities = ', '.join(f'{severities[level]} {level}' for level in
                               ('critical', 'high', 'medium', 'low', 'info') if severities[level])
        return (f"{len(self.data['findings'])} findings ({priorities or 'none'}); {counts or 'no checks'}; "
                f"scan {self.data['status']}. Reports: {self.directory}")

    def markdown(self):
        def safe(value):
            # Keep database-controlled text from creating report markup.
            text = str(value if value is not None else 'unknown')
            for character in ('\\', '`', '*', '_', '[', ']', '<', '>', '#', '|'):
                text = text.replace(character, '\\' + character)
            return text.replace('\r', ' ').replace('\n', ' ')

        lines = ['# SQLEnum report', '',
                 f"Target: {safe(self.data['target'])} ({safe(self.data['engine'])})",
                 f"Original login: {safe(self.data['original_login'])}",
                 f"Status: {safe(self.data['status'])}", '',
                 '## Summary', '', safe(self.summary()), '', '## Findings', '']
        if not self.data['findings']:
            lines += ['No findings recorded. See check coverage below.', '']
        priorities = ('critical', 'high', 'medium', 'low', 'info')
        for item in sorted(self.data['findings'], key=lambda item: priorities.index(item['severity'])):
            location = '.'.join(str(item[key]) for key in ('database', 'schema', 'object')
                                if item[key] is not None)
            lines += [f"### {item['id']}: {safe(item['title'])}", '',
                      f"- Severity: {item['severity']}; confidence: {item['confidence']}",
                      f"- Categories: {safe(', '.join(item['categories']))}",
                      f"- Location: {safe(location or self.data['target'])}",
                      f"- Effective identity: {safe(item['effective_identity'])}",
                      f"- Rules: {safe(', '.join(item['rule_ids']) or 'built-in check')}",
                      '', safe(item['explanation']), '',
                      'Evidence: ' + safe(json.dumps(item['evidence'], default=json_value,
                                                    ensure_ascii=False)), '']
        lines += ['## Check coverage', '', '| Check | Database / object | Identity | Status | Detail |',
                  '| --- | --- | --- | --- | --- |']
        for item in self.data['checks']:
            location = '.'.join(str(item[key]) for key in ('database', 'schema', 'object')
                                if item[key] is not None)
            detail = item['error'] or json.dumps(item['evidence'], default=json_value,
                                                ensure_ascii=False)
            lines.append(f"| {safe(item['name'])} | {safe(location)} | "
                         f"{safe(item['effective_identity'])} | {item['status']} | {safe(detail)} |")
        return '\n'.join(lines) + '\n'

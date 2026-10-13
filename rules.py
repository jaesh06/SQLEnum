"""Validated JSON rules; all specified match conditions must match."""

import json
import re
from dataclasses import dataclass
from pathlib import Path


CONFIDENCE = {'low': 0, 'medium': 1, 'high': 2}
SEVERITY = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
FIELDS = {'table', 'column', 'datatype'}

DEFAULT_RULES = [
    {'id': 'credentials', 'category': 'credentials', 'severity': 'high',
     'confidence': 'high', 'description': 'Name suggests stored credentials or authentication material.',
     'match': {'name': r'password|passwd|pwd|secret|token|credential|private.?key|password.?hash'}},
    {'id': 'identity', 'category': 'identity', 'severity': 'medium',
     'confidence': 'medium', 'description': 'Name suggests account or identity information.',
     'match': {'name': r'user|admin|login|member|account|ssn|social.*security'}},
    {'id': 'financial', 'category': 'financial', 'severity': 'high',
     'confidence': 'medium', 'description': 'Name suggests financial information.',
     'match': {'name': r'card|credit|cc_|bank|acc_|iban|routing|wallet|payment'}},
    {'id': 'sensitive', 'category': 'sensitive', 'severity': 'medium',
     'confidence': 'low', 'description': 'Name suggests potentially sensitive information.',
     'match': {'name': r'email|phone|addr|dob|birth|private|config|session|vault|salt|shadow'}},
]


@dataclass
class Rule:
    id: str
    category: str
    severity: str
    confidence: str
    description: str
    match: dict
    exclude: dict

    def matches(self, table, column, datatype, columns):
        values = {'table': table, 'column': column, 'datatype': datatype,
                  'name': column if columns else table}
        return (all(pattern.search(values[field]) for field, pattern in self.match.items())
                and not any(pattern.search(values[field])
                            for field, pattern in self.exclude.items()))


def load_rules(path=None, keywords=None, mode='literal'):
    if path:
        try:
            document = json.loads(Path(path).read_text(encoding='utf-8'))
        except (OSError, ValueError) as error:
            raise ValueError(f'Cannot load rules: {error}') from error
        if not isinstance(document, dict) or set(document) != {'rules'}:
            raise ValueError('Rules file must be an object with a "rules" array.')
        definitions = document['rules']
    elif keywords is not None:
        words = [word.strip() for word in keywords.split(',')]
        if not all(words):
            raise ValueError('Filter keywords cannot be empty.')
        definitions = [{
            'id': 'custom-filter', 'category': 'custom', 'severity': 'medium',
            'confidence': 'medium', 'description': 'Name matches the supplied filter.',
            'match': {'name': '|'.join(re.escape(word) if mode == 'literal' else f'(?:{word})'
                                       for word in words)},
        }]
    else:
        definitions = DEFAULT_RULES
    if not isinstance(definitions, list) or not definitions:
        raise ValueError('Rules must be a non-empty array.')
    result, identifiers = [], set()
    for definition in definitions:
        required = {'id', 'category', 'severity', 'confidence', 'description', 'match'}
        if (not isinstance(definition, dict) or not required <= definition.keys()
                or definition.keys() - (required | {'exclude'})):
            raise ValueError('Each rule requires id, category, severity, confidence, description, match; optional exclude.')
        for key in required - {'match'}:
            if not isinstance(definition[key], str) or not definition[key].strip():
                raise ValueError(f'Rule {key} must be a non-empty string.')
        if definition['id'] in identifiers:
            raise ValueError(f"Duplicate rule id: {definition['id']}")
        identifiers.add(definition['id'])
        if definition['severity'] not in SEVERITY or definition['confidence'] not in CONFIDENCE:
            raise ValueError(f"Invalid severity or confidence in rule {definition['id']}")
        compiled = {}
        for kind in ('match', 'exclude'):
            conditions = definition.get(kind, {})
            if (not isinstance(conditions, dict) or conditions.keys() - (FIELDS | {'name'})
                    or (kind == 'match' and not conditions)):
                raise ValueError(f'Invalid {kind} conditions; use name, table, column, datatype.')
            compiled[kind] = {}
            for field, pattern in conditions.items():
                if not isinstance(pattern, str) or not pattern:
                    raise ValueError('Patterns must be non-empty strings.')
                try:
                    compiled[kind][field] = re.compile(pattern, re.IGNORECASE)
                except re.error as error:
                    raise ValueError(f"Invalid regex in rule {definition['id']}: {error}") from error
        result.append(Rule(**{key: definition[key] for key in required - {'match'}}, **compiled))
    return result


def matching_rules(rules, table, columns, column_mode=False, minimum='low'):
    """Yield one object and all its matching rules, avoiding duplicate samples."""
    objects = [(column['name'], [column]) for column in columns] if column_mode else [(table, columns)]
    for name, candidates in objects:
        matches = [rule for rule in rules
                   if CONFIDENCE[rule.confidence] >= CONFIDENCE[minimum]
                   and any(rule.matches(table, column['name'], column['datatype'], column_mode)
                           for column in (candidates or [{'name': '', 'datatype': ''}]))]
        if matches:
            yield name, matches

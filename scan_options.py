"""Serializable scan configuration and case-sensitive shell-glob scope filters."""

from dataclasses import asdict, dataclass, field
from fnmatch import fnmatchcase


CHECKS = ('inventory', 'permissions', 'configuration', 'hashes', 'connections', 'links', 'emails', 'findings')


@dataclass
class ScanOptions:
    checks: list = field(default_factory=lambda: list(CHECKS))
    include_database: list = field(default_factory=list)
    exclude_database: list = field(default_factory=list)
    include_schema: list = field(default_factory=list)
    exclude_schema: list = field(default_factory=list)
    include_table: list = field(default_factory=list)
    exclude_table: list = field(default_factory=list)
    connect_timeout: int = 10
    query_timeout: int = 30
    sample_rows: int = 1
    sample_bytes: int = 4096
    skip_data: bool = False
    columns: bool = False
    min_confidence: str = 'low'

    def allows(self, kind, name, *qualified):
        names = (name,) + qualified
        includes = getattr(self, f'include_{kind}')
        excludes = getattr(self, f'exclude_{kind}')
        return ((not includes or any(fnmatchcase(value, pattern) for value in names for pattern in includes))
                and not any(fnmatchcase(value, pattern) for value in names for pattern in excludes))

    def as_dict(self):
        return asdict(self)

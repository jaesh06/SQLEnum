"""Command-line entry point for scoped SQL enumeration."""

import argparse
import csv
import sys

from rules import CONFIDENCE, load_rules
from scan_options import CHECKS, ScanOptions
from scanner import Scanner


def positive_integer(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError('must be a positive integer')
    return number


def build_parser():
    parser = argparse.ArgumentParser(description='Perform scoped enumeration of MSSQL, MySQL, or PostgreSQL.')
    parser.add_argument('type', choices=['mssql', 'mysql', 'psql'])
    parser.add_argument('-t', '--target', required=True)
    parser.add_argument('-u', '--user', required=True)
    parser.add_argument('-p', '--password')
    parser.add_argument('--domain', default='', help='MSSQL Windows authentication domain.')
    parser.add_argument('-H', '--hash', default='', help='MSSQL NTLM hash (NT or LM:NT). Requires --domain.')
    parser.add_argument('-d', '--database', default='', help='Restrict enumeration to this database; required with -q.')
    parser.add_argument('-P', '--port', type=positive_integer)
    parser.add_argument('-q', '--query', help='Run one query and print CSV to stdout instead of enumerating.')
    parser.add_argument('--skip-data', action='store_true', help='Do not sample interesting tables or columns.')
    parser.add_argument('--columns', action='store_true', help='Report matching columns instead of tables.')
    filters = parser.add_mutually_exclusive_group()
    filters.add_argument('-f', '--filter', help='Comma-separated literal keywords (replaces built-in rules).')
    filters.add_argument('--rules', help='JSON detection rule file (replaces built-in rules).')
    parser.add_argument('--filter-mode', choices=['literal', 'regex'], default='literal',
                        help='Interpret --filter as literal keywords or regexes (default: literal).')
    parser.add_argument('--min-confidence', choices=list(CONFIDENCE), default='low',
                        help='Minimum detection-rule confidence to report.')
    parser.add_argument('--checks', help=f'Comma-separated checks or all. Choices: {", ".join(CHECKS)}.')
    for kind in ('database', 'schema', 'table'):
        for action in ('include', 'exclude'):
            parser.add_argument(f'--{action}-{kind}', action='append', default=[], metavar='GLOB',
                                help=f'{action.capitalize()} {kind} names matching a case-sensitive glob; repeatable.')
    parser.add_argument('--connect-timeout', type=positive_integer, default=10, metavar='SECONDS')
    parser.add_argument('--query-timeout', type=positive_integer, default=30, metavar='SECONDS')
    parser.add_argument('--sample-rows', type=positive_integer, default=1, metavar='N')
    parser.add_argument('--sample-bytes', type=positive_integer, default=4096, metavar='N',
                        help='Maximum total UTF-8 sample value bytes per finding (default: 4096).')
    parser.add_argument('--output-dir', help='Report directory; defaults to a unique directory under results/.')
    return parser


def parse_options(parser, args):
    if args.hash and (args.type != 'mssql' or not args.domain):
        parser.error('--hash requires MSSQL and --domain.')
    if args.password is None and not args.hash:
        parser.error('-p/--password is required unless --hash is used.')
    if args.domain and args.type != 'mssql':
        parser.error('--domain is only supported for MSSQL.')
    if args.query and not args.database:
        parser.error('-d/--database is required with -q/--query.')
    if args.port and args.port > 65535:
        parser.error('--port must be between 1 and 65535.')
    if args.connect_timeout > 31536000:
        parser.error('--connect-timeout must not exceed 31536000 seconds.')
    if args.filter_mode == 'regex' and args.filter is None:
        parser.error('--filter-mode regex requires --filter.')
    if args.checks is None:
        checks = [check for check in CHECKS if check != 'emails' or args.type == 'mssql']
    elif args.checks == 'all':
        checks = list(CHECKS)
    else:
        checks = list(dict.fromkeys(check.strip() for check in args.checks.split(',')))
        if not checks or set(checks) - set(CHECKS):
            parser.error(f'--checks must contain only: {", ".join(CHECKS)}, or all.')
    try:
        rules = load_rules(args.rules, args.filter, args.filter_mode)
    except ValueError as error:
        parser.error(str(error))
    fields = {name: getattr(args, name) for name in ScanOptions.__dataclass_fields__ if name != 'checks'}
    return ScanOptions(checks=checks, **fields), rules


def make_collector(args, options):
    # Load only the selected driver; --help and rule validation need no drivers.
    common = dict(target=args.target, user=args.user, password=args.password, options=options)
    if args.type == 'mssql':
        from collectors.mssql import MSSQLCollector
        return MSSQLCollector(port=args.port or 1433, domain=args.domain, ntlm_hash=args.hash, **common)
    if args.type == 'mysql':
        from collectors.mysql import MySQLCollector
        return MySQLCollector(port=args.port or 3306, **common)
    from collectors.psql import PostgreSQLCollector
    return PostgreSQLCollector(port=args.port or 5432, **common)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    options, rules = parse_options(parser, args)
    try:
        collector = make_collector(args, options)
        if args.query:
            try:
                collector.createConnection(args.database)
                writer = csv.writer(sys.stdout)
                writer.writerows(collector.execute(args.query))
                return 0
            finally:
                collector.close()
        return Scanner(collector, options, rules, args.database, args.output_dir,
                       args.rules or ('custom-filter' if args.filter is not None else 'built-in')).run()
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        print(f'Error: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

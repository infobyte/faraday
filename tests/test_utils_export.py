import csv
from io import StringIO

import pytest

from faraday.server.utils.export import SafeDictWriter, sanitize_csv_value

FORMULA_PAYLOADS = [
    '=1+1',
    '+1',
    '-1+1',
    '@SUM(1)',
    '\t=1',
    '\r=1',
    '\n=1',
    ' =1',
    '　=1',
    '＝1',
    '＋1',
    '－1',
    '＠SUM(1)',
]


@pytest.mark.parametrize('payload', FORMULA_PAYLOADS)
def test_sanitize_csv_value_escapes_formulas(payload):
    assert sanitize_csv_value(payload) == "'" + payload


@pytest.mark.parametrize('value', [
    'plain text', 'a;=1', 'a=1', '', "'=1", '(80/tcp) http', '[1, 2]', 'O\'Reilly',
])
def test_sanitize_csv_value_keeps_safe_strings(value):
    assert sanitize_csv_value(value) == value


@pytest.mark.parametrize('value', [None, True, False, 0, -1, -1.5, 3])
def test_sanitize_csv_value_keeps_non_strings(value):
    result = sanitize_csv_value(value)
    assert result is value


def test_sanitize_csv_value_escapes_stringified_objects():
    class Formula:
        def __str__(self):
            return '=1+1'

    assert sanitize_csv_value(Formula()) == "'=1+1"
    assert sanitize_csv_value(['=1']) == ['=1']


def test_safe_dict_writer_escapes_rows_and_quotes_all():
    buffer = StringIO()
    writer = SafeDictWriter(buffer, fieldnames=['a', 'b', 'c', 'd'])
    writer.writeheader()
    row = {'a': '=1+1', 'b': 'a;=1', 'c': 5, 'd': None}
    writer.writerow(row)

    assert row == {'a': '=1+1', 'b': 'a;=1', 'c': 5, 'd': None}
    assert buffer.getvalue().splitlines() == [
        '"a","b","c","d"',
        '"\'=1+1","a;=1","5",""',
    ]


def test_safe_dict_writer_escapes_headers():
    buffer = StringIO()
    writer = SafeDictWriter(buffer, fieldnames=['=1+1', 'name'])
    writer.writeheader()
    writer.writerows([{'=1+1': '@x', 'name': 'ok'}])

    rows = list(csv.reader(StringIO(buffer.getvalue())))
    assert rows == [["'=1+1", 'name'], ["'@x", 'ok']]

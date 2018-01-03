import csv
import click
from collections import OrderedDict


MAPPED_VULN_SEVERITY = OrderedDict([
    ('critical', 'critical'),
    ('high', 'high'),
    ('med', 'medium'),
    ('low', 'low'),
    ('info', 'informational'),
    ('unclassified', 'unclassified'),
    ('unknown', 'unclassified'),
])


@click.command()
@click.argument('input_csv', type=click.File(mode='r+'))
@click.option('-o', '--output', help="Write to a new file instead of "
              "overwritting the input file", type=click.File(mode='w'))
@click.pass_context
def fix_severities(ctx, input_csv, output):
    """Ensures the severity/exploitation of a vuln templace CSV has
    valid values. If not, it will use the most appropiate value"""
    if output is None:
        if not click.confirm(click.style(
                "WARNING: you didn't specify the --output option, so "
                "the input file will be overwritten. Are you sure you "
                "want to do this?", fg='red', bold=True)):
            ctx.abort()
    reader = csv.DictReader(input_csv)
    rows = [fix_row(row) for row in reader]

    fieldnames = ['cwe', 'name', 'description', 'resolution', 'exploitation',
                  'references']
    if output is None:
        input_csv.seek(0)
        output = input_csv
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)


def fix_row(row):
    old_severity = row.get('exploitation', 'unclassified')
    new_severity = 'unclassified'
    for (key, value) in MAPPED_VULN_SEVERITY.items():
        if key in old_severity.lower():
            new_severity = value
            break
    else:
        if old_severity:
            click.echo(click.style(
                'Unknown severity: "{}" found in vulnerability template named '
                '"{}"'.format(old_severity, row.get('name')),
                fg='yellow'), err=True, color='yellow')
    row['exploitation'] = new_severity
    return row


if __name__ == "__main__":
    fix_severities()

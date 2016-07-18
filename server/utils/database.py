# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import server.database
import server.utils.logger

from sqlalchemy import distinct
from sqlalchemy.sql import func, asc, desc
from server.utils.debug import Timer


class ORDER_DIRECTIONS:
    ASCENDING = 'asc'
    DESCENDING = 'desc'


def paginate(query, page, page_size):
    """
    Limit results from a query based on pagination parameters
    """
    if not (page >= 0 and page_size >=0):
        raise Exception("invalid values for pagination (page: %d, page_size: %d)" % (page, page_size))
    return query.limit(page_size).offset(page * page_size)

def sort_results(query, field_to_col_map, order_field, order_dir, default=None):
    """
    Apply sorting operations over a SQL query
    """
    order_cols = field_to_col_map.get(order_field, None)

    if order_cols and order_dir in (ORDER_DIRECTIONS.ASCENDING, ORDER_DIRECTIONS.DESCENDING):
        # Apply the proper sqlalchemy function for sorting direction over every
        # column declared on field_to_col_map[order_field]
        dir_func = asc if order_dir == ORDER_DIRECTIONS.ASCENDING else desc
        order_cols = map(dir_func, order_cols)
    else:
        # Use default ordering if declared if any parameter didn't met the requirements
        order_cols = [default] if default is not None else None

    return query.order_by(*order_cols) if order_cols else query

def apply_search_filter(query, field_to_col_map, free_text_search=None, field_filter={}):
    """
    Build the filter for a SQL query from a free-text-search term or based on individual
    filters applied to labeled columns declared in field_to_col_map.

    FTS implementation is rudimentary since it applies the same LIKE filter for all
    declared columns in field_to_col_map, where the individual search terms stated
    in field_filter take precedence.
    """
    # Raise an error in case an asked column to filter by is not mapped
    if any(map(lambda attr: attr not in field_to_col_map, field_filter)):
        raise Exception('invalid field to filter')

    sql_filter = None

    # Iterate over every searchable field declared in the mapping
    # to then apply a filter on the query if required
    for attribute in field_to_col_map:
        # Add wildcards to both ends of a search term
        if attribute in field_filter:
            like_str = u'%' + field_filter.get(attribute) + u'%'
        elif free_text_search:
            like_str = u'%' + free_text_search + u'%'
        else:
            continue

        for column in field_to_col_map.get(attribute):
            # Labels are expressed as strings in the mapping,
            # currently we are not supporting searches on this
            # kind of fields since they are usually referred to
            # query built values (like counts)
            if isinstance(column, basestring):
                continue

            # Concatenate multiple search terms
            if sql_filter is None:
                sql_filter = column.like(like_str)
            else:
                sql_filter = sql_filter | column.like(like_str)

    return query if sql_filter is None else query.filter(sql_filter)

def get_count(query, count_col=None):
    """
    Get a query row's count. This implementation performs significantly better
    than messaging a query's count method. 
    """
    if count_col is None:
        count_filter = [func.count()]
    else:
        count_filter = [func.count(distinct(count_col))]
    
    with Timer('query.count'):
        count_q = query.statement.with_only_columns(count_filter).\
                  order_by(None).group_by(None)
        count = query.session.execute(count_q).scalar()

    return count


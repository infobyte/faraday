# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import server.utils.logger

from sqlalchemy import distinct, Boolean
from sqlalchemy.sql import func, asc, desc


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

def apply_search_filter(query, field_to_col_map, free_text_search=None, field_filter={}, strict_filter=[]):
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

    fts_sql_filter = None
    dfs_sql_filter = None

    # Iterate over every searchable field declared in the mapping
    # to then apply a filter on the query if required
    for attribute in field_to_col_map:
        is_direct_filter_search = attribute in field_filter
        is_free_text_search = not is_direct_filter_search and free_text_search

        # Add wildcards to both ends of a search term
        if is_direct_filter_search:
            like_str = u'%' + field_filter.get(attribute) + u'%'
        elif is_free_text_search:
            like_str = u'%' + free_text_search + u'%'
        else:
            continue

        search_term_sql_filter = None
        for column in field_to_col_map.get(attribute):
            # Labels are expressed as strings in the mapping,
            # currently we are not supporting searches on this
            # kind of fields since they are usually referred to
            # query built values (like counts)
            if isinstance(column, basestring):
                continue

            # Prepare a SQL search term according to the columns type.
            # As default we treat every column as an string and therefore
            # we use 'like' to search through them.
            if is_direct_filter_search and isinstance(column.type, Boolean):
                field_search_term = field_filter.get(attribute).lower()
                search_term = prepare_boolean_filter(column, field_search_term)
                # Ignore filter for this field if the values weren't expected
                if search_term is None:
                    continue
            else:
                # Strict filtering can be applied for fields. FTS will
                # ignore this list since its purpose is clearly to
                # match anything it can find.
                if is_direct_filter_search and attribute in strict_filter:
                    search_term = column.is_(field_filter.get(attribute))
                else:
                    search_term = column.like(like_str)

            search_term_sql_filter = concat_or_search_term(search_term_sql_filter, search_term)

        # Concatenate multiple search terms on its proper filter
        if is_direct_filter_search:
            dfs_sql_filter = concat_and_search_term(dfs_sql_filter, search_term_sql_filter)
        elif is_free_text_search:
            fts_sql_filter = concat_or_search_term(fts_sql_filter, search_term_sql_filter)

    sql_filter = concat_and_search_term(fts_sql_filter, dfs_sql_filter)
    return query.filter(sql_filter) if sql_filter is not None else query

def concat_and_search_term(left, right):
    return concat_search_terms(left, right, operator='and')

def concat_or_search_term(left, right):
    return concat_search_terms(left, right, operator='or')

def concat_search_terms(sql_filter_left, sql_filter_right, operator='and'):
    if sql_filter_left is None and sql_filter_right is None:
        return None
    elif sql_filter_left is None:
        return sql_filter_right
    elif sql_filter_right is None:
        return sql_filter_left
    else:
        if operator == 'and':
            return sql_filter_left & sql_filter_right
        elif operator == 'or':
            return sql_filter_left | sql_filter_right
        else:
            return None

def prepare_boolean_filter(column, search_term):
    if search_term in ['true', '1']:
        return column.is_(True)
    elif search_term in ['false', '0']:
        return column.is_(False) | column.is_(None)
    else:
        return None

def get_count(query, count_col=None):
    """
    Get a query row's count. This implementation performs significantly better
    than messaging a query's count method. 
    """
    if count_col is None:
        count_filter = [func.count()]
    else:
        count_filter = [func.count(distinct(count_col))]
    
    count_q = query.statement.with_only_columns(count_filter).\
              order_by(None).group_by(None)
    count = query.session.execute(count_q).scalar()

    return count


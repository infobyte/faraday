/*! showdown-table 17-06-2015 */
/*
 * Basic table support with re-entrant parsing, where cell content
 * can also specify markdown.
 *
 * Tables
 * ======
 *
 * | Col 1   | Col 2                                              |
 * |======== |====================================================|
 * |**bold** | ![Valid XHTML] (http://w3.org/Icons/valid-xhtml10) |
 * | Plain   | Value                                              |
 *
 */

(function () {
  'use strict';

  var table = function (converter) {

    var tables = {}, style = 'text-align:left;', filter;
    tables.th = function (header) {
      if (header.trim() === '') {
        return '';
      }
      var id = header.trim().replace(/ /g, '_').toLowerCase();
      return '<th id="' + id + '" style="' + style + '">' + header + '</th>';
    };
    tables.td = function (cell) {
      return '<td style="' + style + '">' + converter.makeHtml(cell) + '</td>';
    };
    tables.ths = function () {
      var out = '',
          i = 0,
          hs = [].slice.apply(arguments);
      for (i; i < hs.length; i += 1) {
        out += tables.th(hs[i]) + '\n';
      }
      return out;
    };
    tables.tds = function () {
      var out = '', i = 0, ds = [].slice.apply(arguments);
      for (i; i < ds.length; i += 1) {
        out += tables.td(ds[i]) + '\n';
      }
      return out;
    };
    tables.thead = function () {
      var out,
          hs = [].slice.apply(arguments);
      out = '<thead  class="thead-dark">\n';
      out += '<tr>\n';
      out += tables.ths.apply(this, hs);
      out += '</tr>\n';
      out += '</thead>\n';
      return out;
    };
    tables.tr = function () {
      var out,
          cs = [].slice.apply(arguments);
      out = '<tr>\n';
      out += tables.tds.apply(this, cs);
      out += '</tr>\n';
      return out;
    };
    filter = function (text) {
      var i = 0, lines = text.split('\n'), line, hs, out = [];
      for (i; i < lines.length; i += 1) {
        line = lines[i];
        if (line.trim().match(/^[|].*[|]$/)) {
          line = line.trim();
          var tbl = [];
          tbl.push('<table class="table table-sm">');
          hs = line.substring(1, line.length - 1).split('|');
          tbl.push(tables.thead.apply(this, hs));
          line = lines[++i];
          if (!line.trim().match(/^[|][-=|: ]+[|]$/)) {
            line = lines[--i];
          } else {
            line = lines[++i];
            tbl.push('<tbody>');
            while (line.trim().match(/^[|].*[|]$/)) {
              line = line.trim();
              tbl.push(tables.tr.apply(this, line.substring(1, line.length - 1).split('|')));
              line = lines[++i];
            }
            tbl.push('</tbody>');
            tbl.push('</table>');
            out.push(tbl.join('\n'));
            continue;
          }
        }
        out.push(line);
      }
      return out.join('\n');
    };
    return [
      {
        type:   'lang',
        filter: filter
      }
    ];
  };
  if (typeof window !== 'undefined' && window.showdown && window.showdown.extensions) {
    window.showdown.extensions.table = table;
  }
  if (typeof module !== 'undefined') {
    module.exports = table;
  }
}());

//# sourceMappingURL=showdown-table.js.map
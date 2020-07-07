// Faraday Penetration Test IDE
// Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information


angular.module('faradayApp').filter('markdown', function (BASEURL) {
    var evidenceRender = function () {
      // This could be a lot more simple code, but
      // we found a bug on filename with spaces and we need to espape it.
      // take a look to the history of this extension to see the simple version of this code
      var ws_index = window.location.href.split('/').indexOf('ws');
      var workspace = window.location.href.split('/')[ws_index + 1];
      var evidenceExtension = {
        type: 'lang',
        filter: function(text, converter) {
          var regex = /\(evidence\:(\w+)\:(\d+)\:([a-zA-Z0-9\s_\\.\-\(:]+\.\w+)\)/g;
          var matches = text.match(regex);
          var markdown = text;
          var filename;
          for (var evidence_index in matches) {
            filename = escape(matches[evidence_index].split(':')[3].slice(0, -1));
            evidence = matches[evidence_index].replace(regex, '![$1 With Id $2 Evidence ](' + BASEURL + '_api/v2/ws/' + workspace + '/vulns/$2/attachment/' + filename + '/ =500x281)');
            console.log(evidence);
            markdown = markdown.replace(matches[evidence_index], evidence);
          }
          return markdown;
        }
      };
      return [evidenceExtension];
    }
    
    return function (md) {
        var converter = new showdown.Converter({extensions: ['table', evidenceRender]});
        converter.setOption('tables', 'true');
        converter.setOption('tasklists', 'true');
        return converter.makeHtml(md);
    }
});

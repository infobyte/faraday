angular.module('faradayApp')
    // CSV export
    .directive('downloadCsv', function($parse, $click, $blob, $log, $timeout) {
      return {
        compile: function($element, attr) {
          var fn = $parse(attr.downloadCsv);
           
          return function(scope, element, attr) {
             
            element.on('click', function(event) {
              var a_href, content, title, url, _ref;
              _ref = fn(scope), content = _ref.content, title = _ref.title;
               
              if (!(content != null) && !(title != null)) {
                $log.warn("Invalid content or title in download-csv : ", content, title);
                return;
              }
               
              title = $blob.sanitizeCSVName(title);
              url = $blob.csvToURL(content);
               
              element.append("<a download=\"" + title + "\" href=\"" + url + "\"></a>");
              a_href = element.find('a')[0];
               
              $click.on(a_href);
              $timeout(function() {$blob.revoke(url);});
               
              element[0].removeChild(a_href);
            });
          };
        }
      };
    });

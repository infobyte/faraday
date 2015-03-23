// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    // file export
    .directive('fileExporter', function($parse, $click, $blob, $log, $timeout) {
      return {
        compile: function($element, attr) {
          var fn = $parse(attr.fileExporter);
           
          return function(scope, element, attr) {
             
            element.on('click', function(event) {
              var a_href, content, extension, title, type, url, _ref;
              _ref = fn(scope), content = _ref.content, extension = _ref.extension, title = _ref.title, type = _ref.type;
               
              if (!(content != null) && !(extension != null) && !(title != null) && !(type != null)) {
                $log.warn("Invalid content, extension, title or type in file exporter : ", content, extension, title, type);
                return;
              }
               
              title = $blob.sanitizeFileName(title, extension);
              type  = $blob.sanitizeFileType(type);
              url   = $blob.fileToURL(content, type);
               
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

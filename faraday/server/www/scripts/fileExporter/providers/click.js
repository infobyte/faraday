// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('$click', function() {
      return {
        on: function(element) {
          var e = document.createEvent("MouseEvent");
          e.initMouseEvent("click", false, true, window, 0, 0, 0, 0, 0, false, false, false, false, 0, null);
          element.dispatchEvent(e);
        }
      };
    });

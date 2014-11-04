angular.module('faradayApp')
    // CSV export
    .factory('$click', function() {
      return {
        on: function(element) {
          var e = document.createEvent("MouseEvent");
          e.initMouseEvent("click", false, true, window, 0, 0, 0, 0, 0, false, false, false, false, 0, null);
          element.dispatchEvent(e);
        }
      };
    });

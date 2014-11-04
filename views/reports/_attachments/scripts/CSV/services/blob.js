angular.module('faradayApp')
    // CSV export
    .factory('$blob', function() {
      return {
        csvToURL: function(content) {
          var blob;
          blob = new Blob([content], {type: 'text/csv'});
          return (window.URL || window.webkitURL).createObjectURL(blob);
        },
        sanitizeCSVName: function(name) {
          if (/^[A-Za-z0-9]+\.csv$/.test(name)) {
            return name;
          }
          if (/^[A-Za-z0-9]+/.test(name)) {
            return name + ".csv";
          }
          throw new Error("Invalid title fo CSV file : " + name);
        },
        revoke: function(url) {
          return (window.URL || window.webkitURL).revokeObjectURL(url);
        }
      };
    });

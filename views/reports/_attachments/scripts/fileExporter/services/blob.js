angular.module('faradayApp')
    .factory('$blob', function() {
      return {
        fileToURL: function(content, t) {
          var blob;
          blob = new Blob([content], {type: t});
          return (window.URL || window.webkitURL).createObjectURL(blob);
        },
        sanitizeFileName: function(name, extension) {
          var nameRegExp    = new RegExp("^[A-Za-z0-9_-]+$");
          var extRegExp     = new RegExp("^[A-Za-z]+$");
          if(nameRegExp.test(name) && extRegExp.test(extension)) {
            return "Faraday-" + name + "." + extension;
          }
          throw new Error("Invalid title or extension for file: " + name + "." + extension);
        },
        sanitizeFileType: function(type) {
          var patt = new RegExp("^[a-z]+/[a-z+.-]+$");
          if(patt.test(type)) {
            return name;
          }
          throw new Error("Invalid type for file: " + type);
        },
        revoke: function(url) {
          return (window.URL || window.webkitURL).revokeObjectURL(url);
        }
      };
    });

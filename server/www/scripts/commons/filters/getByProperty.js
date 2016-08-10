// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

// returns index of object in collection if found or -1
angular.module('faradayApp')
    .filter('getByProperty', function() {
        return function(propertyName, propertyValue, collection) {
            var len = collection.length;

            for(var i = 0; i < len; i++) {
                if(collection[i][propertyName] == propertyValue) {
                    return i;
                }
            }
            return -1;
        }
    });

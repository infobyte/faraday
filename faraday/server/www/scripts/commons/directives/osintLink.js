// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

/**
 * @see http://docs.angularjs.org/guide/concepts
 * @see http://docs.angularjs.org/api/ng.directive:ngModel.NgModelController
 * @see https://github.com/angular/angular.js/issues/528#issuecomment-7573166
 */

// TODO: Refactor to don't do one request to the server for each host
// TODO: urlencode query

angular.module('faradayApp')
    .directive('osintLink', ['indexFact', function(indexFact){
        return {
            scope: {
                query: '=query',
                osint: '=osint'
            },
            templateUrl: 'scripts/commons/partials/osintLink.html'
        }
    }]);

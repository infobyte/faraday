// Faraday Penetration Test IDE
// Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('uiCommonFact', [function () {

        var uiCommonFact = {};

        uiCommonFact.updateBtnSeverityColor = function (severity, btnSelector, caretSelector) {
            var color = undefined;
            switch (severity) {
                case "unclassified":
                    color = '#999999';
                    break;
                case "info":
                    color = '#2e97bd';
                    break;
                case "low":
                    color = '#a1ce31';
                    break;
                case "med":
                    color = '#dfbf35';
                    break;
                case "high":
                    color = '#df3936';
                    break;
                case "critical":
                    color = '#932ebe';
                    break;
            }

            angular.element(btnSelector).css('background-color', color);
            angular.element(caretSelector).css('background-color', color);
        };


        return uiCommonFact;

    }]);

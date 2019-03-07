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


        uiCommonFact.updateBtnStatusColor = function (status, btnSelector, caretSelector) {
            var color = undefined;
            switch (status) {
                case "opened":
                    color = '#DB3130';
                    break;
                case "closed":
                    color = '#97F72C';
                    break;
                case "re-opened":
                    color = '#DBB72F';
                    break;
                case "risk-accepted":
                    color = '#288DB4';
                    break;
                default:
                    color = '#aaaaaa';
                    break;
            }

            angular.element(btnSelector).css('background-color', color);
            angular.element(caretSelector).css('background-color', color);
        };


        return uiCommonFact;

    }]);

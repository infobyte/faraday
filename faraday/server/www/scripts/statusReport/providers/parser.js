// Faraday Penetration Test IDE
// Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('parserFact', ['commonsFact', function (commonsFact) {
        var parserFact = {};

        parserFact.evaluateExpression = function (expression) {
            var outputJson = {
                "filters": []
            };

            try {
                var filter = peg$parse(expression);
                outputJson["filters"].push(filter);
                return escape(JSON.stringify(outputJson));
            } catch (e) {
                commonsFact.showMessage(e.message || e);
                return null;
            }
        };

        var testParenthesisPairs = function (string) {
            var length = string.length,
                i = 0,
                count = 0,
                openChar = arguments[1] || "(",
                closeChar = arguments[2] || ")";

            while (i < length) {
                char = string.charAt(i);

                if (char === openChar) {
                    count += 1;
                } else if (char === closeChar) {
                    count -= 1;
                }

                if (count < 0) {
                    return false;
                }

                i += 1;
            }

            return count === 0;
        };


        parserFact.isValid = function (expression) {
            var reQuotes = /^(?:[^"\\]|\\.|"(?:\\.|[^"\\])*")*$/; // checks if the expressions contains unclosed quotes
            var reDoubleSpaces = /\s\s/; // checks if the expressions contains double spaces
            return testParenthesisPairs(expression) && expression.match(reQuotes) !== null && expression.match(reDoubleSpaces) === null;
        };


        return parserFact;

    }]);

// Faraday Penetration Test IDE
// Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('parserFact', [function () {
        var parserFact = {};

        parserFact.evaluateExpression = function (expression) {
            var outputJson = {
                "filters": []
            };

            if (expression !== '') {
                var tokens = expression.split(" ");
                tokens = clearTokens(tokens);
                console.log("Tokens: " + tokens);

                var operatorStack = [];
                var termStack = [];

                for (var i = 0; i < tokens.length; i++) {
                    console.log("Analyzing Token: " + tokens[i]);
                    if (tokens[i] === '(') {
                        operatorStack.push(tokens[i]);
                    } else if (tokens[i] === ')') {
                        while (operatorStack[operatorStack.length - 1] !== '(')
                            termStack.push(execute(operatorStack.pop(), termStack.pop(), termStack.pop()));
                        operatorStack.pop();
                    }
                    else if (tokens[i] === "and" || tokens[i] === "or") {
                        while (operatorStack.length !== 0 && hasPrecedence(tokens[i], operatorStack[operatorStack.length - 1]))
                            termStack.push(execute(operatorStack.pop(), termStack.pop(), termStack.pop()));

                        // Push current token to 'ops'.
                        operatorStack.push(tokens[i]);
                    }
                    else if (tokens[i] === "not") {
                        operatorStack.push(tokens[i]);
                        var termCount = 0;
                        while (tokens[i] !== ')') {
                            if (isTerm(tokens[i])) {
                                termStack.push(tokens[i]);
                                termCount++;
                            }
                            i++
                        }
                        if (termCount === 2) {
                            termStack.push(execute(operatorStack.pop(), termStack.pop(), termStack.pop()));
                        } else {
                            termStack.push(execute(operatorStack.pop(), termStack.pop(), undefined));
                        }


                    }
                    else {
                        if (tokens.length === 1) {
                            tokens[i] = processTerm(tokens[i], null);
                        }

                        termStack.push(tokens[i]);
                    }
                }

                // Entire expression has been parsed at this point, apply remaining
                // ops to remaining values
                while (operatorStack.length !== 0)
                    termStack.push(execute(operatorStack.pop(), termStack.pop(), termStack.pop()));

                // Top of 'values' contains result, return it
                var output = termStack.pop();
                outputJson["filters"].push(output);
            }

            return JSON.stringify(outputJson);
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

        var clearTokens = function (tokens) {
            var signsStack = [];
            var cleanedTokens = [];
            for (var i = 0; i < tokens.length; i++) {
                if (tokens[i] !== "") {
                    if (tokens[i].indexOf('(') === 0) {
                        cleanedTokens.push('(');
                        if (tokens[i].indexOf(':"') !== -1) {
                            while (tokens[i] !== undefined && tokens[i].indexOf('"') !== tokens[i].length - 1) {
                                signsStack.push(tokens[i]);
                                i++;
                            }
                            if (tokens[i] !== undefined) signsStack.push(tokens[i]);
                            cleanedTokens.push(signsStack.join(" "));
                            signsStack = [];
                        } else {
                            cleanedTokens.push(spliceSlice(tokens[i], 0, 1));
                        }
                    } else if (tokens[i].indexOf(')') === tokens[i].length - 1 && (tokens[i].substr(0, 3) !== "not")) {
                        cleanedTokens.push(spliceSlice(tokens[i], tokens[i].length - 1, 1));
                        cleanedTokens.push(')');
                    } else if (tokens[i].substr(0, 3) === "not") {
                        cleanedTokens.push("not");
                        cleanedTokens.push(tokens[i].substr(3, 1));
                        var tempTkn = tokens[i].substr(4, tokens[i].length - 4);

                        if (tempTkn.indexOf(':"') !== -1) {
                            signsStack.push(tempTkn);
                            i++;
                            while (tokens[i] !== undefined && tokens[i].indexOf('")') !== tokens[i].length - 2) {
                                signsStack.push(tokens[i]);
                                i++;
                            }
                            signsStack.push(spliceSlice(tokens[i], tokens[i].length - 1, 1));
                            cleanedTokens.push(signsStack.join(" "));
                            cleanedTokens.push(')');
                            signsStack = [];
                        } else if (tempTkn.indexOf(')') === tempTkn.length - 1) {
                            cleanedTokens.push(spliceSlice(tempTkn, tempTkn.length - 1, 1));
                            cleanedTokens.push(')');
                        } else {
                            cleanedTokens.push(tempTkn);
                        }
                    } else if (tokens[i].indexOf(':"') !== -1) {
                        while (tokens[i] !== undefined && tokens[i].indexOf('"') !== tokens[i].length - 1) {
                            signsStack.push(tokens[i]);
                            i++;
                        }
                        if (tokens[i] !== undefined) signsStack.push(tokens[i]);
                        cleanedTokens.push(signsStack.join(" "));
                        signsStack = [];
                    }
                    else {
                        cleanedTokens.push(tokens[i]);
                    }
                }
            }
            return cleanedTokens;
        };

        var hasPrecedence = function (op1, op2) {
            if (op2 === '(' || op2 === ')')
                return false;
            return !((op1 === 'and' || op1 === 'or') && (op2 === 'not'));
        };

        var isTerm = function (token) {
            return token.indexOf("and") === -1 && token.indexOf("or") === -1 && token.indexOf("not") === -1
                && token.indexOf("(") === -1 && token.indexOf(")") === -1 && token !== '';
        };

        var execute = function (operator, term1, term2) {
            console.log("EXECUTE -->  " + "OP: " + operator + " TERM1: " + term1 + " TERM2: " + term2);
            var item = {};
            term1 = processTerm(term1, operator);
            term2 = processTerm(term2, operator);

            if (term2 === undefined || term2 === null) {
                if (operator === 'not') {
                    return term1
                } else {
                    item[operator] = [term1];
                }
            } else {
                if (operator === 'not') {
                    item['and'] = [term1, term2];
                } else {
                    item[operator] = [term1, term2];
                }


            }
            console.log(JSON.stringify(item));
            return item;
        };

        var processTerm = function (term, operator) {
            var res = {
                'name': '',
                'op': '',
                'val': ''
            };

            try {
                var array = term.split(':');
                if (array.length === 2) {
                    var name = array[0];
                    var val = array[1].replace(/"/g, '');
                    var op = 'like';
                    if (operator !== 'not') {
                        if (name === 'confirmed' || name === 'accountability' || name === 'availability' || name === 'confidentiality' || name === 'integrity') {
                            op = '==';
                            if (name !== 'confirmed')
                                name = 'impact_' + name;
                        }
                    } else {
                        if (name === 'accountability' || name === 'availability' || name === 'confidentiality' || name === 'integrity') {
                            name = 'impact_' + name;
                        }
                        op = '!='
                    }

                    res.name = name;
                    res.op = op;
                    res.val = val;
                    if (op === 'like') {
                        res.val = '%' + val + '%';
                    }
                    return res
                }
                else {
                    return term
                }
            } catch (err) {
                console.log(err.message);
                return term
            }
        };

        var spliceSlice = function (str, index, count, add) {
            // We cannot pass negative indexes directly to the 2nd slicing operation.
            if (index < 0) {
                index = str.length + index;
                if (index < 0) {
                    index = 0;
                }
            }
            return str.slice(0, index) + (add || "") + str.slice(index + count);
        };

        return parserFact;

    }]);

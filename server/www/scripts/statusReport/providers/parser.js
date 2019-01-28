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
                var tokens = clearTokens(expression);
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

        var clearTokens = function (expression) {
            var tokens = [];
            var isOpenQuotes = false;
            var isOpenParenthesis = false;
            var canAddToken = false;
            var withSpace = false;

            for (var i = 0; i < expression.length; i++) {
                switch (expression[i]) {
                    case ' ':
                        withSpace = true;
                        if (isOpenQuotes === true)
                            tokens[tokens.length - 1] += expression[i];
                        break;

                    case '(':
                        withSpace = false;
                        tokens.push(expression[i]);
                        isOpenParenthesis = true;
                        canAddToken = true;
                        break;

                    case ')':
                        withSpace = false;
                        tokens.push(expression[i]);
                        isOpenParenthesis = false;
                        canAddToken = true;
                        break;
                    case '"':
                        withSpace = false;
                        isOpenQuotes = !isOpenQuotes;
                        break;

                    default:
                        if (expression.substr(i, 3) === 'not' && expression.charAt(i - 1) === ' '
                            && expression.charAt(i + 3) === ' ' && !isOpenQuotes) {
                            tokens.push('not');
                            i = i + 2;
                            canAddToken = true;
                        }

                        else if (expression.substr(i, 3) === 'and' && expression.charAt(i - 1) === ' '
                            && expression.charAt(i + 3) === ' ' && !isOpenQuotes) {
                            tokens.push('and');
                            canAddToken = true;
                            i = i + 2;
                        }

                        else if (expression.substr(i, 2) === 'or' && expression.charAt(i - 1) === ' '
                            && expression.charAt(i + 2) === ' ' && !isOpenQuotes) {
                            tokens.push('or');
                            canAddToken = true;
                            i++;
                        } else {
                            if ((!isOpenQuotes && (withSpace || tokens.length === 0)) || canAddToken) {
                                tokens.push(expression[i]);
                                canAddToken = false;
                            }
                            else tokens[tokens.length - 1] += expression[i];
                        }
                        withSpace = false;
                        break;
                }
            }

            return tokens;
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


        var processName = function (name) {
            var processedName = "";
            switch (name) {
                case 'accountability':
                case 'availability':
                case 'confidentiality':
                case 'integrity':
                    processedName = 'impact_' + name;
                    break;
                case 'service':
                    processedName = 'service__name';
                    break;
                case 'easeofresolution':
                case 'ease_of_resolution':
                    processedName = 'ease_of_resolution';
                    break;
                case 'web':
                    processedName = 'type';
                    break;
                case 'creator':
                    processedName = 'creator_command_tool';
                    break;
                case 'policy_violations':
                case 'policyviolations':
                    processedName = 'policy_violations__name';
                    break;
                case 'host_os':
                    processedName = 'host__os';
                    break;
                case 'refs':
                case 'ref':
                    processedName = 'references__name';
                    break;
                case 'evidence':
                    processedName = 'evidence__filename';
                    break;
                case 'params':
                case 'parameters':
                    processedName = 'parameters';
                    break;
                case 'pname':
                case 'parameter_name':
                    processedName = 'parameter_name';
                    break;
                case 'query':
                case 'query_string':
                    processedName = 'query_string';
                    break;
                case 'tags':
                case 'tag':
                    processedName = 'tags__name';
                    break;
                default:
                    processedName = name;
                    break;
            }

            return processedName;
        };

        var processOperator = function (name, operator) {
            var processedOperator = "";
            switch (name) {
                case 'confirmed':
                case 'impact_accountability':
                case 'impact_availability':
                case 'impact_confidentiality':
                case 'impact_integrity':
                case 'ease_of_resolution':
                case 'type':
                case 'id':
                    processedOperator = operator !== 'not' ? '==' : '!=';
                    break;
                case 'severity':
                case 'target':
                    processedOperator = operator !== 'not' ? 'eq' : '!=';
                    break;
                case 'service__name':
                case 'host__os':
                    processedOperator = operator !== 'not' ? 'has' : '!=';
                    break;
                case 'policy_violations__name':
                case 'references__name':
                case 'evidence__filename':
                case 'tags__name':
                    processedOperator = operator !== 'not' ? 'any' : '!=';
                    break;
                default:
                    processedOperator = operator !== 'not' ? 'ilike' : '!=';
                    break;
            }

            return processedOperator;
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
                    var op;

                    name = processName(name);
                    op = processOperator(name, operator);

                    if (val === 'info') val = 'informational';
                    if (val === 'med') val = 'medium';

                    res.name = name;
                    res.op = op;
                    res.val = val;
                    if (op === 'ilike') {
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

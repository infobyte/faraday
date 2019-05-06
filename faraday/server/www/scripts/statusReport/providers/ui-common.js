// Faraday Penetration Test IDE
// Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('uiCommonFact', ['BASEURL', function (BASEURL) {

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


        uiCommonFact.populate = function (template, vuln) {
            for (var key in vuln) {
                if (key !== "refs" && key !== "policyviolations" && template.hasOwnProperty(key) && vuln.hasOwnProperty(key)) {
                    vuln[key] = template[key];
                }
            }
            // convert refs to an array of objects
            var refs = [];
            template.refs.forEach(function (ref) {
                refs.push(ref);
            });
            vuln.refs = refs;

            // convert policyviolations to an array of objects
            var policyviolations = [];
            template.policyviolations.forEach(function (policyviolation) {
                policyviolations.push(policyviolation);
            });
            vuln.policyviolations = policyviolations;
        };


        uiCommonFact.newReference = function (newRef, vuln) {
            if (newRef !== "") {
                // we need to check if the ref already exists
                if (vuln.refs.filter(function (ref) {
                        return ref === newRef
                    }).length === 0) {
                    vuln.refs.push(newRef);
                    newRef = "";
                }
            }
        };


        uiCommonFact.newPolicyViolation = function (newPolicyViolation, vuln) {
            if (newPolicyViolation !== "") {
                // we need to check if the policy violation already exists
                if (vuln.policyviolations.filter(function (policyviolation) {
                        return policyviolation.value === newPolicyViolation
                    }).length === 0) {
                    vuln.policyviolations.push(newPolicyViolation);
                    newPolicyViolation = "";
                }
            }
        };


        uiCommonFact.removeEvidence = function (name, vuln) {
             delete vuln._attachments[name];
        };

        uiCommonFact.openEvidence = function (name, vuln, ws) {
            var currentEvidence = vuln._attachments[name];
            if (!currentEvidence.newfile)
                window.open(BASEURL + '_api/v2/ws/' + ws + '/vulns/' + vuln._id + '/attachment/' + encodeURIComponent(name), '_blank');
        };


        return uiCommonFact;

    }]);

// Faraday Penetration Test IDE
// Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .directive('checkCustomType', function () {
        return {
            restrict: 'A',
            link: function (scope, elm, attrs, ctrl) {
                elm.on('keydown', function (event) {
                    if (attrs.checkCustomType === 'int') {
                        if (event.shiftKey) {
                            event.preventDefault();
                            return false;
                        }
                        //console.log(event.which);
                        if ([8, 13, 27, 37, 38, 39, 40].indexOf(event.which) > -1) {
                            // backspace, enter, escape, arrows
                            return true;
                        } else if (event.which >= 48 && event.which <= 57) {
                            // numbers 0 to 9
                            return true;
                        } else if (event.which >= 96 && event.which <= 105) {
                            // numpad number
                            return true;
                        }
                        else {
                            event.preventDefault();
                            return false;
                        }
                    }else {
                        return true;
                    }

                });
            }
        }
    });
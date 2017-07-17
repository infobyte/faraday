// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

// removes line breaks \n from text

angular.module('faradayApp')
    .filter('removeLinebreaks',function(){
        return function(text){
            return text?text.replace(/\n/g, ' '):'';
    }});
// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('hostsFact', ['BASEURL', function(BASEURL) {
        var hostsFact = {};

        hostsFact.get = function(ws) {
            hosts_url = BASEURL + ws + "/_design/hosts/_view/hosts";
            var hosts = [];
            //gets hosts json from couch
            $.getJSON(hosts_url, function(data) {
                $.each(data.rows, function(n, obj) {
                   hosts[obj.id] = {
                       "categories": obj.value.categories,
                       "default_gateway": obj.value.default_gateway,
                       "description": obj.value.description,
                       "metadata": obj.value.metadata,
                       "name": obj.value.name,
                       "os": obj.value.os,
                       "owned": obj.value.owned,
                       "owner": obj.value.owner
                    };
                }); 
            });
            return hosts;
        }
        return hostsFact;
    }]);

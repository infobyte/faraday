angular.module('faradayApp')
    .factory('hostsFact', ['BASEURL', function(BASEURL) {
        var hostsFact = {};

        hostsFact.get = function(ws) {
            hosts_url = BASEURL + ws + "/_design/hosts/_view/hosts";
            var hosts = [];
            //gets hosts json from couch
            $.getJSON(hosts_url, function(data) {
                $.each(data.rows, function(n, obj) {
                   hosts[obj.id] = {"name": obj.value.name, "os": obj.value.os, "owned": obj.value.owned};
                }); 
            });
            return hosts;
        }
        return hostsFact;
    }]);

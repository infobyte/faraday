angular.module('faradayApp')
    .factory('targetFact', ['BASEURL', '$http', function(BASEURL, $http) {
        var targetFact = {};

        targetFact.getTarget = function(ws, need_hosts) {
            if(need_hosts){
                var hosts = [];
                var url = BASEURL + ws + "/_design/hosts/_view/hosts";
                $.getJSON(url, function(data) {
                    $.each(data.rows, function(n, obj) {
                        obj.value._id = obj.id;
                        hosts.push(obj.value);
                    });
                });
                return hosts;
            }else{
                var services = [];
                var url = BASEURL + ws + "/_design/services/_view/byhost";
                $.getJSON(url, function(data) {
                    $.each(data.rows, function(n, obj) {
                        obj.value._id = obj.id;
                        services.push(obj.value);
                    });
                });
                return services;
            }
        };

        return targetFact;
    }]);

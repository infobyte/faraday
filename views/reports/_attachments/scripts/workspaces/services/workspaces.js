angular.module('faradayApp')
    .factory('workspacesFact', ['BASEURL', '$http', function(BASEURL, $http) {
        var workspacesFact = {};

        workspacesFact.get = function(callback) {

            var url = BASEURL + "_all_dbs";
            $http.get(url).success(function(d, s, h, c) {
                var wss = d.filter(function(ws) {
                    return ws.search(/^_/) < 0 && ws.search("reports") < 0;
                });
                callback(wss);
            });
        };

        workspacesFact.exists = function(workspace_name) {
            var request = {
                method: 'HEAD',
                url: BASEURL + workspace_name
            };
            var exists = false;
            return $http(request).success(function(data) {
                exists = true;
            });
            return exists;
        };

        return workspacesFact;
    }]);

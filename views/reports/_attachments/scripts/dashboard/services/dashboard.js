angular.module('faradayApp')
    .factory('dashboardSrv', ['BASEURL', '$q', '$http', function(BASEURL, $q, $http) {
        var dashboardSrv = {};

        dashboardSrv._getView = function(url) {
            var deferred = $q.defer();

            $http.get(url).then(function(response){
                res = response.data.rows;
                deferred.resolve(res);
            }, function(){
                deferred.reject();
            });

            return deferred.promise;
        };

        dashboardSrv.getHostsByServicesCount = function(ws, id) {
            var url = BASEURL + "/" + ws + "/_design/hosts/_view/byservicecount?group=true";
            if (id != undefined){
                url += "&key=\"" + id + "\"";
            }
            return dashboardSrv._getView(url);
        };

        dashboardSrv.getServicesCount = function(ws) {
            var url = BASEURL + "/" + ws + "/_design/hosts/_view/byservices?group=true";
            return dashboardSrv._getView(url);
        };

        dashboardSrv.getVulnerabilitiesCount = function(ws) {
            var url = BASEURL + "/" + ws + "/_design/hosts/_view/vulns?group=true";
            return dashboardSrv._getView(url);
        };

        dashboardSrv.getObjectsCount = function(ws) {
            var url = BASEURL + "/" + ws + "/_design/hosts/_view/summarized?group=true";
            return dashboardSrv._getView(url);
        };

        dashboardSrv.getCommands = function(ws) {
            var deferred = $q.defer();
            var url = BASEURL + "/" + ws + "/_design/commands/_view/list";
            dashboardSrv._getView(url).then(function(res){
                var tmp = [];
                res.forEach(function(cmd){
                    var _cmd = cmd.value;
                    _cmd["command"] = cmd.key;
                    tmp.push(_cmd);
                });
                deferred.resolve(tmp);
            }, function(){
                deferred.reject();
            });
            return deferred.promise;
        };

        dashboardSrv.getHosts = function(ws) {
            var deferred = $q.defer();
            var url = BASEURL + "/" + ws + "/_design/hosts/_view/hosts";
            dashboardSrv._getView(url).then(function(res){
                var tmp = [];
                res.forEach(function(host){
                    var _host = host.value;
                    _host["id"] = host.key;
                    tmp.push(_host);
                });
                deferred.resolve(tmp);
            }, function(){
                deferred.reject();
            });
            return deferred.promise;
        };

        dashboardSrv.getServicesByHost = function(ws, host_id) {
            var deferred = $q.defer();
            var url = BASEURL + "/" + ws + "/_design/services/_view/byhost?key=\"" + host_id + "\"";
            dashboardSrv._getView(url).then(function(res){
                var tmp = [];
                res.forEach(function(service){
                    var _service = service.value;
                    _service["id"] = service.id;
                    _service["port"] = _service.ports[0];
                    tmp.push(_service);
                });
                deferred.resolve(tmp);
            }, function(){
                deferred.reject();
            });
            return deferred.promise;
        }

        dashboardSrv.getName = function(ws, id){
            var deferred = $q.defer();
            url = BASEURL + "/" + ws + "/" + id;

            $http.get(url).then(function(response){
                res = response.data.name;
                deferred.resolve(res);
            }, function(){
                deferred.reject();
            });

            return deferred.promise;
        }

        return dashboardSrv;
    }]);
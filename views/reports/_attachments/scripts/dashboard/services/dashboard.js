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

        dashboardSrv.getHost = function(ws, host_id) {
            var deferred = $q.defer();
            var url = BASEURL + "/" + ws + "/" + host_id;
            $http.get(url).then(function(res){
                deferred.resolve(res.data);
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

        dashboardSrv.getHostsByServicesName = function(ws, srv_name) {
            var deferred = $q.defer();
            var url = BASEURL + "/" + ws + "/_design/services/_view/byname?key=\"" + srv_name + "\"";
            dashboardSrv._getView(url).then(function(res){
                var dict = {};
                var tmp = [];
                res.forEach(function(srv){
                    tmp.push(dashboardSrv.getHost(ws, srv.value.hid));
                });
                $q.all(tmp).then(function(hosts){
                    var res = [];
                    hosts.sort(function(a, b){
                        if(a.name < b.name) return -1;
                        if(a.name > b.name) return 1;
                        return 0;
                    });
                    for (var i = 0; i < hosts.length - 1; i++){
                        if (res.length == 0 || hosts[i].name != res[res.length - 1].name) {
                            res.push(hosts[i]);
                        }
                    }
                    deferred.resolve(res);
                });
            }, function(){
                deferred.reject();
            });
            return deferred.promise;
        };

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
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

        dashboardSrv.getHostsByServicesCount = function(ws) {
            var url = BASEURL + "/" + ws + "/_design/hosts/_view/byservicecount?group=true";
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

        dashboardSrv.getHostname = function(id){
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
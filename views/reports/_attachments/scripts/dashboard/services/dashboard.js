angular.module('faradayApp')
    .factory('dashboardSrv', ['BASEURL', '$q', '$http', function(BASEURL, $q, $http) {
        var dashboardSrv = {};

        dashboardSrv.getHostsByServicesCount = function(ws) {
            var deferred = $q.defer();
            url = BASEURL + "/" + ws + "/_design/hosts/_view/byservicecount?group=true";

            $http.get(url).then(function(response){
                res = response.data.rows;
                deferred.resolve(res);
            }, function(){
                deferred.reject();
            });

            return deferred.promise;
        };

        return dashboardSrv;
    }]);
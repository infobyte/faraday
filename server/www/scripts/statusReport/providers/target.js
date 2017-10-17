// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('targetFact', ['BASEURL', '$q', 'hostsManager', 'servicesManager', function(BASEURL, $q, hostsManager, servicesManager) {
        var targetFact = {};

        targetFact.getTargets = function(workspace) {
            var deferred = $q.defer();
            var res = [];
            var hosts_dict = {};
            hostsManager.getHosts(workspace).then(function(resp) {
                resp.hosts.forEach(function(host) {
                    host.hostnames = [];
                    host.services = [];
                    hosts_dict[host._id] = host;
                    res.push(host);
                });

                servicesManager.getServices(workspace).then(function(services) {
                    services.forEach(function(service) {
                        host_id = service.host_id
                        if (hosts_dict.hasOwnProperty(host_id)) {
                            hosts_dict[host_id].services.push(service);
                        }
                    });
                }, function(err) {deferred.reject(err)});

                deferred.resolve(res);

            }, function(err) {deferred.reject(err)});

            return deferred.promise;
        };

        return targetFact;
    }]);

// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('dashboardSrv', ['BASEURL', 'SEVERITIES', '$cookies', '$q', '$http', function(BASEURL, SEVERITIES, $cookies, $q, $http) {
        var dashboardSrv = {};

        dashboardSrv._getView = function(url) {
            var deferred = $q.defer();

            $http.get(url).then(function(response) {
                res = response.data.rows;
                deferred.resolve(res);
            }, function() {
                deferred.reject();
            });

            return deferred.promise;
        };

        dashboardSrv._areConfirmed = $cookies.get('confirmed') === 'true';

        dashboardSrv.setConfirmed = function(val) {
            dashboardSrv._areConfirmed = val;
            $cookies.put('confirmed', val);
        };

        dashboardSrv.vulnPrices = {
            "critical": "5000",
            "high": "3000",
            "med": "1000",
            "low": "500",
            "info": "0",
            "unclassified": "0"
        };

        dashboardSrv.vulnColors = [
            "#932EBE",  // critical
            "#DF3936",  // high
            "#DFBF35",  // med
            "#A1CE31",  // low
            "#428BCA",  // info
            "#999999"   // unclassified
        ];

        dashboardSrv.getHostsByServicesCount = function(ws, id) {
            var url = BASEURL + "/" + ws + "/_design/hosts/_view/byservicecount?group=true";
            if (id != undefined){
                url += "&key=\"" + id + "\"";
            }
            return dashboardSrv._getView(url);
        };

        dashboardSrv.getTopHosts = function(ws, colors) {
            var deferred = $q.defer();

            dashboardSrv.getHostsByServicesCount(ws)
                .then(function(servicesCount) {
                    if(servicesCount.length > 2) {
                        var hosts = [],
                        tmp = {key:[], colors:[], value:[]};

                        if(colors == undefined) {
                            colors = ["rgb(57, 59, 121)", "rgb(82, 84, 163)", "rgb(107, 110, 207)"];
                        }

                        servicesCount.sort(function(a, b) {
                            return b.value-a.value;
                        });

                        tmp.options = {
                            showScale : false,
                            maintainAspectRatio: false
                        };

                        servicesCount = servicesCount.slice(0, 3);

                        servicesCount.forEach(function(host) {
                            hosts.push(dashboardSrv.getHost(ws, host.key));
                        });

                        $q.all(hosts)
                            .then(function(res) {
                                var hs = {};

                                res.forEach(function(host) {
                                    hs[host._id] = host.name;
                                });

                                servicesCount.forEach(function(srv) {
                                    tmp.colors.push(colors.shift());
                                    tmp.value.push(srv.value);
                                    tmp.key.push(hs[srv.key]);
                                });
                                deferred.resolve(tmp);
                            }, function() {
                                deferred.reject("Unable to get Top Hosts");
                            });
                    }
                }, function() {
                    deferred.reject("Unable to get Services count for Top Hosts");
                });

            return deferred.promise;
        };

        dashboardSrv.getServicesCount = function(ws) {
            var deferred = $q.defer(),
            url = BASEURL + "/" + ws + "/_design/hosts/_view/byservices?group=true";

            dashboardSrv._getView(url)
                .then(function(res) {
                    res.sort(function(a, b) {
                        return b.value - a.value;
                    });

                    deferred.resolve(res);
                }, function() {
                    deferred.reject("Unable to get Services Count");
                });

            return deferred.promise;
        };

        dashboardSrv.getTopServices = function(ws, colors) {
            var deferred = $q.defer();

            dashboardSrv.getServicesCount(ws)
                .then(function(res) {
                    if(res.length > 4) {
                        var tmp = [];

                        if(colors == undefined) {
                            colors = ["#FA5882", "#FF0040", "#B40431", "#610B21", "#2A0A1B"];
                        }

                        res.slice(0, 5).forEach(function(srv) {
                            srv.color = colors.shift();
                            tmp.push(srv);
                        });
                        deferred.resolve(tmp);
                    }
                }, function() {
                    deferred.reject("Unable to get Top Services");
                });

            return deferred.promise;
        };

        dashboardSrv.getVulnsWorth = function(ws) {
            var deferred = $q.defer();

            dashboardSrv.getVulnerabilitiesCount(ws)
                .then(function(vulns) {
                    var vs = [];

                    SEVERITIES.forEach(function(severity, ind) {
                        vs.push({
                            "amount": dashboardSrv.vulnPrices[severity] * vulns[severity],
                            "color": dashboardSrv.vulnColors[ind],
                            "key": severity,
                            "value": vulns[severity]
                        });
                    });

                    deferred.resolve(vs);
                });
            return deferred.promise;
        };

        dashboardSrv.getVulnerabilitiesCount = function(ws) {
            var deferred = $q.defer(),
            url = BASEURL + "/" + ws + "/_design/vulns/_view/byseverity?group=true";

            dashboardSrv._getView(url)
                .then(function(vulns) {
                    var vs = [];

                    vulns.forEach(function(vuln) {
                        vs[vuln.key] = vuln.value;
                    });

                    deferred.resolve(vs);
                }, function() {
                    deferred.reject("Unable to get Vulnerabilities count");
                });

            return deferred.promise;
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
            dashboardSrv._getView(url)
                .then(function(res) {
                    var tmp = [];
                    res.forEach(function(host) {
                        var _host = host.value;
                        _host["id"] = host.key;
                        tmp.push(_host);
                    });
                    deferred.resolve(tmp);
                }, function() {
                    deferred.reject();
                });
            return deferred.promise;
        };

        dashboardSrv.getHost = function(ws, host_id) {
            var deferred = $q.defer();
            var url = BASEURL + "/" + ws + "/" + host_id;
            $http.get(url)
                .then(function(res) {
                    deferred.resolve(res.data);
                }, function() {
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
                    _service["port"] = _service.ports;
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
            dashboardSrv._getView(url).then(function(res) {
                var dict = {};
                var tmp = [];
                res.forEach(function(srv) {
                    tmp.push(dashboardSrv.getHost(ws, srv.value.hid));
                });
                $q.all(tmp).then(function(hosts) {
                    var res = [];
                    hosts.sort(function(a, b){
                        if(a.name < b.name) return -1;
                        if(a.name > b.name) return 1;
                        return 0;
                    });
                    for (var i = 0; i < hosts.length; i++){
                        if (res.length == 0 || hosts[i].name != res[res.length - 1].name) {
                            res.push(hosts[i]);
                        }
                    }
                    deferred.resolve(res);
                });
            }, function() {
                deferred.reject();
            });
            return deferred.promise;
        };

        dashboardSrv.getName = function(ws, id) {
            var deferred = $q.defer();
            url = BASEURL + "/" + ws + "/" + id;

            $http.get(url).then(function(response){
                res = response.data.name;
                deferred.resolve(res);
            }, function(){
                deferred.reject();
            });

            return deferred.promise;
        };


        dashboardSrv.accumulate = function(_array, key, value, accum) {
            _array.forEach(function(obj) {
                if(obj.key == key) {
                    if(obj[accum] === undefined) obj[accum] = 0;
                    obj[accum] += value;
                }
            });
        };

        return dashboardSrv;
    }]);

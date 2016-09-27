// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('dashboardSrv', ['BASEURL', 'SEVERITIES', '$cookies', '$q', '$http', '$interval', 'hostsManager',
        function(BASEURL, SEVERITIES, $cookies, $q, $http, $interval, hostsManager) {
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

        dashboardSrv.props = {};
        dashboardSrv.setConfirmedFromCookie = function() {
            dashboardSrv.props["confirmed"] = ($cookies.get('confirmed') == undefined) ? false : JSON.parse($cookies.get('confirmed'));
        }

        dashboardSrv.setConfirmed = function(val) {
            if(val == undefined) {
                val = ($cookies.get('confirmed') == undefined) ? false : !JSON.parse($cookies.get('confirmed'));
            }

            dashboardSrv.props["confirmed"] = val;
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

        dashboardSrv.getTopHosts = function(ws, colors) {
            var deferred = $q.defer();

            hostsManager.getHosts(ws, 0, 3, null, "services", "desc")
                .then(function(res) {
                    var hosts = res.hosts;
                    if(hosts.length == 3) {
                        var tmp = {key:[], colors:[], value:[]};

                        if(colors == undefined) {
                            colors = ["rgb(57, 59, 121)", "rgb(82, 84, 163)", "rgb(107, 110, 207)"];
                        }

                        tmp.options = {
                            showScale : false,
                            maintainAspectRatio: false
                        };

                        hosts.forEach(function(host) {
                            tmp.colors.push(colors.shift());
                            tmp.value.push(host.services);
                            tmp.key.push(host.name);
                        });

                        deferred.resolve(tmp);
                    } else {
                        deferred.reject("Not enough hosts");
                    }
                }, function() {
                    deferred.reject("Unable to get Services count for Top Hosts");
                });

            return deferred.promise;
        };

        dashboardSrv.getServicesCount = function(ws) {
            var deferred = $q.defer(),
            url = BASEURL + "_api/ws/" + ws + "/services/count?group_by=name";

            $http.get(url)
                .then(function(res) {
                    var tmp =[];
                    res.data.groups.sort(function(a, b) {
                        return b.count - a.count;
                    });
                    deferred.resolve(res.data.groups);
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
                        var amount = 0,
                        value = 0;

                        if(vulns[severity] != undefined) {
                            amount = dashboardSrv.vulnPrices[severity] * vulns[severity];
                            value = vulns[severity];
                        }

                        vs.push({
                            "amount": amount,
                            "color": dashboardSrv.vulnColors[ind],
                            "key": severity,
                            "value": value
                        });
                    });

                    deferred.resolve(vs);
                });
            return deferred.promise;
        };

        dashboardSrv.getVulnerabilitiesCount = function(ws) {
            var deferred = $q.defer(),
            url = BASEURL + "_api/ws/" + ws + "/vulns/count?group_by=severity";

            if(dashboardSrv.props['confirmed']) {
                url += "&confirmed=true";
            }

            $http.get(url)
                .then(function(res) {
                    var vs = {};
                    res.data.groups.forEach(function(vuln) {
                        vs[vuln.severity] = vuln.count;
                    });

                    deferred.resolve(vs);
                }, function() {
                    deferred.reject("Unable to get Vulnerabilities count");
                });

            return deferred.promise;
        };

        dashboardSrv.getObjectsCount = function(ws) {
            var deferred = $q.defer(),
            url = BASEURL + "_api/ws/" + ws + "/summary";

            if(dashboardSrv.props['confirmed']) {
                url += "?confirmed=true";
            }

            $http.get(url)
                .then(function(res) {
                    delete res.data.stats["interfaces"];
                    deferred.resolve(res.data.stats);
                }, function() {
                    deferred.reject("Unable to get Objects count");
                });

            return deferred.promise;
        };

        dashboardSrv.getCommands = function(ws) {
            var deferred = $q.defer();
            var url = BASEURL + "/" + ws + "/_design/commands/_view/list";

            dashboardSrv._getView(url)
                .then(function(res) {
                    var tmp = [];
                    res.forEach(function(cmd) {
                        var _cmd = cmd.value;
                        _cmd["command"] = cmd.key;
                        _cmd.user = _cmd.user || "unknown";
                        _cmd.hostname = _cmd.hostname || "unknown";
                        _cmd.ip = _cmd.ip || "0.0.0.0";
                        if(_cmd.duration == "0" || _cmd.duration == "") {
                            _cmd.duration = "In progress";
                        } else if(_cmd.duration != undefined) {
                            _cmd.duration = _cmd.duration.toFixed(2) + "s";
                        }
                        _cmd.date = _cmd.startdate * 1000;
                        tmp.push(_cmd);
                    });

                    deferred.resolve(tmp);
                }, function() {
                    deferred.reject();
                });

            return deferred.promise;
        };

        dashboardSrv.getHosts = function(ws) {
            var deferred = $q.defer();
            var url = BASEURL + "_api/ws/" + ws + "/hosts";
            $http.get(url)
                .then(function(res) {
                    var tmp = [];
                    res.data.rows.forEach(function(host) {
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
            hostsManager.getHosts(ws, null, null, {"service": srv_name}, "name", "desc")
                .then(function(res) {
                    deferred.resolve(res.hosts);
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

        var timer = undefined;

        dashboardSrv.startTimer = function() {
            timer = $interval(function(){
                dashboardSrv.updateData();
            }, 60000)
        }
        dashboardSrv._callbacks = [];

        dashboardSrv.registerCallback = function(callback) {
            dashboardSrv._callbacks.push(callback);
        }

        dashboardSrv.stopTimer = function() {
            dashboardSrv._callbacks = [];
            if (angular.isDefined(timer)) {
                $interval.cancel(timer);
                timer = undefined;
            }
        }

        dashboardSrv.updateData = function() {
            for (var i = 0; i < dashboardSrv._callbacks.length; i++) {
                var callback = dashboardSrv._callbacks[i];
                callback();
            }
        }

        return dashboardSrv;
    }]);

// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('hostsManager', ['BASEURL', '$http', '$q', 'ServerAPI', 'Host', 'commonsFact', function(BASEURL, $http, $q, ServerAPI, Host, commonsFact) {
        var hostsManager = {};

        hostsManager._objects = {};

        hostsManager._get = function(id, data) {
            var host = this._objects[id];

            if(host) {
                host.set(data);
            } else {
                host = new Host(data);
                this._objects[id] = host;
            }

            return host;
        };

        hostsManager._search = function(id) {
            return this._objects[id];
        };

        hostsManager._load = function(id, ws, deferred) {
            var self = this;
            ServerAPI.getHosts(ws, {couchid: id}).then(
                function(response){
                    if (response.data.rows.length === 1) {
                        var host = self._get(response.data.rows[0].id, response.data.rows[0].value);
                        deferred.resolve(host);
                    } else {
                        deferred.reject();
                    }
                }, function(){
                    deferred.reject();
                });
        };

        hostsManager.getHost = function(id, ws, force_reload) {
            var deferred = $q.defer(),
            host = this._search(id);
            force_reload = force_reload || false;

            if((host) && (!force_reload)) {
                deferred.resolve(host);
            } else {
                this._load(id, ws, deferred);
            }

            return deferred.promise;
        };

        hostsManager.getHosts = function(ws, page, page_size, filter, sort, sort_direction) {
            var deferred = $q.defer();

            options = {page: page, page_size: page_size, sort:sort, sort_dir: sort_direction}
            for( var property in filter ) {
                if (filter.hasOwnProperty(property)) {
                    options[property] = filter[property];
                }
            };
            ServerAPI.getHosts(ws, options)
                .then(function(response) {
                    var result = { hosts: [], total: 0 };
                    response.data.rows.forEach(function(host_data) {
                        host = new Host(host_data.value);
                        result.hosts.push(host);
                    });
                    result.total = response.data.total_rows;
                    deferred.resolve(result);
                }, function(response) {
                    deferred.reject();
                });

            return deferred.promise;
        };

        hostsManager.deleteHost = function(id, ws) {
            var deferred = $q.defer();
            var self = this;
            this.getHost(id, ws)
                .then(function(host) {
                    host.delete(ws)
                        .then(function() {
                            delete self._objects[id];
                            deferred.resolve();
                        })
                        .catch(function() {
                            // host couldn't be deleted
                            deferred.reject("Error deleting host");
                        });
                })
                .catch(function() {
                    // host doesn't exist
                    deferred.reject("Host doesn't exist");
                });
            return deferred.promise;
        };

        hostsManager.createHost = function(hostData, interfaceData, ws) {
            var deferred = $q.defer();
            var self = this;

            this.getHosts(ws)
                .then(function(hosts) {
                    var host = new Host(hostData);
                    self.getHost(host._id, ws)
                        .then(function() {
                            deferred.reject("Host already exists");
                        })
                        .catch(function() {
                            // host doesn't exist, good to go
                            host.save(ws, interfaceData)
                                .then(function() {
                                    host = self.getHost(host._id, ws);
                                    deferred.resolve(host);
                                })
                                .catch(function() {
                                    deferred.reject("Error: host couldn't be saved");
                                })
                        });
                })
                .catch(function() {
                    deferred.reject("Error creating host");
                });

            return deferred.promise;
        };

        hostsManager.updateHost = function(host, hostData, interfaceData, ws) {
            var deferred = $q.defer(),
            self = this;

            this.getHost(host._id, ws)
                .then(function(resp) {
                    resp.update(hostData, interfaceData, ws)
                        .then(function() {
                            // reload the host to update _rev
                            host = self._load(host._id, ws, deferred);
                            deferred.resolve(host);
                        })
                        .catch(function() {
                            deferred.reject("Error updating host");
                        });
                })
                .catch(function() {
                    // host doesn't exist
                    deferred.reject("Host doesn't exist");
                });

            return deferred.promise;
        };

        hostsManager.getAllInterfaces = function(ws) {
            var deferred = $q.defer(),
            self = this;
            ServerAPI.getInterfaces(ws) 
                .then(function(ints) {
                    var interfaces = [];
                    ints.data.interfaces.forEach(function(interf) {
                        interfaces.push(interf.value);
                    });

                    deferred.resolve(interfaces);
                }, function() {
                    deferred.reject("Unable to retrieve Interfaces");
                });

            return deferred.promise;
        };

        var get_count = function(ws, object) {
            var deferred = $q.defer();
            ServerAPI.getWorkspaceSummary(ws).then(
                function(summary) {
                    deferred.resolve(summary[object])
                }, function() {
                    deferred.reject("Unable to get vulnerability count")
                }
            )
            return deferred.promise;
        };


        hostsManager.getAllVulnsCount = function(ws) {
            return this.get_count(ws, 'total_vulns');
        };

        hostsManager.getAllServicesCount = function(ws) {
            return this.get_count(ws, 'services');
        };

        // XXX: THIS STILL USES VIEWS
        hostsManager.getInterfaces = function(ws, id) {
            var deferred = $q.defer(),
            self = this;

            var url = BASEURL + ws + '/_design/interfaces/_view/interfaces?key=\"' + id + '\"';

            $http.get(url)
                .success(function(interfaces) {
                    deferred.resolve(interfaces.rows);
                })
                .error(function() {
                    deferred.reject("Unable to retrieve Interfaces for Host " + id);
                });

            return deferred.promise;
        };

        return hostsManager;
    }]);

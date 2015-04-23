// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('hostsManager', ['BASEURL', '$http', '$q', 'Host', function(BASEURL, $http, $q, Host) {
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
        }

        hostsManager._search = function(id) {
            return this._objects[id];
        }

        hostsManager._load = function(id, ws, deferred) {
            var self = this;
            $http.get(BASEURL + '/' + ws + '/' + id)
                .success(function(data){
                    var host = self._get(data._id, data);
                    deferred.resolve(host);
                })
                .error(function(){
                    deferred.reject();
                });
        }

        hostsManager.getHost = function(id, ws, force_reload) {
            var deferred = $q.defer();
            var host = this._search(id);
            force_reload = force_reload || false;
            if((host) && (!force_reload)) {
                deferred.resolve(host);
            } else {
                this._load(id, ws, deferred);
            }
            return deferred.promise;
        }

        // async method - this is the one to use from now on!
        hostsManager.getHosts = function(ws) {
            var deferred = $q.defer();
            var self = this;
            $http.get(BASEURL + '/' + ws + '/_design/hosts/_view/hosts')
                .success(function(hostsArray){
                    var hosts = [];
                    hostsArray.rows.forEach(function(hostData){
                        var host = self._get(hostData.value._id, hostData.value);
                        hosts.push(host);
                    });
                    deferred.resolve(hosts);
                })
                .error(function(){
                    deferred.reject();
                })
            return deferred.promise;
        }

        // sync method - still used in statusReportFact
        hostsManager.get = function(ws) {
            hosts_url = BASEURL + ws + "/_design/hosts/_view/hosts";
            var hosts = [];
            //gets hosts json from couch
            $.getJSON(hosts_url, function(data) {
                $.each(data.rows, function(n, obj) {
                   hosts[obj.id] = {
                       "categories": obj.value.categories,
                       "default_gateway": obj.value.default_gateway,
                       "description": obj.value.description,
                       "metadata": obj.value.metadata,
                       "name": obj.value.name,
                       "os": obj.value.os,
                       "owned": obj.value.owned,
                       "owner": obj.value.owner
                    };
                }); 
            });
            return hosts;
        }

        hostsManager.deleteHost = function(id, ws) {
            var deferred = $q.defer();
            var self = this;
            this.getHost(id, ws).then(function(host) {
                host.delete(ws).success(function() {
                    delete self._objects[id];
                    deferred.resolve();
                }).error(function(){
                    // host couldn't be deleted
                    deferred.reject("Error deleting host");
                });
            }, function(){
                // host doesn't exist
                deferred.reject("Host doesn't exist");
            });
            return deferred.promise;
        }

        hostsManager.createHost = function(hostData, ws) {
            var deferred = $q.defer();
            var self = this;

            this.getHosts(ws).then(function(hosts) {
                var host = new Host(hostData);
                self.getHost(host._id, ws).then(function() {
                    deferred.reject("Host already exists");
                }, function() {
                    // host doesn't exist, good to go
                    host.save(ws).then(function(){
                        host = self.getHost(host._id, ws);
                        deferred.resolve(host);
                    }, function(){
                        // host couldn't be saved
                        deferred.reject("Error: host couldn't be saved");
                    })
                });
            });
            
            return deferred.promise;
        }

        hostsManager.updateHost = function(host, hostData, ws) {
            var deferred = $q.defer();
            var self = this;
            this.getHost(host._id, ws).then(function(resp) {
                resp.update(hostData, ws).then(function() {
                    // we need to reload the host in order
                    // to update _rev
                    host = self.getHost(host._id, ws, true);
                    deferred.resolve(host);
                })
            }, function(){
                // host doesn't exist
                deferred.reject("Host doesn't exist");
            });
            return deferred.promise;
        }

        return hostsManager;
    }]);

// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('servicesManager', ['BASEURL', '$http', '$q', 'Service', 'ServerAPI', 
        function(BASEURL, $http, $q, Service, ServerAPI) {
        var servicesManager = {};

        servicesManager._objects = {};
        servicesManager._get = function(id, data) {
            var service = this._objects[id];

            if(service) {
                service.set(data);
            } else {
                service = new Service(data);
                this._objects[id] = service;
            }

            return service;
        }

        servicesManager._search = function(id) {
            return this._objects[id];
        }

        servicesManager._load = function(id, ws, deferred) {
            var self = this;
            ServerAPI.getServices(ws, {'couchid': id}).
                then(function(response) {
                    if (response.data.services.length == 1) {
                        var service_data = response.data.services[0].value;
                        var service_id = service_data._id;
                        var service = self._get(service_id, service_data);
                        deferred.resolve(service);
                    } else {
                        deferred.reject("More than one object found by ID");
                    }
                }, function(error) {
                    deferred.reject(error); 
                })
        };

        servicesManager.getService = function(id, ws, force_reload) {
            var deferred = $q.defer();
            var service = this._search(id);
            force_reload = force_reload || false;
            if((service) && (!force_reload)) {
                deferred.resolve(service);
            } else {
                this._load(id, ws, deferred);
            }
            return deferred.promise;
        }

        // async method - this is the one to use from now on!
        servicesManager.getServices = function(ws) {
            var deferred = $q.defer();
            var self = this;
            this._objects = {};

            ServerAPI.getServices(ws)
                .then(function(servicesArray) {
                    var services = [];
                    servicesArray.data.services.forEach(function(serviceData) {
                        var service = self._get(serviceData.value._id, serviceData.value);
                        services.push(service);
                    });
                    deferred.resolve(services);
                }, function(){
                    deferred.reject();
                })
            return deferred.promise;
        }

        // XXX: this still uses couch 
        // host_id is the couch host_id, but the server allows grouping
        // by server ID D: D: D: D: 
        servicesManager.getServicesByHost = function(ws, host_id) {
            var deferred = $q.defer();
            var url = BASEURL + "/" + ws + "/_design/services/_view/byhost?key=\"" + host_id + "\"";
            $http.get(url).then(function(res){
                var promises = [];
                res.data.rows.forEach(function(service){
                    promises.push(servicesManager.getService(service.id, ws, true));
                });
                $q.all(promises).then(function(services) {
                    deferred.resolve(services);
                });
            }, function(){
                deferred.reject();
            });
            return deferred.promise;
        }

        servicesManager.deleteServices = function(id, ws) {
            var deferred = $q.defer();
            var self = this;
            this.getService(id, ws).then(function(service) {
                service.delete(ws).then(function() {
                    delete self._objects[id];
                    deferred.resolve();
                }, function(){
                    // host couldn't be deleted
                    deferred.reject("Error deleting service");
                });
            }, function(){
                // host doesn't exist
                deferred.reject("Service doesn't exist");
            });
            return deferred.promise;
        }

        servicesManager.getServiceVulnCount = function(ws, services) {
            var deferred = $q.defer();
            var promises =  [];
            services.forEach(function(service) {
                promises.push(ServerAPI.getServices(ws, {'couchid': service._id}));
            });

            $q.all(promises).then(function(services){
                var result = {};
                services.forEach(function(service) {
                    var service_data = service.data.services[0];
                    result[service_data.id] = service_data.vulns;
                });
                deferred.resolve(result);
            }, function(){
                deferred.reject([]);
            });
            return deferred.promise;
        }

        servicesManager.createService = function(serviceData, ws) {
            var deferred = $q.defer();
            var self = this;

            this.getServices(ws).then(function(services) {
                var service = new Service(serviceData);
                self.getService(service._id, ws).then(function(resp) {
                    deferred.reject("Service already exists");
                }, function() {
                    // host doesn't exist, good to go
                    service.save(ws).then(function(){
                        service = self.getService(service._id, ws);
                        deferred.resolve(service);
                    }, function(){
                        // host couldn't be saved
                        deferred.reject("Error: host couldn't be saved");
                    })
                });
            });

            return deferred.promise;
        }

        servicesManager.updateService = function(service, data, ws) {
            var deferred = $q.defer();
            var self = this;
            this.getService(service._id, ws).then(function(resp) {
                resp.update(data, ws).then(function() {
                    // we need to reload the service in order
                    // to update _rev
                    service = self._load(service._id, ws, deferred);
                    deferred.resolve(service);
                })
            }, function(){
                // service doesn't exist
                deferred.reject("Service doesn't exist");
            });
            return deferred.promise;
        }

        return servicesManager;
    }]);

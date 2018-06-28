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

        servicesManager._load = function(id, ws) {
            var self = this;
            var deferred = $q.defer();
            ServerAPI.getService(ws, id).
                then(function(response) {

                    deferred.resolve(new Service(response.data));

                }, function(error) {
                    deferred.reject(error); 
                });
            return deferred.promise;
        };

        servicesManager.getService = function(id, ws, force_reload) {
            var deferred = $q.defer();
            var service = this._search(id);
            force_reload = force_reload || false;
            if((service) && (!force_reload)) {
                deferred.resolve(service);
            } else {
                return this._load(id, ws);
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

        servicesManager.deleteServices = function(service, ws) {
            var deferred = $q.defer();
            var self = this;
            var service = self._get(service.id, service);
            service.delete(ws).then(function() {
                delete self._objects[service.id];
                deferred.resolve();
            }, function(){
                // host couldn't be deleted
                deferred.reject("Error deleting service");
            });

            return deferred.promise;
        }

        servicesManager.createService = function(serviceData, ws) {
            var deferred = $q.defer();
            var self = this;
            var service = new Service(serviceData);
            service.save(ws).then(function(saved_service){
                deferred.resolve(saved_service.data);
            }, function(response){
                deferred.reject(response);
            })

            return deferred.promise;
        }

        servicesManager.updateService = function(service, data, ws) {
            var deferred = $q.defer();
            var self = this;
            service.update(data, ws).then(function() {
                deferred.resolve();
            }, function(response) {
                deferred.reject(response);
            });
            return deferred.promise;
        }

        return servicesManager;
    }]);

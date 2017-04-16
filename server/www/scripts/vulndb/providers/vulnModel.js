// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp').
    factory('VulnModel', ['BASEURL', 'configSrv', '$http', '$q',
        function(BASEURL, configSrv, $http, $q) {
            function VulnModel(data) {
                this._id = "";
                this._rev = "";
                this.exploitation = "";
                this.references = [];
                this.name = "";
                this.resolution = "";
                this.cwe = "";
                this.desc_summary = "";
                this.description = "";
                this.formated_tags = "";
                this.tags = [];

                if (data) {
                    if(data.name === undefined || data.name === "") {
                        throw new Error("Unable to create a Vulnerability Model whithout a name");
                    }
                    this.set(data)
                }
            };

            VulnModel.prototype = {

                public_properties: ['exploitation', 'references', 'name', 'resolution', 'cwe', 'desc_summary', 'description', 'tags'],

                set: function(data) {
                    var self = this;

                    if(data._id != undefined) {
                        self._id = data._id;
                        if(data._rev !== undefined) self._rev = data._rev;
                    }

                    self.public_properties.forEach(function(property) {
                        if(data[property] !== undefined) {
                            self[property] = data[property];
                        };
                    });

                    if (data.tags) {
                        this.formated_tags = data.tags.join();
                    }
                },

                remove: function() {
                    var deferred = $q.defer();
                    var self = this;

                    configSrv.promise.
                        then(function() {
                            var url = BASEURL + configSrv.vulnModelsDB + "/" + self._id + "?rev=" + self._rev;

                            $http.delete(url).
                                then(function(resp) {
                                    deferred.resolve(resp);
                                }, function(data, status, headers, config) {
                                    deferred.reject("Unable to delete Vuln Model from DB. " + status)
                                });
                        }, function(reason) {
                            deferred.reject(reason);
                        });

                    return deferred.promise;
                },

                update: function(data) {
                    var deferred = $q.defer();
                    var self = this;

                    configSrv.promise.
                        then(function() {
                            var url = BASEURL + configSrv.vulnModelsDB + "/" + self._id;

                            $http.put(url, data).
                                then(function(res) {
                                    self.set(res.data);
                                    self._rev = res.data.rev;
                                    deferred.resolve(self);
                                }, function(res) {
                                    deferred.reject("Unable to update the Vuln Model. " + res.data.reason);
                                });
                        }, function(reason) {
                            deferred.reject(reason);
                        });
                    return deferred.promise;
                },

                save : function() {
                    var self = this;
                    var deferred = $q.defer();

                    delete this._id;
                    delete this._rev;

                    configSrv.promise.
                        then(function() {
                            var url = BASEURL + configSrv.vulnModelsDB;

                            $http.post(url, self).
                                then(function(data) {
                                    self._id = data.id;
                                    self._rev = data.rev;
                                    deferred.resolve(self);
                                }, function(res) {
                                    deferred.reject("Unable to save the Vuln Model. " + res.data.reason)
                                });
                        }, function(reason) {
                            deferred.reject(reason);
                        });

                    return deferred.promise;
                }
            };

            return VulnModel;
        }]);



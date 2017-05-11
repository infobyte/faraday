// Faraday Penetration Test IDE
// Copyright (C) 2017  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

"use strict";

angular.module('faradayApp')
    .factory('credential', ['ServerAPI', '$q', 
    function(ServerAPI, $q) {

        // All credentials need this properties minimum for build object.
        var _credentialFields = {
            '_id': 'string',
            'name': 'string',
            'username': 'string',
            'password': 'string',
            'type': 'string',
        };

        // Only this properties will be saved to server.
        var _credentialFieldsSaveToServer = {
            '_id': 'string',
            '_rev': 'string',
            'name': 'string',
            'username': 'string',
            'metadata': 'string',
            'password': 'string',
            'type': 'string',
        };

        var Credential;
        Credential = function(data, parent){
            if(data) {
                this.set(data, parent);
            }
        };

        Credential.prototype = {
            // Build object.
            set: function(data, parent) {

                data.type = 'Cred';
                if(data.metadata === undefined)
                    data.metadata = '';
                if(data._id === undefined && parent)
                    data['_id'] = _generateID(parent, data.name, data.username, data.password);

                _checkFieldsOk(data);
                angular.extend(this, data);
            },

            // Find object in server and build that.
            load: function(ws, id){
                
                var deferred = $q.defer();
                var self = this;
                
                ServerAPI.getObj(ws, id).then(function(response){
                    angular.extend(self, response.data);
                    deferred.resolve();
                });
                
                return deferred.promise;
            },

            // Delete object object in server.
            delete: function(ws) {
                return ServerAPI.deleteCredential(ws, this._id, this._rev);
            },

            // Update object in server.
            update: function(ws) {
                var self = this;
                self.metadata = updateMetadata(self.metadata);
                
                return ServerAPI.updateCredential(ws, buildObjectServer(self))
                .then(function(credentialData) {
                    self._rev = credentialData.rev;
                });
            },

            // Create object in server.
            create: function(ws) {
                var self = this;
                self.metadata = generateCreateMetadata();
                
                return ServerAPI.createCredential(ws, buildObjectServer(self)).
                    then(function(credential_data) {
                        self._rev = credential_data.rev;
                    });
            },

            getParentName: function(ws){
                
                var deferred = $q.defer();
                
                var result = this._id.split('.');
                var hostIdToSearch = undefined;
                var serviceIdToSearch = undefined;

                //Parent is Host
                if (result.length === 2){
                    hostIdToSearch = result[0];

                    ServerAPI.getObj(ws, hostIdToSearch).then(function(response){
                        deferred.resolve(response.data.name);
                    });
                }

                //Parent is Service
                else if (result.length === 4){
                    hostIdToSearch = result[0];
                    serviceIdToSearch = result.slice(0, result.length - 1).join('.');

                     ServerAPI.getObj(ws, hostIdToSearch).then(function(responseHost){
                         ServerAPI.getObj(ws, serviceIdToSearch).then(function(responseService){
                            deferred.resolve(responseHost.data.name + '/' + responseService.data.name);
                         });
                    });
                }

                return deferred.promise;
            }
        };

    var _generateID = function(parent, name, username, password){
        var id = parent + '.' + CryptoJS.SHA1([name, username, password].join('._.')).toString();
        return id;
    };

    // Check object to construct have all fields and also, type of they are OK.
    // All fields in _credentialFields should are in object.
    var _checkFieldsOk = function(credential){

        Object.keys(_credentialFields).forEach(function(key, index) {
            // Credential dont have property or type of property in credential dont same.
            if(!credential.hasOwnProperty(key) || typeof(credential[key]) !== _credentialFields[key] || credential[key] === '')
                throw 'Credential-Invalid fields: Invalid fields in credential creation: ' + key;
        });
    };

    // Build a credential object with only properties specified in _credentialFieldsSaveToServer (properties to save in server).
    var buildObjectServer =  function(credential){
        
        var serverObject = {};
        Object.keys(_credentialFieldsSaveToServer).forEach(function(key, index) {
             if(credential.hasOwnProperty(key))
                serverObject[key] = credential[key];
        });
        return serverObject;
    };

    var generateCreateMetadata = function() {

        return {
                'update_time': new Date().getTime(),
                'update_user': '',
                'update_action': 0,
                'creator': 'UI Web',
                'create_time': new Date().getTime(),
                'update_controller_action': '',
                'owner': ''
        };
    };

    var updateMetadata = function(metadata) {
        metadata['update_time'] =  new Date().getTime();
        return metadata;
    };

    return Credential;
}]);

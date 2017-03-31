// Faraday Penetration Test IDE
// Copyright (C) 2017  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

"use strict";

angular.module('faradayApp')
    .factory('credential', ['ServerAPI',
    function(ServerAPI) {

        // All credentials need this properties minimum.
        var _credentialFields = {
            '_id': 'string',
            'name': 'string',
            'username': 'string',
            'password': 'string',
            'type': 'string',
            'parent': 'string'
        };

         var _credentialFieldsSaveToServer = {
            '_id': 'string',
            '_rev': 'string',
            'name': 'string',
            'username': 'string',
            'metadata': 'string',
            'password': 'string',
            'type': 'string',
        };

        Credential = function(data){
            if(data) {
                this.set(data);
            }
        };

        Credential.prototype = {
            set: function(data) {

                data.type = 'Cred';
                if(data.metadata !== undefined)
                    data.metadata = '';
                if(data._id === undefined)
                    data['_id'] = _generateID(data.parent, data.name, data.username, data.password);
                
                _checkFieldsOk(data);
                angular.extend(this, data);
            },

            delete: function(ws) {
                return ServerAPI.deleteCredential(ws, this._id, this._rev);
            },

            update: function(ws, data) {
                var self = this;
                self.metadata = updateMetadata(self.metadata);
                
                return ServerAPI.updateCredential(ws, buildObjectServer(self))
                .then(function(credentialData) {
                    self._rev = credentialData.rev;
                });
            },

            create: function(ws) {
                var self = this;
                self.metadata = generateCreateMetadata();
                
                return ServerAPI.createCredential(ws, buildObjectServer(self)).
                    then(function(credential_data) {
                        self._rev = credential_data.rev;
                    });
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
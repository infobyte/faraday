angular.module('faradayApp')
    .factory('attachmentsFact', ['BASEURL', '$http', '$q', function(BASEURL, $http, $q) {
        var attachmentsFact = {};

        // receives an array of File objects
        // returns an array of promises
        attachmentsFact.loadAttachments = function(files) {
            var deferred = $q.defer(),
            promises = [];
            files.forEach(function(file) {
                promises.push(attachmentsFact.loadAttachment(file));
            });
            $q.all(promises).then(function(attachments) {
                deferred.resolve(attachments);
            });

            return deferred.promise;
        };

        // receives a File object
        // returns a promise
        attachmentsFact.loadAttachment = function(file) {
            var deferred = $q.defer(),
            filename = encodeURIComponent(file.name),
            filetype = file.type.replace("/", "\/"),
            fileReader = new FileReader();
            fileReader.readAsDataURL(file);
            fileReader.onloadend = function (readerEvent) {
                result = readerEvent.target.result;
                result = result.slice(result.indexOf(',')+1);
                deferred.resolve({"filename": filename, "value": {"content_type": filetype, "data": result}});
            };

            return deferred.promise;
        };

        // receives an object containing attachments (such as the one CouchDB returns)
        // returns an array containing the attachments object including a "name" property
        attachmentsFact.attachmentsObjToArray = function(obj) {
            var array = [];
            for(var attachment in obj) {
                obj[attachment].name = decodeURI(attachment);
                array.push(obj[attachment]);
            }

            return array;
        };

        // receives an array containing attachments
        // returns an object containing the attachments (such as the one CouchDB expects)
        attachmentsFact.attachmentsArrayToObj = function(array) {
            var obj = {},
            name = "";
            array.forEach(function(attachment) {
                name = encodeURI(attachment.name);
                delete attachment.name;
                obj[name] = attachment;
            });

            return obj;
        };

        return attachmentsFact;
    }]);

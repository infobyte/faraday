angular.module('faradayApp')
    .factory('attachmentsFact', ['BASEURL', '$http', '$q', function(BASEURL, $http, $q) {
        var attachmentsFact = {};

        // receives an array of File objects
        // returns an array of promises
        attachmentsFact.loadAttachments = function(files) {
            var deferred = $q.defer(),
            promises = [],
            tmp = {};
            files.forEach(function(file) {
                promises.push(attachmentsFact.loadAttachment(file));
            });
            $q.all(promises).then(function(attachments) {
                attachments.forEach(function(attachment) {
                    tmp[attachment.filename] = attachment;
                });
                deferred.resolve(tmp);
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

        attachmentsFact.getStubs = function(ws, vid, names) {
            var url = BASEURL + ws + "/" + vid, 
            stubs = {},
            deferred = $q.defer();

            $http.get(url).success(function(result) {
                for(var attachment in result._attachments) {
                    if(names.indexOf(attachment) >= 0) {
                        stubs[attachment] = result._attachments[attachment];
                    }
                }
                deferred.resolve(stubs);
            });

            return deferred.promise;
        };

        return attachmentsFact;
    }]);

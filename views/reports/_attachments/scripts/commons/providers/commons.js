angular.module('faradayApp')
    .factory('commonsFact', function() {
        var commonsFact = {};

        // receives a list of files each with a type property
        // returns a list with the icon corresponding to the file type, position by position
        commonsFact.loadIcons = function(files) {
            var icons = [],
            type = "";
            
            files.forEach(function(file, index) {
                // first lets load the type prop
                if(file.hasOwnProperty("type")) {
                    type = file.type.toLowerCase();
                } else if(file.hasOwnProperty("content_type")) {
                    type = file.content_type.toLowerCase();
                }
                if(type == "application/pdf") {
                    icons[index] = "fa-file-pdf-o";
                } else if(type.split("/")[0] == "image") {
                    icons[index] = "fa-file-image-o";
                } else if(type.split("/")[0] == "video") {
                    icons[index] = "fa-file-video-o";
                } else if(type == "application/msword" || type == "text/plain") {
                    icons[index] = "fa-file-text-o";
                } else {
                    icons[index] = "fa-file-o";
                }
            });

            return icons;
        };

        return commonsFact;
    });

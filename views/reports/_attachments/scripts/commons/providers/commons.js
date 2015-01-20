angular.module('faradayApp')
    .factory('commonsFact', function() {
        var commonsFact = {};

        // receives a list of files each with a type property
        // returns a list with the icon corresponding to the file type, position by position
        commonsFact.loadIcons = function(files) {
            var icons = [];
            files.forEach(function(file, index) {
                if(file.type.toLowerCase() == "application/pdf") {
                    icons[index] = "fa-file-pdf-o";
                } else if(file.type.toLowerCase().split("/")[0] == "image") {
                    icons[index] = "fa-file-image-o";
                } else if(file.type.toLowerCase().split("/")[0] == "video") {
                    icons[index] = "fa-file-video-o";
                } else if(file.type.toLowerCase() == "application/msword" || file.type.toLowerCase() == "text/plain") {
                    icons[index] = "fa-file-text-o";
                } else {
                    icons[index] = "fa-file-o";
                }
            });

            return icons;
        };

        return commonsFact;
    });

angular.module('faradayApp')
    .factory('commonsFact', function() {
        var commonsFact = {};

        // receives a dictionary of files whose keys are names
        // returns a dictionary whose keys are names and values are strings - the names of the icons
        commonsFact.loadIcons = function(files) {
            var icons = {},
            type = "";
            
            for(var name in files) {
                // first lets load the type prop
                if(files[name].hasOwnProperty("type")) {
                    type = files[name].type.toLowerCase();
                } else {
                    type = name.slice(-3);
                }
                if(type == "application/pdf" || type == "pdf") {
                    icons[name] = "fa-file-pdf-o";
                } else if(type.split("/")[0] == "image" || type == "jpg" || type == "peg" || type == "png") {
                    icons[name] = "fa-file-image-o";
                } else if(type == "application/msword" || type == "text/plain" || type == "txt" || type == "doc") {
                    icons[name] = "fa-file-text-o";
                } else {
                    icons[name] = "fa-file-o";
                }
            };

            return icons;
        };

        return commonsFact;
    });

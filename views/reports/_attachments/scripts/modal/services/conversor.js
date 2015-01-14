angular.module('faradayApp')
    .factory('conversor', function() {
    	var conversor = {};

    	conversor.arrayToObject = function(array){
	    	var refArray = [];
	       array.forEach(function(r){
	            refArray.push({ref:r});
	        });
	        return refArray;
    	}

    	conversor.objectToArray = function(object){
            var res = {};
            var arrayReferences = [];
            object.forEach(function(r){
                arrayReferences.push(r.ref);
            });
            arrayReferences = arrayReferences.filter(Boolean);
            return arrayReferences;
    	}

    	return conversor;
    });

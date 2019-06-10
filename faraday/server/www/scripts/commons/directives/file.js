// Faraday Penetration Test IDE
// Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

/**
 * @see http://docs.angularjs.org/guide/concepts
 * @see http://docs.angularjs.org/api/ng.directive:ngModel.NgModelController
 * @see https://github.com/angular/angular.js/issues/528#issuecomment-7573166
 */


angular.module('faradayApp')
    .directive('validFile',function(){
        return {
            require:'ngModel',
            link:function(scope,el,attrs,ngModel){
              //change event is fired when file is selected
              el.bind('change',function(){
                scope.$apply(function(){
                  ngModel.$setViewValue(el.val());
                  ngModel.$render();
                });
            });
        }
    }
});

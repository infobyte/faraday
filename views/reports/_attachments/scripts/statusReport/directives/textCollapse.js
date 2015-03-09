angular.module('faradayApp')
    .directive('textCollapse', ['$compile', 'commonsFact', function($compile, commons) {
        return {
            restrict: 'A',
            replace: true,
            link: function(scope, element, attrs) {
                // start collapsed
                scope.collapsed = false;

                // create the function to toggle the collapse
                scope.toggle = function() {
                    scope.collapsed = !scope.collapsed;
                };

                // wait for changes on the text
                attrs.$observe('textCollapseText', function(text) {
                    // escape text
                    text = commons.htmlentities(text);

                    // and get the maxLength
                    var maxLength = scope.$eval(attrs.textCollapseMaxLength);

                    if(text.length > maxLength) {
                        // split the text in two parts, the first always showing
                        var firstPart = String(text).substring(0, maxLength);
                        var secondPart = String(text).substring(maxLength, text.length);

                        // create some new html elements to hold the separate info
                        var firstSpan = $compile('<span>' + firstPart + '</span>')(scope);
                        var secondSpan = $compile('<span ng-if="collapsed">' + secondPart + '</span>')(scope);
                        var moreIndicatorSpan = $compile('<span ng-if="!collapsed">...</span>')(scope);
                        var toggleButton = $compile('<span selection-model-ignore class="collapse-text-toggle" ng-click="toggle()"> <a href="" selection-model-ignore>{{collapsed ? "less" : "more"}}</a></span>')(scope);

                        // remove the current contents of the element
                        // and add the new ones we created
                        element.empty();
                        element.append(firstSpan);
                        element.append(secondSpan);
                        element.append(moreIndicatorSpan);
                        element.append(toggleButton);
                    } else {
                        element.empty();
                        element.append(text);
                    }
                });
            }
        };
    }]);

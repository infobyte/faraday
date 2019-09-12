// Faraday Penetration Test IDE
// Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .directive('customFieldPrev', ['vulnsManager', function (vulnsManager) {
        return {
            restrict: 'E',
            scope: false,
            replace: true,
            template: '<div><div class="tab-pane-header"><i class="fa fa-spinner fa-spin" ng-show="isUpdatingVuln === true && fieldToEdit === cf.field_name"></i>    {{cf.field_display_name}}</div> \n\
                            <div class="form-group" ng-if="cf.field_type !== \'list\'"> \n\
                                <label class="sr-only" for="{{cf.field_name}}">{{cf.field_display_name}}</label> \n\
                                <input type="text" class="form-control input-sm" id="{{cf.field_name}}" name="{{cf.field_name}}" \n\
                                       placeholder="{{cf.field_display_name}}" \n\
                                       ng-focus="activeEditPreview(cf.field_name)" \
                                       ng-blur="processToEditPreview(false)"\
                                       ng-model="lastClickedVuln.custom_fields[cf.field_name]" check-custom-type="{{cf.field_type}}" \n\
                                       uib-tooltip="{{(cf.field_type === \'int\') ? \'Type only numbers\' : \'Input type text\'}}"/> \n\
                            </div> \n\
                            <div class="form-group " ng-if="cf.field_type === \'list\'" ng-class="lastClickedVuln.custom_fields[cf.field_name].length > 0 ? \'no-margin-bottom\' : \'\'">\n\
                                <div class="input-group"> \n\
                                    <label class="sr-only" for="{{cf.field_name}}">{{cf.field_display_name}}</label> \n\
                                    <input type="text" class="form-control input-sm" id="{{cf.field_name}}" name="{{cf.field_name}}" \n\
                                           placeholder="{{cf.field_display_name}}" \n\
                                           ng-focus="activeEditPreview(cf.field_name)" \
                                           ng-model="valueField" \n\
                                           uib-tooltip="Input type list"/> \n\
                                    <span class="input-group-addon cursor" ng-click="newValueField(valueField)"><i class="fa fa-plus-circle"></i></span> \n\
                                </div> \n\
                            </div> \n\
                            <div class="reference" ng-repeat="item in lastClickedVuln.custom_fields[cf.field_name] track by $index" ng-class="{\'last-item-field\':$last}" ng-if="cf.field_type === \'list\'"> \n\
                                <div class="input-group margin-bottom-sm"> \n\
                                    <label class="sr-only" for="vuln-refs-create">{{cf.field_display_name}}</label> \n\
                                    <input ng-if="item.value" type="text" class="form-control input-sm" id="vuln-refs-create" placeholder="{{cf.field_display_name}}" \n\
                                           ng-model="item.value" \n\
                                           role="button" readonly/> \n\
                                    <input ng-if="!item.value" type="text" class="form-control input-sm" id="vuln-refs-create" placeholder="{{cf.field_display_name}}" \n\
                                           ng-model="item" \n\
                                           role="button" readonly/> \n\
                                    <span class="input-group-addon cursor" ng-click="removeValueField($index)"> \n\
                                    <i class="fa fa-minus-circle"></i></span>                                \n\
                                    </div> \n\
                            </div> \n\
                        </div></div>',
            link: function (scope, element, attrs) {
                scope.newValueField = function (valueField) {
                    if (valueField !== "" && valueField !== undefined) {
                        if(scope.lastClickedVuln.custom_fields[scope.cf.field_name] === null )
                            scope.lastClickedVuln.custom_fields[scope.cf.field_name] = [];

                        // we need to check if the ref already exists
                        if (scope.lastClickedVuln.custom_fields[scope.cf.field_name].filter(function(field) {return field.value === valueField}).length === 0) {
                            scope.lastClickedVuln.custom_fields[scope.cf.field_name].push({value: valueField});
                            scope.valueField = "";
                        }
                        angular.element('#'+scope.cf.field_name).val("");

                        scope.fieldToEdit = scope.cf.field_name;
                        scope.processToEditPreview(false);

                    }
                };

                scope.removeValueField = function (index) {
                    scope.fieldToEdit = scope.cf.field_name;
                    scope.lastClickedVuln.custom_fields[scope.cf.field_name].splice(index, 1);
                    scope.isUpdatingVuln = true;

                    vulnsManager.updateVuln(scope.realVuln, scope.lastClickedVuln).then(function () {
                        scope.isUpdatingVuln = false;
                        scope.fieldToEdit = undefined;
                        }, function (data) {
                            scope.hideVulnPreview();
                            commonsFact.showMessage("Error updating vuln " + scope.realVuln.name + " (" + scope.realVuln._id + "): " + (data.message || JSON.stringify(data.messages)));
                            scope.fieldToEdit = undefined;
                            scope.isUpdatingVuln = false;

                });
          };
            }
        }
    }]);

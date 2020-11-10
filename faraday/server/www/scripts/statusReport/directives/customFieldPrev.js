// Faraday Penetration Test IDE
// Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .directive('customFieldPrev', ['vulnsManager', function (vulnsManager) {
        return {
            restrict: 'E',
            scope: false,
            replace: true,
            template: '<div> \n\
                            <div ng-if="cf.field_type === \'str\'" ng-init="isEditable = true"> \n\
                                <div class="tab-pane-header" ng-dblclick="isEditable = true" title="Double click to edit"><i class="fa fa-spinner fa-spin" ng-show="isUpdatingVuln === true && fieldToEdit === cf.field_name"></i>    {{cf.field_display_name}}  <span class="glyphicon glyphicon-question-sign" title="Edit using markdown code"></span></div> \n\
                                <div class="form-group"> \n\
                                    <label class="sr-only" for="{{cf.field_name}}">{{cf.field_display_name}}</label> \n\
                                    <textarea class="form-control" placeholder="{{cf.field_display_name}}" rows="5" id="vuln-desc" name="desc" ng-show="isEditable === true" \n\
                                        ng-focus="activeEditPreview(cf.field_name)" ng-blur="processToEditPreview(false); isEditable = isEditable.length==0 || !lastClickedVuln.custom_fields[cf.field_name]" ng-model="lastClickedVuln.custom_fields[cf.field_name]" ng-bind-html="lastClickedVuln.custom_fields[cf.field_name] | markdown" \n\
                                        style="margin: 0 2px 0 0;"  autofocus> \n\
                                    </textarea> \n\
                                    <div class="col-md-12" ng-cloak ng-show="lastClickedVuln.custom_fields[cf.field_name].length > 0 && isEditable === false"> \n\
                                        <div class="markdown-preview" style="height: 100px;!important;" ng-bind-html="lastClickedVuln.custom_fields[cf.field_name] | markdown" ng-dblclick="isEditable = true">{{lastClickedVuln.custom_fields[cf.field_name] | markdown}}</div> \n\
                                    </div> \n\
                                </div> \n\
                            </div> \n\
                            <div ng-if="cf.field_type === \'int\'"> \n\
                                <div class="tab-pane-header"><i class="fa fa-spinner fa-spin" ng-show="isUpdatingVuln === true && fieldToEdit === cf.field_name"></i>  {{cf.field_display_name}}</div> \n\
                                    <div class="form-group">\n\
                                        <label class="sr-only" for="{{cf.field_name}}">{{cf.field_display_name}}</label> \n\
                                        <input type="text" class="form-control input-sm" id="{{cf.field_name}}" name="{{cf.field_name}}" \n\
                                               placeholder="{{cf.field_display_name}}" \n\
                                               ng-focus="activeEditPreview(cf.field_name)" \
                                               ng-blur="processToEditPreview(false)"\
                                               ng-model="lastClickedVuln.custom_fields[cf.field_name]" check-custom-type="{{cf.field_type}}" \n\
                                               uib-tooltip="Type only numbers"/> \n\
                                    </div> \n\
                            </div> \n\ \
                            <div ng-if="cf.field_type === \'choice\'"> \n\
                                <div class="tab-pane-header"><i class="fa fa-spinner fa-spin" ng-show="isUpdatingVuln === true && fieldToEdit === cf.field_name"></i>  {{cf.field_display_name}}</div> \n\
                                <div class="btn-group col-md-6 col-sm-6 col-xs-6 btn-cf-choice" ng-if="cf.field_type === \'choice\'"> \n\
                                    <button type="button" class="dropdown-toggle btn-change-property primary-btn btn-primary-white no-overflow"  data-toggle = "dropdown" id = "btn-chg-choice" title = "Choices">\n\
                                        <span ng-if="lastClickedVuln.custom_fields[cf.field_name] !== null" > {{lastClickedVuln.custom_fields[cf.field_name]}}</span>\n\
                                        <span ng-if="lastClickedVuln.custom_fields[cf.field_name] === null">Select {{cf.field_display_name}}</span> \n\
                                    </button> \n\
                                    <button type="button" class="dropdown-toggle secondary-btn btn-change-property btn-secondary-white" data-toggle="dropdown" id="caret-choice" title="Choices"> \n\
                                        <span><i class="fa fa-angle-down fa-lg" aria-hidden="true"></i> </span> \n\
                                    </button> \n\
                                    <ul class="dropdown-menu dropdown-menu-right col-md-12 dropd-cf-choice" role="menu"> \n\
                                        <li ng-repeat="choice in  parserOptions(cf.field_metadata)"> \n\
                                        <a class="ws no-overflow" href="javascript:;" ng-click="onChangeChoiceCf(choice)">{{choice}}</a> \n\
                                        </li> \n\
                                    </ul> \n\
                                 </div> \n\
                            </div> \n\
                            <div ng-if="cf.field_type === \'list\'"> \n\
                                <div class="tab-pane-header"><i class="fa fa-spinner fa-spin" ng-show="isUpdatingVuln === true && fieldToEdit === cf.field_name"></i>  {{cf.field_display_name}}</div> \n\
                                <div class="form-group" ng-class="lastClickedVuln.custom_fields[cf.field_name].length > 0 ? \'no-margin-bottom\' : \'\'">\n\
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
                        if (scope.lastClickedVuln.custom_fields[scope.cf.field_name] === null)
                            scope.lastClickedVuln.custom_fields[scope.cf.field_name] = [];

                        // we need to check if the ref already exists
                        if (scope.lastClickedVuln.custom_fields[scope.cf.field_name].filter(function (field) {
                            return field.value === valueField
                        }).length === 0) {
                            scope.lastClickedVuln.custom_fields[scope.cf.field_name].push({value: valueField});
                            scope.valueField = "";
                        }
                        angular.element('#' + scope.cf.field_name).val("");

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

                scope.onChangeChoiceCf = function (value) {
                    scope.fieldToEdit = scope.cf.field_name;
                    scope.activeEditPreview(scope.cf.field_name);
                    scope.lastClickedVuln.custom_fields[scope.cf.field_name] = value;
                    scope.processToEditPreview(false);
                };

                scope.parserOptions = function (rawOptions) {
                    return JSON.parse(rawOptions)
                };
            }}
    }]);

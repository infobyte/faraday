
/**
 * The Selection Model module
 *
 * The ngRepeat companion. This module exists to give developers a lightweight
 * option for easily managing selections in lists and tables. It also aims to
 * play nicely with native angular features so you can leverage existing tools
 * for filtering, sorting, animations, etc.
 *
 * @package selectionModel
 */

angular.module('selectionModel', []);


angular.module('selectionModel').directive('selectionModel', [
  'selectionStack', 'uuidGen', 'selectionModelOptions',
  function(selectionStack, uuidGen, selectionModelOptions) {
    'use strict';
    return {
      restrict: 'A',
      link: function(scope, element, attrs) {

        /**
         * Defaults from the options provider
         *
         * Use `selectionModelOptionsProvider` when configuring your module to
         * set application wide defaults
         */
        var defaultOptions = selectionModelOptions.get()
          , defaultSelectedAttribute = defaultOptions.selectedAttribute
          , defaultSelectedClass = defaultOptions.selectedClass
          , defaultType = defaultOptions.type
          , defaultMode = defaultOptions.mode
          , defaultCleanupStrategy = defaultOptions.cleanupStrategy;

        /**
         * The selection model type
         *
         * Controls how selections are presented on the underlying element. Use
         * 'basic' (the default) to simplye assign a "selected" class to
         * selected items. If set to 'checkbox' it'll also sync the checked
         * state of the first checkbox child in each underlying `tr` or `li`
         * element.
         *
         * Note that the 'checkbox' type assumes the first input child element
         * will be the checkbox.
         */
        var smType = attrs.selectionModelType || defaultType;

        /**
         * The selection mode
         *
         * Supports 'single', 'multi[ple]', and 'multi[ple]-additive'. Single
         * mode will only allow one item to be marked as selected at a time.
         * Vanilla multi mode allows for multiple selectioned items but requires
         * modifier keys to select more than one item at a time. Additive-multi
         * mode allows for multiple items to be selected and will not deselect
         * other items when a vanilla click is made. Additive multi also allows
         * for de-selection without a modifier key (think of `'multi-additive'`
         * as turning every click into a ctrl-click.
         */
        var smMode = attrs.selectionModelMode || defaultMode
          , isMultiMode = /^multi(ple)?(-additive)?$/.test(smMode)
          , isModeAdditive = /^multi(ple)?-additive/.test(smMode);

        /**
         * The item attribute to track selected status
         *
         * Use `selection-model-selected-attribute` to override the default
         * attribute.
         */
        var selectedAttribute = attrs.selectionModelSelectedAttribute || defaultSelectedAttribute;

        /**
         * The selected class name
         *
         * Will be applied to dom items (e.g. `tr` or `li`) representing
         * selected items. Use `selection-model-selected-class` to override the
         * default class name.
         */
        var selectedClass = attrs.selectionModelSelectedClass || defaultSelectedClass;

        /**
         * The cleanup strategy
         *
         * How to handle items that are removed from the current view. By
         * default no action is taken, you may set this to `deselect` to force
         * items to be deselected when they are filtered away, paged away, or
         * otherwise no longer visible on the client.
         */
        var cleanupStrategy = attrs.selectionModelCleanupStrategy || defaultCleanupStrategy;

        /**
         * The list of items
         *
         * selectionModel must be attached to the same element as an ngRepeat
         */
        var repeatLine = attrs.ngRepeat;
        if(!repeatLine) {
          throw 'selectionModel must be used along side ngRepeat';
        }

        /**
         * The list of selected items
         *
         * If used should resolve to an (initially empty) array.  Use this in
         * your view as **read only** if you'd like to do something with just
         * the selected items. Note that order is not guarenteed and any items
         * added to this array programmatically are ignored.
         */
        var selectedItemsList = scope.$eval(attrs.selectionModelSelectedItems);

        /**
         * The last-click stack id
         *
         * There may be multiple selection models on the page and each will need
         * independent click stacks.
         */
        var clickStackId = (function() {
          if(!isMultiMode) {
            return null;
          }
          var idAttr = 'data-selection-model-stack-id';
          // Id may be cached on this element
          var stackId = element.attr(idAttr);
          if(stackId) {
            return stackId;
          }

          // Otherwise it may be on the partent
          stackId = element.parent().attr(idAttr);
          if(stackId) {
            element.attr(idAttr, stackId);
            return stackId;
          }

          // welp guess we're the first, create a new one and cache it on this
          // element (for us) and the parent element (for others)
          stackId = uuidGen.create();
          element.attr(idAttr, stackId);
          element.parent().attr(idAttr, stackId);
          return stackId;
        }());

        var repeatParts = repeatLine.split(' in ')
          , smItem = scope.$eval(repeatParts[0]);

        var updateDom = function() {
          if(smItem[selectedAttribute]) {
            element.addClass(selectedClass);
          } else {
            element.removeClass(selectedClass);
          }

          if('checkbox' === smType) {
            var cb = element.find('input');
            cb.prop('checked', smItem[selectedAttribute]);
          }
        };

        var getAllVisibleItems = function() {
          return scope.$eval(repeatParts[1]);
        };

        // Strips away filters - this lets us e.g. deselect items that are
        // filtered out
        var getAllItems = function() {
          return scope.$eval(repeatParts[1].split('|')[0]);
        };

        var deselectAllItems = function() {
          angular.forEach(getAllItems(), function(item) {
            item[selectedAttribute] = false;
          });
          if(angular.isArray(selectedItemsList)) {
            selectedItemsList.length = 0;
          }
        };

        var selectItemsBetween = function(lastItem) {
          var allItems = getAllVisibleItems()
            , foundLastItem = false
            , foundThisItem = false;

          lastItem = lastItem || smItem;

          angular.forEach(getAllVisibleItems(), function(item) {
            foundThisItem = foundThisItem || item === smItem;
            foundLastItem = foundLastItem || item === lastItem;
            var inRange = (foundLastItem + foundThisItem) === 1;
            if(inRange || item === smItem || item === lastItem) {
              item[selectedAttribute] = true;
            }
          });
        };

        /**
         * Item click handler
         *
         * Use the `ctrl` key to select/deselect while preserving the rest of
         * your selection. Note your your selection mode must be set to
         * `'multiple'` to allow for more than one selected item at a time. In
         * single select mode you still must use the `ctrl` or `shitft` keys to
         * deselect an item.
         *
         * The `shift` key allows you to select ranges of items at a time. Use
         * `ctrl` + `shift` to select a range while preserving your existing
         * selection. In single select mode `shift` behaves like `ctrl`.
         *
         * When an item is clicked with no modifier keys pressed it will be the
         * only selected item.
         *
         * On Mac the `meta` key is treated as `ctrl`.
         *
         * Note that when using the `'checkbox'` selection model type clicking
         * on a checkbox will have no effect on any row other than the one the
         * checkbox is in.
         */
        var handleClick = function(event) {
          var isCtrlKeyDown = event.ctrlKey || event.metaKey || isModeAdditive
            , isShiftKeyDown = event.shiftKey
            , target = event.target || event.srcElement
            , isCheckboxClick = 'checkbox' === smType &&
                'INPUT' === target.tagName &&
                'checkbox' === target.type;

          if(isCheckboxClick) {
            event.stopPropagation();
          }

          // Select multiple allows for ranges - use shift key
          if(isShiftKeyDown && isMultiMode && !isCheckboxClick) {
            // Use ctrl+shift for additive ranges
            if(!isCtrlKeyDown) {
              scope.$apply(deselectAllItems);
            }
            selectItemsBetween(selectionStack.peek(clickStackId));
            scope.$apply();
            return;
          }

          // Use ctrl/shift without multi select to true toggle a row
          if(isCtrlKeyDown || isShiftKeyDown || isCheckboxClick) {
            var isSelected = !smItem[selectedAttribute];
            if(!isMultiMode) {
              deselectAllItems();
            }
            smItem[selectedAttribute] = isSelected;
            if(smItem[selectedAttribute]) {
              selectionStack.push(clickStackId, smItem);
            }
            scope.$apply();
            return;
          }

          // Otherwise the clicked on row becomes the only selected item
          deselectAllItems();
          scope.$apply();

          smItem[selectedAttribute] = true;
          selectionStack.push(clickStackId, smItem);
          scope.$apply();
        };

        element.on('click', handleClick);
        if('checkbox' === smType) {
          var elCb = element.find('input');
          if(elCb[0] && 'checkbox' === elCb[0].type) {
            element.find('input').on('click', handleClick);
          }
        }

        // We might be coming in with a selection
        updateDom();

        // If we were given a cleanup strategy then setup a `'$destroy'`
        // listener on the scope.
        if('deselect' === cleanupStrategy) {
          scope.$on('$destroy', function() {
            smItem[selectedAttribute] = false;
          });
        }

        scope.$watch(repeatParts[0] + '.' + selectedAttribute, function(newVal, oldVal) {
          // Be mindful of programmatic changes to selected state
          if(!isMultiMode && newVal && !oldVal) {
            deselectAllItems();
            smItem[selectedAttribute] = true;
          }

          if(angular.isArray(selectedItemsList)) {
            var ixSmItem = selectedItemsList.indexOf(smItem);
            if(smItem[selectedAttribute]) {
              if(-1 === ixSmItem) {
                selectedItemsList.push(smItem);
              }
            } else {
              if(-1 < ixSmItem) {
                selectedItemsList.splice(ixSmItem, 1);
              }
            }
          }

          updateDom();
        });
      }
    };
  }
]);


/**
 * Default options for the selection model directive
 *
 * 
 *
 * @package selectionModel
 */

angular.module('selectionModel').provider('selectionModelOptions', [function() {
  'use strict';

  var options = {
    selectedAttribute: 'selected',
    selectedClass: 'selected',
    type: 'basic',
    mode: 'single',
    cleanupStrategy: 'none'
  };

  this.set = function(userOpts) {
    angular.extend(options, userOpts);
  };

  this.$get = function() {
    var exports = {
      get: function() {
        return angular.copy(options);
      }
    };
    return exports;
  };


}]);


angular.module('selectionModel').service('selectionStack', function() {
  'use strict';
  var exports = {}
    , maxSize = 1000
    , stacks = {};

  exports.push = function(id, item) {
    if(!stacks.hasOwnProperty(id)) {
      stacks[id] = [];
    }
    var stack = stacks[id];
    stack.push(item);
    while(stack.length > maxSize) {
      stack.shift();
    }
    return stack.length;
  };

  exports.pop = function(id) {
    if(!stacks.hasOwnProperty(id)) {
      stacks[id] = [];
    }
    var stack = stacks[id];
    return stack.pop();
  };

  exports.peek = function(id) {
    if(!stacks.hasOwnProperty(id)) {
      stacks[id] = [];
    }
    var stack = stacks[id];
    return stack.length ? stack[stack.length - 1] : undefined;
  };

  return exports;
});

/*jshint bitwise:false */

angular.module('selectionModel').service('uuidGen', function() {
  'use strict';
  var exports = {};
  var uid = ['0', '0', '0'];

  exports.create = function() {
    var index = uid.length;
    var digit;
    while (index) {
      index--;
      digit = uid[index].charCodeAt(0);
      if (digit === 57 /*'9'*/ ) {
        uid[index] = 'A';
        return uid.join('');
      }
      if (digit === 90 /*'Z'*/ ) {
        uid[index] = '0';
      } else {
        uid[index] = String.fromCharCode(digit + 1);
        return uid.join('');
      }
    }
    uid.unshift('0');
    return uid.join('');
  };

  return exports;
});

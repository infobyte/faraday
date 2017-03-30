// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

module.exports = function(config){
  config.set({

    basePath : './',

    files : [ 
      '../server/www/script/mousetrap.js',
      '../server/www/script/jquery-1.9.1.js',
      '../server/www/script/bootstrap.min.js',
      '../server/www/script/angular.js',
      '../server/www/script/angular-cookies.js',
      '../server/www/script/angular-hotkeys.js',
      '../server/www/script/angular-route.js',
      '../server/www/script/angular-selection-model.js',
      '../server/www/script/angular-file-upload-shim.js',
      '../server/www/script/angular-file-upload.js',
      '../server/www/script/angular-mocks.js',
      '../server/www/script/ngClip.js',
      '../server/www/script/ui-bootstrap-tpls-0.14.1.min.js',
      '../server/www/script/cryptojs-sha1.js',
      '../server/www/script/ZeroClipboard.min.js',
      '../server/www/script/sanitize.js',
      '../server/www/script/angular-ui-notification.min.js',
      '../server/www/script/Chart.js',
      '../server/www/script/angular-chart.min.js',
      '../server/www/script/ui-grid.js',
      '../server/www/script/moment.js',
      '../server/www/script/angular-moment.js',
      '../server/www/scripts/app.js',
      '../server/www/scripts/**/*.js',
      '../tests_web/faradayApp/components/**/*.js',
    ],

    autoWatch : true,

    frameworks: ['jasmine'],

    browsers : ['Chrome'],

    plugins : [
            'karma-chrome-launcher',
            'karma-firefox-launcher',
            'karma-jasmine',
            'karma-junit-reporter'
            ],

    junitReporter : {
      outputFile: 'test_out/unit.xml',
      suite: 'unit'
    }

  });
};

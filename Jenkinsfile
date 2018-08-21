#!groovy
node (label: "master"){
    def ENV_PATH = "$HOME/venv/faraday"
    echo "${ENV_PATH}"

    stage("Clean virtualenv") {
        sh "rm -rf ${ENV_PATH}"
    }

    stage("Install Python Virtual Enviroment") {
        sh "/usr/local/bin/virtualenv --no-site-packages ${ENV_PATH} --python=/usr/local/bin/python"
    }

    // Get the latest version of our application code.
    stage ("Pull Code from SCM") {
        checkout scm
    }

    stage ("Install Application Dependencies") {
        sh """
            source ${ENV_PATH}/bin/activate
            pip install virtualenv responses
            pip install -U -r $WORKSPACE/requirements.txt
            pip install -U -r $WORKSPACE/requirements_server.txt
            pip install -U -r $WORKSPACE/requirements_extras.txt
            pip install -U -r $WORKSPACE/requirements_dev.txt
            deactivate
           """
    }

    stage ("Check code style") {
        sh """
            sloccount --duplicates --wide --details $WORKSPACE   | fgrep -v .git > $WORKSPACE/sloccount.sc || :
            find $WORKSPACE -name \\"*.py\\" | egrep -v '^./tests/'  | xargs pyflakes  > $WORKSPACE/pyflakes.log || :
            find $WORKSPACE -name \\"*.py\\" | egrep -v '^./tests/'  | xargs pylint --output-format=parseable --reports=y > $WORKSPACE/pylint.log || :
            eslint -c /home/faraday/.eslintrc.js -f checkstyle $WORKSPACE/server/www/scripts/**/* > eslint.xml || true

           """
           warnings canComputeNew: false, canResolveRelativePaths: false, consoleParsers: [[parserName: 'PyFlakes']], defaultEncoding: '', excludePattern: '', healthy: '', includePattern: '', messagesPattern: '', parserConfigurations: [[parserName: 'AcuCobol Compiler', pattern: 'pyflakes.log']], unHealthy: ''

    }

    stage ("Run Unit/Integration Tests") {
        def testsError = null
        try {
            sh """
                source ${ENV_PATH}/bin/activate
                cd $WORKSPACE && pytest -v --junitxml=$WORKSPACE/xunit.xml || :
                deactivate
               """
               step([$class: 'CoberturaPublisher', autoUpdateHealth: false, autoUpdateStability: false, coberturaReportFile: '**/coverage.xml', failNoReports: false, failUnhealthy: false, failUnstable: false, maxNumberOfBuilds: 0, onlyStable: false, sourceEncoding: 'ASCII', zoomCoverageChart: false])
        }
        catch(err) {
            testsError = err
            currentBuild.result = 'FAILURE'
        }
        finally {
            junit "**/xunit.xml"
            notifyBuild(currentBuild.result, "SQLite Build")
            if (testsError) {
                throw testsError
            }

        }
    }

    stage ("Run Unit/Integration Tests (with PostgreSQL)") {
        def testsError = null
        try {
            withCredentials([string(credentialsId: 'postgresql_connection_string', variable: 'CONN_STRING')]) {
                sh """
                    source ${ENV_PATH}/bin/activate
                    cd $WORKSPACE && pytest -v --junitxml=$WORKSPACE/xunit-postgres.xml --connection-string "$CONN_STRING" || :
                    deactivate
                """
                step([$class: 'CoberturaPublisher', autoUpdateHealth: false, autoUpdateStability: false, coberturaReportFile: '**/coverage.xml', failNoReports: false, failUnhealthy: false, failUnstable: false, maxNumberOfBuilds: 0, onlyStable: false, sourceEncoding: 'ASCII', zoomCoverageChart: false])
            }
        }
        catch(err) {
            testsError = err
            currentBuild.result = 'FAILURE'
        }
        finally {
            junit "**/xunit-postgres.xml"
            notifyBuild(currentBuild.result, "PostgreSQL Build")
            if (testsError) {
                throw testsError
            }

        }
    }

    stage ("Build docs") {
        sh """
            source ${ENV_PATH}/bin/activate
            pip install sphinx
            mkdir -p ~/docs
            rm -rf ~/docs/jenkins_build
            cd $WORKSPACE/doc && make html && cp -r _build/html ~/docs/jenkins_build
        """
    }

    stage ("Run Closure Compiler") {
        try {
            sh """
                java -jar /home/faraday/closure-compiler-v20180610.jar $WORKSPACE/server/www/scripts
            """
        }
        catch (err) {
            currentBuild.result = 'FAILURE'
        }
        finally {
            notifyBuild(currentBuild.result, "Closure compiler")
        }
    }
}

def notifyBuild(String buildStatus = 'STARTED', String extraMessage = '') {
  // build status of null means successful
  buildStatus =  buildStatus ?: 'SUCCESSFUL'

  // Default values
  def colorName = 'RED'
  def colorCode = '#FF0000'
  def subject = "${buildStatus}: Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]'"
  def summary = "${subject} (${env.BUILD_URL}) " + extraMessage

  // Override default values based on build status
  if (buildStatus == 'STARTED') {
    color = 'YELLOW'
    colorCode = '#FFFF00'
  } else if (buildStatus == 'SUCCESSFUL') {
    color = 'GREEN'
    colorCode = '#00FF00'
  } else {
    color = 'RED'
    colorCode = '#FF0000'
    summary = summary + ' @channel'
  }

  // Send notifications
  slackSend (color: colorCode, message: summary)
}

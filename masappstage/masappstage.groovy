#!groovy
import groovy.transform.Field
@Field Map scmVars = null
job_name = "${env.JOB_NAME}".toLowerCase()

if (job_name.contains('android')){
    app_extension = 'apk'
    directory = 'TRP: PATH_TO_APK_ARTIFACTS'
    project = "TRP: ANDROID JOB WHERE THE APK WILL BE DOWNLOADED"
    critical_vulnerabilities = "TRP: 0"
    high_vulnerabilities = "TRP: 0"
    medium_vulnerabilities = "TRP: 3"
    low_vulnerabilities = "TRP: 3"
    critical_behaviors = "TRP: 0"
    high_behaviors = "TRP: 0"
    medium_behaviors = "TRP: 0"
    low_behaviors = "TRP: 0"
    riskscoring = "TRP: 7"
}
else {
    app_extension = 'ipa'
    directory = 'TRP: PATH_TO_IPA_ARTIFACTS'
    project = "TRP: IOS JOB WHERE THE IPA WILL BE DOWNLOADED"
    critical_vulnerabilities = "TRP: 0"
    high_vulnerabilities = "TRP: 0"
    medium_vulnerabilities = "TRP: 3"
    low_vulnerabilities = "TRP: 3"
    critical_behaviors = "TRP: 0"
    high_behaviors = "TRP: 0"
    medium_behaviors = "TRP: 0"
    low_behaviors = "TRP: 0"
    riskscoring = "TRP: 7"
}

def projectProperties = [
    buildDiscarder(logRotator(artifactDaysToKeepStr: '', artifactNumToKeepStr: '', daysToKeepStr: '', numToKeepStr: '30')),
    parameters([
         choice(choices: ['standard', 'detailed standard', 'riskscoring', 'detailed riskscoring'], description: 'The mASAPP CI execution mode. Go to https://github.com/alopezna5/mASAPP_CI/blob/master/masappstage/README.md for more info', name: 'mASAPP_CI'),
         string(defaultValue: "TRP: WORKGROUP NAME", description: 'The mASAPP workgroup to analyse in', name: 'WORKGROUP', trim: false),
         string(defaultValue: critical_vulnerabilities, description: 'The maximum number of allowed critical vulnerabilities. (NOT COMPATIBLE WITH RISKSCORING EXECUTION) ', name: 'CRITICAL_VULNERABILITIES', trim: true),
         string(defaultValue: high_vulnerabilities, description: 'The maximum number of allowed high vulnerabilities. (NOT COMPATIBLE WITH RISKSCORING EXECUTION) ', name: 'HIGH_VULNERABILITIES', trim: true),
         string(defaultValue: medium_vulnerabilities, description: 'The maximum number of allowed medium vulnerabilities. (NOT COMPATIBLE WITH RISKSCORING EXECUTION) ', name: 'MEDIUM_VULNERABILITIES', trim: true),
         string(defaultValue: low_vulnerabilities, description: 'The maximum number of allowed low vulnerabilities. (NOT COMPATIBLE WITH RISKSCORING EXECUTION) ', name: 'LOW_VULNERABILITIES', trim: true),
         string(defaultValue: critical_behaviors, description: 'The maximum number of allowed critical behaviors. (NOT COMPATIBLE WITH RISKSCORING EXECUTION) ', name: 'CRITICAL_BEHAVIORS', trim: true),
         string(defaultValue: high_behaviors, description: 'The maximum number of allowed high behaviors. (NOT COMPATIBLE WITH RISKSCORING EXECUTION) ', name: 'HIGH_BEHAVIORS', trim: true),
         string(defaultValue: medium_behaviors, description: 'The maximum number of allowed medium behaviors. (NOT COMPATIBLE WITH RISKSCORING EXECUTION) ', name: 'MEDIUM_BEHAVIORS', trim: true),
         string(defaultValue: low_behaviors, description: 'The maximum number of allowed low behaviors. (NOT COMPATIBLE WITH RISKSCORING EXECUTION) ', name: 'LOW_BEHAVIORS', trim: true),
         string(defaultValue: riskscoring, description: 'The maximum risk allowed (NOT COMPATIBLE WITH STANDARD EXECUTION) ', name: 'RISKSCORE', trim: true)]),
         pipelineTriggers([upstream(project)]),
]
properties(projectProperties)

node("TRP: NODE NAME"){
    stage('Get applications to analyse'){
        copyArtifacts projectName: project, selector: lastSuccessful()
    }
    stage('Build'){
        sh '''
            #!/bin/bash
            PATH=~/.local/bin:${PATH}
            pip3 install masappcli --user --upgrade
        '''
    }

    stage('mASAPP CI'){
        withCredentials([
            string(credentialsId:'MASAPP_KEY', variable: 'MASAPP_KEY'),
            string(credentialsId:'MASAPP_SECRET', variable: 'MASAPP_SECRET')
        ]){
            if (env.mASAPP_CI.contains("riskscoring")){
                if (env.mASAPP_CI.contains("detailed")){
                    detail = "-d"
                    print "mASAPP CI Detailed Riskscoring Execution"
                }
                else{
                    print "mASAPP CI Riskscoring Execution"
                    detail = ""
                }
                try{
                    sh """
                        #!/bin/bash
                        PATH=~/.local/bin:${PATH}
                        for app in \$(find ${directory} -name *.${app_extension}); do
                            echo [!] Analysing: \${app}
                            echo [!] Executing: masappcli -r ${env.RISKSCORE} -a \${app} -w ${env.WORKGROUP} ${detail}
                            masappcli -r ${env.RISKSCORE} -a \${app} -w "${env.WORKGROUP}" ${detail}
                        done;
                    """
                }
                catch(error){
                    currentBuild.result = 'UNSTABLE'
                }
            }
            else if (env.mASAPP_CI.contains("standard")){
                try{
                    standard_vulns_and_behaviors_string = """ {"vulnerabilities":{ "critical": ${env.CRITICAL_VULNERABILITIES},"high": ${env.HIGH_VULNERABILITIES}, "medium": ${env.MEDIUM_VULNERABILITIES}, "low": ${env.LOW_VULNERABILITIES} },"behaviorals":{"critical": ${env.CRITICAL_BEHAVIORS},"high": ${env.HIGH_BEHAVIORS},"medium": ${env.MEDIUM_BEHAVIORS},"low": ${env.LOW_BEHAVIORS} }} """
                    writeFile file: 'max_values.json', text: standard_vulns_and_behaviors_string
                    if (env.mASAPP_CI.contains("detailed")){
                        detail = "-d"
                        print "mASAPP CI Detailed Standard Execution"
                    }
                    else{
                        print "mASAPP CI Standard Execution"
                        detail = ""
                    }
                    sh """
                        #!/bin/bash
                        PATH=~/.local/bin:${PATH}
                        cat max_values.json
                        for app in \$(find ${directory} -name *.${app_extension}); do
                            echo [!] Analysing: \${app}
                            echo [!] Executing: masappcli -s max_values.json -a \${app} -w ${env.WORKGROUP} ${detail}
                            masappcli -s max_values.json -a \${app} -w "${env.WORKGROUP}" ${detail}
                        done;
                     """
                }
                catch(error){
                    currentBuild.result = 'UNSTABLE'
                }
            }
        }
    }

}
stage('mASAPP CI'){
    withCredentials([
        string(credentialsId: 'MASAPP_KEY', variable: 'MASAPP_KEY'),
        string(credentialsId: 'MASAPP_SECRET', variable: 'MASAPP_SECRET')
    ]){

        sh '''
            pip install masappcli --user --upgrade
        '''

        if (env.mASAPP_CI=="riskscoring"){
            print "mASAPP CI Riskscoring Execution"
            try{
                sh '''
                    masappcli -r $MAXIMUM -a [APPLICATION_PATH] --packageNameOrigin [PACKAGE_NAME_ORIGIN]
                '''

            }
            catch(error){
                    currentBuild.result = 'UNSTABLE'
            }
        }

        else if (env.mASAPP_CI=="detailed riskscoring"){
            print "mASAPP CI Detailed Riskscoring Execution"
            try{
                sh '''
                    masappcli -r $MAXIMUM -a [APPLICATION_PATH] --packageNameOrigin [PACKAGE_NAME_ORIGIN] -d
                '''

                }
            catch(error){
                currentBuild.result = 'UNSTABLE'
            }
        }

        else if (env.mASAPP_CI=="standard"){
                print "mASAPP CI Standard Execution"

                try{
                sh '''
                    echo $MAXIMUM >> max_values.json
                    cat max_values.json
                    pip install masappcli --user
                    masappcli -s max_values.json -a [APPLICATION_PATH] --packageNameOrigin [PACKAGE_NAME_ORIGIN]
                '''

                }
                catch(error){
                    currentBuild.result = 'UNSTABLE'
                }
        }

        else if (env.mASAPP_CI=="detailed standard"){
                print "mASAPP CI Detailed Standard Execution"

                try{
                sh '''
                    echo $MAXIMUM >> max_values.json
                    cat max_values.json
                    pip install masappcli --user
                    masappcli -s max_values.json -a [APPLICATION_PATH] --packageNameOrigin [PACKAGE_NAME_ORIGIN] -d
                '''

                }
                catch(error){
                    currentBuild.result = 'UNSTABLE'
                }
        }
        else{
            currentBuild.result = 'UNSTABLE'
        }
    }
}
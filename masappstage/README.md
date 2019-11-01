The file **masappstage_stored_credentials.groovy** from the current folder contains a standard stage for adding mASAPP CI
to your Jenkins Pipeline.

**HowTo:**


* You have to configure your Jenkins Pipeline for working with three variables:

    * mASAPP_CI : In this variable you will send the type of execution for your job. 
    Possible values:
        * "riskscoring": This execution analyse the application and throws an error if the maximum risk determined 
        in MAXIMUM is surpassed.
        * "detailed riskscoring": It executes a riskscoring analysis but including a detailed output where you can find the 
        vulnerabilities and behaviors evidences, tittle, risk (only for vulnerabilities), impact (only for behaviors) 
        and number of occurrences.
        * "standard": This execution expects a JSON file where the maximum of vulnerabilities and behaviors are 
        broken by severity.
        * "detailed standard": It executes a standard analysis but including a detailed output where you can find the 
        vulnerabilities and behaviors evidences, tittle, risk (only for vulnerabilities), impact (only for behaviors) 
        and number of occurrences.
        
    * MASAPP_KEY and MASAPP_SECRET: In this variables you will add the key and secret of mASAPP API as Jenkins credentials. 
    You can remove it and add them as masappcli params with -key and -secret.
    * MAXIMUM: The maximum value accepted in the execution. It depends on execution type:
        * "riskscoring" and "detailed riskscoring" expects a float number
        * "standard" and "detailed standard" expects a JSON file with the same format as the following example:
            
          ```json
            {
              "vulnerabilities": {
                "critical": 0,
                "high": 2,
                "medium": 5,
                "low": 6
              },
              "behaviorals": {
                "critical": 1,
                "high": 4,
                "medium": 5,
                "low": 5
              }
            } 
          ```
     
    * packageNameOrigin: the parameter returned by mASAPP named packageNameOrigin. It is only necessary when the job fails
    and **masappcli** requests this param, if not, leave it empty. It is not recommended to set a default value 
    for this var 

* Replace [APPLICATION_PATH] by the path to your application or add it as a var.
* Make particular fixes to your Pipeline like modifying the PATH or whatever.
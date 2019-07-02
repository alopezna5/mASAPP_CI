The file **masappstage_stored_credentials.groovy** from the current folder contains a standard stage for adding mASAPP CI
to your Jenkins Pipeline.

**HowTo:**


* Configure your Jenkins Pipeline for working with four variables:

    * mASAPP_CI : In this variable you will send the type of execution for your job.
    * MASAPP_KEY and MASAPP_SECRET: In this variables you will add the key and secret of mASAPP API as credentials. You \ 
      can remove it and add them as masappcli params with -key and -secret.
    * MAXIMUM: The maximum value accepted in the execution. It would be a float or a JSON depending the execution type.
    
* Replace [APPLICATION_PATH] by the path to your application
* Replace [PACKAGE_NAME_ORIGIN] by the packageNameOrigin of the application. You can remove this param in the execution.
* Make particular fixes to your Pipeline like modifying the PATH or whatever.
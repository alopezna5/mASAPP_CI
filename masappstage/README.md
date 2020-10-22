The file **masappstage.groovy** from the current folder contains a standard jenkinsfile for adding mASAPP CI
to your Jenkins Pipeline.

**HowTo:**

* You have to configure your Jenkins Pipeline for working with the variables MASAPP_KEY and MASAPP_SECRET: 
In this variables you will add the key and secret of mASAPP API as Jenkins credentials. 
You can remove it and add them as masappcli params with -key and -secret modifying masappstage.groovy but it is not 
recommended (key and secret will be printed in the job logs as plain text).
     
* Replace some of the Jenkinsfile values for adapting the file to your Jenkins and your own needs. You could find the 
elements that must be replaced looking for 'TRP:' in the file (I love Ctrl + F too :smile: )

* Make particular fixes to your Pipeline like modifying the PATH or whatever.

* Run one time the job and all the configuration will be applied to your job... Let's analyze  :fire:  !!!!
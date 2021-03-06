# mASAPP CI 
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/789361eff9e54d6cb15b1c267b866280)](https://www.codacy.com/manual/alopezna5/mASAPP_CI?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=alopezna5/mASAPP_CI&amp;utm_campaign=Badge_Grade) [![Version status](https://img.shields.io/pypi/v/masappcli.svg?color=F609C0)](https://pypi.org/project/masappcli) [![Documentation Status](https://readthedocs.org/projects/masappci/badge/?version=master)](https://masappci.readthedocs.io/en/master/?badge=master) [![Build Status](https://travis-ci.org/alopezna5/mASAPP_CI.svg?branch=minor_improvements)](https://travis-ci.org/alopezna5/mASAPP_CI) 


**mASAPP CI is an easy automated security check in your mobile development cycle.**

## Why


[Tacyt](https://tacyt.elevenpaths.com) is a big data tool that analyses and correlates millions of mobile apps and I played with some of the queries that
it permits obtaining worrying results:

[![Foo](readme_resources/vulnerabilities_tacyt.png)](https://tacyt.elevenpaths.com/)
[![Foo](readme_resources/behaviors_tacyt.png)](https://tacyt.elevenpaths.com/)
[![Foo](readme_resources/high_vulns_with_a_lot_of_download.png)](https://tacyt.elevenpaths.com/)

The summary of this results is that the the best known markets do not contains the most safest apps :(  


mASAPP CI was born for detecting security issues before uploading the apps to the markets giving the opportunity of solving
them with a really lower costs than if this issues were discovered by third parties in production environments.


mASAPP CI is the combination of two tools:
 
 * [masappcli](masappcli/): CLI tool that upload and analyse your *.apk or *.ipa file looking for vulnerabilities and behaviors using 
 [mASAPP](https://www.elevenpaths.com/es/tecnologia/masapp/index.html) or 
 [mASAPP Online](https://www.elevenpaths.com/es/tecnologia/masapp-online/index.html).
 This tool will return an error if the analysis exceeds the ceiling previously set by you
    
 * [masappstage](masappstage/): Groovy stage template that allows you to easy start using mASAPP CI in your jenkins 
 pipeline.


## Get started!

For getting started you only need a [mASAPP](https://masapp.elevenpaths.com) account and a simple Jenkins configuration explained in 
[masappstage README.md](masappstage/README.md). If you want to use masappcli in your CLI follow this 
[documentation](https://masappci.readthedocs.io/en/master/getting_started.html)


## Learn more

* [Learn more about Tacyt](https://www.youtube.com/watch?v=dg4-y5DPnMg)   <a href="https://tacyt.elevenpaths.com"> <img src="readme_resources/tacyt.png" width="14%" height="16%"  align="right"> </a>  <a href="https://masapp.elevenpaths.com"> <img src="readme_resources/mASAPP.png" width="14%" height="16%"  align="right"> </a>                    
* [HowTo for mASAPP Online registry](https://www.youtube.com/watch?v=WatthF8tVwA)                     
* [Other mASAPP features](https://www.youtube.com/watch?v=aclSLbqoVxg)  
 


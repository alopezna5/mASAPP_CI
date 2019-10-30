# mASAPP CI 
[![Documentation Status](https://readthedocs.org/projects/masappci/badge/?version=master)](https://masappci.readthedocs.io/en/master/?badge=master) [![Build Status](https://travis-ci.org/alopezna5/mASAPP_CI.svg?branch=minor_improvements)](https://travis-ci.org/alopezna5/mASAPP_CI)


mASAPP CI is designed for being an easy automated security check in your mobile development cycle.
mASAPP CI is the combination of two tools:
 
 * [masappcli](docs/source/index.rst): CLI tool that upload and analyse your *.apk or *.ipa file looking for vulnerabilities and behaviors using 
 [mASAPP](https://www.elevenpaths.com/es/tecnologia/masapp/index.html) or 
 [mASAPP Online](https://www.elevenpaths.com/es/tecnologia/masapp-online/index.html).
 This tool will return an error if the analysis exceeds the ceiling previously set by you
    
 * [masappstage](masappstage/README.md): Groovy stage template that allows you to easy start using mASAPP CI in your jenkins 
 pipeline.


## Why ??
Tacyt supervisa, almacena, analiza, correlaciona y clasifica millones de apps
móviles mediante su tecnología de big data añadiendo miles de aplicaciones nuevas cada día.

[![Foo](readme_resources/tacyt_is_the_answer.png)](https://tacyt.elevenpaths.com/)
Tacyt is a big data tool that analyses and correlates millions of mobile apps and I played with some of the queries that
it permits obtaining worrying results:

[![Foo](readme_resources/vulnerabilities_tacyt.png)](https://tacyt.elevenpaths.com/)
[![Foo](readme_resources/behaviors_tacyt.png)](https://tacyt.elevenpaths.com/)
[![Foo](readme_resources/high_vulns_with_a_lot_of_download.png)](https://tacyt.elevenpaths.com/)

The summary of this results is that the the best known markets do not contains the most safest apps :(  


mASAPP CI born for detecting security issues before uploading the apps to the apps markets and make our apps markets a safety place
 

Installation

Provide step by step series of examples and explanations about how to get a development env running.

How to use?
If people like your project they’ll want to learn how they can use it. To do so include step by step guide to use your project.



## Learn more

* [Learn more about Tacyt](https://www.youtube.com/watch?v=dg4-y5DPnMg)
* [HowTo for mASAPP Online registry](https://www.youtube.com/watch?v=WatthF8tVwA)
* [Other mASAPP features](https://www.youtube.com/watch?v=aclSLbqoVxg) 

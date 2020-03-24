# SAML-IDP 

Boilerplate for SAML Identity Provider implementation.

## Run locally on Docker

- `git clone https://github.com/giosil/saml-idp.git` 
- `mvn clean install` - this will produce `saml-idp.war` in `target` directory
- `docker build -t saml-idp .` - this will create a Docker image named saml-idp
- `docker run --rm -it -p 8080:8080 saml-idp` - To run image named saml-idp

## Contributors

* [Giorgio Silvestris](https://github.com/giosil)

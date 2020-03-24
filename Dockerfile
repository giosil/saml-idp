FROM tomcat
ENV DEPLOY_DIR /usr/local/tomcat/webapps
COPY target/saml-idp.war $DEPLOY_DIR

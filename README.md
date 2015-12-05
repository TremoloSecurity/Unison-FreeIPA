# Unison-FreeIPA
This project provides a provisioning target for FreeIPA / Red Hat Identity Management (http://www.freeipa.org/page/Main_Page / https://access.redhat.com/products/identity-management-and-infrastructure).  The provisioning target allows for the creation of users, updating of attributes and groups as well as setting passwords.  In addition, the target can generate "shadow objects" designed to work with SSO and constrained delegation where a password shouldn't be known.

## Configuration Options
There are three configration options:

* url - The protocol and host of the FreeIPA IPA-Web server.  Do NOT include any path information
* userName - The user name (uid attribute) of a member of the admins group
* password - The password of the service account used to create accounts
* createShadowAccounts - If true, when a user is created a random password is generated so that the account is active and ready for use, but not usable with a password

## Build
This project is built using maven

## Deploy
After a build, copying `target/unison-services-freeipa-1.0.7.jar` to OpenUnison's classpath or uploading into Unison as a proxy library will make the target available.  There are no additional libraries needed.

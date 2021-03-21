# Deploy

For deploy of this project, I have choosen AWS Lightsail Container services. 

Deploy is simple using their CLI and using our own dockerfiles as base as simple as:

* Build the image from a docker file
* Use AWS CLI to push that image to Lightsail repository.
* Create new deployment from UI or CLI


docker build -t hmm-identity:v1 .
aws lightsail push-container-image --region eu-central-1 --service-name auth-help-motivate-me --label identity --image hmm-identity:v3
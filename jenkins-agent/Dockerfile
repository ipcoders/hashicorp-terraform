# This Dockerfile extends the official Jenkins agent Docker image by adding support for HashiCorp's tfc-workflows-tooling.
# The tfc-workflows-tooling is a Go application designed to automate Terraform Cloud Runs via its API, facilitating
# infrastructure as code (IaC) practices. This Dockerfile customizes the Jenkins agent to seamlessly integrate with
# Terraform Cloud, enabling automated build, test, and deployment workflows for infrastructure management.
# It installs necessary dependencies, clones the tfc-workflows-tooling repository, builds the Go application,
# and cleans up the build environment to keep the Docker image as lean and efficient as possible.

# Repositories
# Hashicorp https://github.com/hashicorp/tfc-workflows-tooling
# Jenkins https://github.com/jenkinsci/docker-agent

# Use the Jenkins agent base image
FROM jenkins/agent as agent

SHELL ["/bin/bash","-e", "-u", "-o", "pipefail", "-c"]
ARG user=jenkins
USER root
WORKDIR /home/"${user}"
RUN apt-get update && apt-get install -y golang-go jq && \
    git clone https://github.com/hashicorp/tfc-workflows-tooling.git tfc_repo

WORKDIR /home/"${user}"/tfc_repo
RUN go build -o tfci
WORKDIR /home/"${user}"
RUN mv tfc_repo/tfci . && rm -rf tfc_repo

USER jenkins

# Jenkins Agent with HashiCorp TFC Workflows Tooling
This repository contains a custom Jenkins agent Dockerfile designed for integrating with HashiCorp's tfc-workflows-tooling, 
a powerful tool for automating Terraform Cloud Runs via its API. This setup is tailored for teams looking to streamline their 
infrastructure as code (IaC) workflows, enabling automated build, test, and deployment processes for managing infrastructure.

## Features
- Custom Jenkins Agent: Based on the official Jenkins agent image, customized to support Terraform Cloud automation.
- HashiCorp TFC Workflows Tooling Integration: Automates Terraform Cloud Runs, enhancing IaC practices with Jenkins.
- Go Application Support: Includes Go for building and running Go-based applications, specifically the tfc-workflows-tooling.
- Optimized Dockerfile: Carefully crafted to maintain a balance between functionality and image size, ensuring efficient CI/CD pipelines.

## Getting Started
To use this custom Jenkins agent, you will need Docker installed on your machine. Follow these steps to build and run your custom Jenkins agent Docker image.

### Prerequisites
- Docker
- Jenkins with agent configuration setup

### Building the Docker Image
Run the following command to build the Docker image:

```bash
docker build -t jenkins-tfc-agent:latest .
```

### Integrating with Jenkins
To utilize this custom Jenkins agent within your Jenkins setup, you must configure Jenkins to use this Docker image as an agent through the Jenkins Clouds configuration. 
This integration allows Jenkins to dynamically launch this agent container whenever a build job requires it, enabling seamless automation workflows with Terraform Cloud.

#### Steps for Configuration:
1. Install the Docker Plugin: Ensure the Docker plugin is installed in Jenkins to allow Jenkins to provision agents using Docker.
2. Configure a Docker Cloud in Jenkins**:
   - Navigate to *Manage Jenkins > Manage Nodes and Clouds > Configure Clouds*.
   - Add a new Docker Cloud and configure it with your Docker host's details.
   - Under the Docker Cloud configuration, add a new Docker Agent template.
   - Specify the Docker image name (`jenkins-tfc-agent:latest`) in the image field.
   - Configure any additional options such as labels, environment variables, and the connection method (e.g., JNLP or SSH) as required by your Jenkins setup.
3. Save Your Configuration: Once configured, Jenkins will use this Docker image as an agent template, allowing Jenkins jobs to run on dynamically provisioned agents based on this image.

By following these steps, Jenkins will automatically provision new agent instances using this custom Docker image whenever your build pipelines require it. This setup enhances your CI/CD workflows by integrating the capabilities of HashiCorp's tfc-workflows-tooling directly into your Jenkins pipelines, streamlining the process of managing infrastructure with Terraform Cloud.

## Contributing
Contributions are welcome! If you have improvements or bug fixes, please open a pull request or issue.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

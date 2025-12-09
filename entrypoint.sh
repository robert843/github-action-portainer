#!/bin/sh
set -e

/root/portainer-deploy \
  --portainer-url="${INPUT_PORTAINER_URL}" \
  --portainer-api-key="${INPUT_PORTAINER_API_KEY}" \
  --stack-name="${INPUT_STACK_NAME}" \
  --deployment-method="${INPUT_DEPLOYMENT_METHOD}" \
  --repository-url="${INPUT_REPOSITORY_URL}" \
  --repository-reference="${INPUT_REPOSITORY_REFERENCE}" \
  --repository-username="${INPUT_REPOSITORY_USERNAME}" \
  --repository-password="${INPUT_REPOSITORY_PASSWORD}" \
  --compose-file-path="${INPUT_COMPOSE_FILE_PATH}" \
  --stack-file="${INPUT_STACK_FILE}" \
  --endpoint-id="${INPUT_ENDPOINT_ID}" \
  --environment-variables="${INPUT_ENVIRONMENT_VARIABLES}" \
  --prune="${INPUT_PRUNE}" \
  --pull-image="${INPUT_PULL_IMAGE}" \
  --use-https="${INPUT_USE_HTTPS}" \
  --auto-update="${INPUT_AUTO_UPDATE}" \
  --auto-update-interval="${INPUT_AUTO_UPDATE_INTERVAL}"
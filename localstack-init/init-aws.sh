#!/bin/sh
# Runs automatically inside the LocalStack container once it's healthy
# (mounted to /etc/localstack/init/ready.d/). Creates the dummy AWS
# resources the app expects: an S3 bucket wired to send ObjectCreated
# events to an SQS queue, and an SNS topic for scan-result notifications.

set -e

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
ENDPOINT="http://localhost:4566"
BUCKET="clamrest-uploads"
QUEUE_NAME="clamrest-scan-queue"
TOPIC_NAME="clamrest-scan-results"

echo "[init] Creating S3 bucket: $BUCKET"
awslocal s3 mb "s3://$BUCKET"

echo "[init] Creating SQS queue: $QUEUE_NAME"
awslocal sqs create-queue --queue-name "$QUEUE_NAME"
QUEUE_URL=$(awslocal sqs get-queue-url --queue-name "$QUEUE_NAME" --query 'QueueUrl' --output text)
QUEUE_ARN=$(awslocal sqs get-queue-attributes --queue-url "$QUEUE_URL" --attribute-names QueueArn --query 'Attributes.QueueArn' --output text)

echo "[init] Creating SNS topic: $TOPIC_NAME"
awslocal sns create-topic --name "$TOPIC_NAME"
TOPIC_ARN=$(awslocal sns list-topics --query "Topics[?contains(TopicArn, '$TOPIC_NAME')].TopicArn" --output text)

echo "[init] Subscribing webhook-receiver to SNS topic"
awslocal sns subscribe --topic-arn "$TOPIC_ARN" --protocol http --notification-endpoint http://webhook-receiver:8080/sns

echo "[init] Allowing S3 to publish to SQS queue"
awslocal sqs set-queue-attributes --queue-url "$QUEUE_URL" --attributes '{
  "Policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"sqs:SendMessage\",\"Resource\":\"'"$QUEUE_ARN"'\",\"Condition\":{\"ArnLike\":{\"aws:SourceArn\":\"arn:aws:s3:::'"$BUCKET"'\"}}}]}"
}'

echo "[init] Wiring S3 -> SQS event notifications on ObjectCreated:*"
awslocal s3api put-bucket-notification-configuration \
  --bucket "$BUCKET" \
  --notification-configuration '{
    "QueueConfigurations": [
      {
        "QueueArn": "'"$QUEUE_ARN"'",
        "Events": ["s3:ObjectCreated:*"]
      }
    ]
  }'

echo "[init] Done. Bucket=$BUCKET Queue=$QUEUE_URL"

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/dutchcoders/go-clamd"
	"github.com/google/uuid"
)

type S3Event struct {
	Records []S3EventRecord `json:"Records"`
}

type S3EventRecord struct {
	EventName string `json:"eventName"`
	S3        struct {
		Bucket struct {
			Name string `json:"name"`
		} `json:"bucket"`
		Object struct {
			Key string `json:"key"`
		} `json:"object"`
	} `json:"s3"`
}

func startSQSConsumer(queueURL string) {
	fmt.Printf(time.Now().Format(time.RFC3339)+" [SQS] Starting consumer on queue %s\n", queueURL)

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("[SQS] Failed to load AWS config: %v\n", err)
		return
	}

	sqsClient := sqs.NewFromConfig(cfg)
	s3Client := s3.NewFromConfig(cfg)

	for {
		msgResult, err := sqsClient.ReceiveMessage(context.TODO(), &sqs.ReceiveMessageInput{
			QueueUrl:            aws.String(queueURL),
			MaxNumberOfMessages: 10,
			WaitTimeSeconds:     20, // Long polling
		})

		if err != nil {
			fmt.Printf("[SQS] Error receiving messages: %v\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		if len(msgResult.Messages) == 0 {
			continue
		}

		for _, msg := range msgResult.Messages {
			go processSQSMessage(sqsClient, s3Client, queueURL, *msg.Body, *msg.ReceiptHandle)
		}
	}
}

func processSQSMessage(sqsClient *sqs.Client, s3Client *s3.Client, queueURL string, body string, receiptHandle string) {
	scanID := uuid.New().String()
	
	// S3 events might be wrapped in SNS, but typically they are direct JSON
	var s3Event S3Event
	if err := json.Unmarshal([]byte(body), &s3Event); err != nil {
		fmt.Printf("[SQS %s] Failed to parse message body: %v\n", scanID, err)
		deleteMessage(sqsClient, queueURL, receiptHandle)
		return
	}

	if len(s3Event.Records) == 0 {
		// E.g. "s3:TestEvent"
		deleteMessage(sqsClient, queueURL, receiptHandle)
		return
	}

	for _, record := range s3Event.Records {
		if !strings.HasPrefix(record.EventName, "ObjectCreated") {
			continue
		}
		
		bucket := record.S3.Bucket.Name
		key, _ := url.QueryUnescape(record.S3.Object.Key)

		fmt.Printf(time.Now().Format(time.RFC3339)+" [SQS %s] Started scanning S3 Object: s3://%s/%s\n", scanID, bucket, key)

		// 1. Fetch Object (Stream)
		objReq := &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		}
		objResp, err := s3Client.GetObject(context.TODO(), objReq)
		if err != nil {
			fmt.Printf("[SQS %s] Failed to fetch object s3://%s/%s: %v\n", scanID, bucket, key, err)
			continue
		}

		// 2. Scan Object
		c := clamd.NewClamd(opts["CLAMD_PORT"])
		var abort chan bool
		clamdResponse, err := c.ScanStream(objResp.Body, abort)
		if err != nil {
			fmt.Printf("[SQS %s] ScanStream error for s3://%s/%s: %v\n", scanID, bucket, key, err)
			objResp.Body.Close()
			continue
		}

		var scanStatus string
		var clamdResult *clamd.ScanResult

		for s := range clamdResponse {
			clamdResult = s
			if s.Status == clamd.RES_OK {
				scanStatus = "CLEAN"
			} else {
				scanStatus = "INFECTED"
			}
			break
		}
		objResp.Body.Close()
		fmt.Printf(time.Now().Format(time.RFC3339)+" [SQS %s] Finished scanning s3://%s/%s. Result: %s\n", scanID, bucket, key, scanStatus)

		// 3. Tag Object in S3
		tagReq := &s3.PutObjectTaggingInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
			Tagging: &s3types.Tagging{
				TagSet: []s3types.Tag{
					{
						Key:   aws.String("ScanStatus"),
						Value: aws.String(scanStatus),
					},
					{
						Key:   aws.String("ScanDate"),
						Value: aws.String(time.Now().UTC().Format(time.RFC3339)),
					},
				},
			},
		}
		if _, err := s3Client.PutObjectTagging(context.TODO(), tagReq); err != nil {
			fmt.Printf("[SQS %s] Failed to tag object s3://%s/%s: %v\n", scanID, bucket, key, err)
		} else {
			fmt.Printf("[SQS %s] Successfully tagged s3://%s/%s as %s\n", scanID, bucket, key, scanStatus)
		}

		// 4. Send Webhook
		webhookURL := getWebhookURL(objResp, opts["SQS_WEBHOOK_URL"])
		if webhookURL != "" && clamdResult != nil {
			sendWebhook(webhookURL, clamdResult, scanID, fmt.Sprintf("s3://%s/%s", bucket, key))
		}
	}

	// 5. Delete Message from SQS
	deleteMessage(sqsClient, queueURL, receiptHandle)
}

func getWebhookURL(objResp *s3.GetObjectOutput, fallbackURL string) string {
	if objResp != nil && objResp.Metadata != nil {
		// S3 metadata keys are lowercased by the SDK usually, but check standard case
		if url, ok := objResp.Metadata["webhook-url"]; ok {
			return url
		}
		if url, ok := objResp.Metadata["Webhook-Url"]; ok {
			return url
		}
	}
	return fallbackURL
}

func deleteMessage(sqsClient *sqs.Client, queueURL string, receiptHandle string) {
	_, err := sqsClient.DeleteMessage(context.TODO(), &sqs.DeleteMessageInput{
		QueueUrl:      aws.String(queueURL),
		ReceiptHandle: aws.String(receiptHandle),
	})
	if err != nil {
		fmt.Printf("[SQS] Failed to delete message: %v\n", err)
	}
}

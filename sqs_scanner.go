package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

func scanS3EventHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSONError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONError(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{
		"scan_id": scanID,
		"message": "S3 Event processing started asynchronously",
	})

	go func() {
		cfg, err := config.LoadDefaultConfig(context.TODO())
		if err != nil {
			fmt.Printf("[API S3-Event] Failed to load AWS config: %v\n", err)
			return
		}
		s3Client := s3.NewFromConfig(cfg)
		processS3Event(s3Client, string(bodyBytes), scanID)
	}()
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
			WaitTimeSeconds:     20,
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
	processed := processS3Event(s3Client, body, scanID)
	if processed {
		deleteMessage(sqsClient, queueURL, receiptHandle)
	}
}

func processS3Event(s3Client *s3.Client, body string, scanID string) bool {
	var s3Event S3Event
	if err := json.Unmarshal([]byte(body), &s3Event); err != nil {
		fmt.Printf("[%s] Failed to parse message body: %v\n", scanID, err)
		return true // Invalid JSON, delete message
	}

	if len(s3Event.Records) == 0 {
		return true // e.g. s3:TestEvent, delete message
	}

	for _, record := range s3Event.Records {
		if !strings.HasPrefix(record.EventName, "ObjectCreated") {
			continue
		}
		
		bucket := record.S3.Bucket.Name
		key, _ := url.QueryUnescape(record.S3.Object.Key)

		fmt.Printf(time.Now().Format(time.RFC3339)+" [%s] Started scanning S3 Object: s3://%s/%s\n", scanID, bucket, key)

		objReq := &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		}
		objResp, err := s3Client.GetObject(context.TODO(), objReq)
		if err != nil {
			fmt.Printf("[%s] Failed to fetch object s3://%s/%s: %v\n", scanID, bucket, key, err)
			continue
		}

		c := clamd.NewClamd(opts["CLAMD_PORT"])
		var abort chan bool
		clamdResponse, err := c.ScanStream(objResp.Body, abort)
		if err != nil {
			fmt.Printf("[%s] ScanStream error for s3://%s/%s: %v\n", scanID, bucket, key, err)
			objResp.Body.Close()
			continue
		}

		var scanStatus string
		var scanSignature string
		var clamdResult *clamd.ScanResult

		for s := range clamdResponse {
			clamdResult = s
			if s.Status == clamd.RES_OK {
				scanStatus = "CLEAN"
				scanSignature = "OK"
			} else {
				scanStatus = "INFECTED"
				scanSignature = s.Description
				if scanSignature == "" {
					scanSignature = "UNKNOWN-THREAT FOUND"
				}
			}
			break
		}
		objResp.Body.Close()
		fmt.Printf(time.Now().Format(time.RFC3339)+" [%s] Finished scanning s3://%s/%s. Result: %s\n", scanID, bucket, key, scanStatus)

		timestamp := time.Now().UTC().Format("2006/01/02 15:04:05 UTC")
		tagReq := &s3.PutObjectTaggingInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
			Tagging: &s3types.Tagging{
				TagSet: []s3types.Tag{
					{
						Key:   aws.String("av-status"),
						Value: aws.String(scanStatus),
					},
					{
						Key:   aws.String("av-signature"),
						Value: aws.String(scanSignature),
					},
					{
						Key:   aws.String("av-timestamp"),
						Value: aws.String(timestamp),
					},
				},
			},
		}
		
		if _, err := s3Client.PutObjectTagging(context.TODO(), tagReq); err != nil {
			fmt.Printf("[%s] Failed to tag object s3://%s/%s: %v\n", scanID, bucket, key, err)
		} else {
			fmt.Printf("[%s] Successfully tagged s3://%s/%s as %s\n", scanID, bucket, key, scanStatus)
		}

		webhookURL := getWebhookURL(objResp, opts["SQS_WEBHOOK_URL"])
		if webhookURL != "" && clamdResult != nil {
			sendWebhook(webhookURL, clamdResult, scanID, fmt.Sprintf("s3://%s/%s", bucket, key))
		}
	}
	
	return true
}

func getWebhookURL(objResp *s3.GetObjectOutput, fallbackURL string) string {
	if objResp != nil && objResp.Metadata != nil {
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

package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
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
			Key       string `json:"key"`
			VersionId string `json:"versionId,omitempty"`
		} `json:"object"`
	} `json:"s3"`
}

func scanS3EventHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSONError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit for JSON
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		if checkMaxBytesError(w, err) {
			return
		}
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
			slog.Error("Failed to load AWS config for S3-Event", slog.Any("error", err))
			return
		}
		s3Client := s3.NewFromConfig(cfg)
		snsClient := sns.NewFromConfig(cfg)
		processS3Event(s3Client, snsClient, string(bodyBytes), scanID)
	}()
}

func startSQSConsumer(queueURL string) {
	slog.Info("Starting SQS consumer", slog.String("queue", queueURL))

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		slog.Error("Failed to load AWS config for SQS", slog.Any("error", err))
		return
	}

	sqsClient := sqs.NewFromConfig(cfg)
	s3Client := s3.NewFromConfig(cfg)
	snsClient := sns.NewFromConfig(cfg)

	for {
		msgResult, err := sqsClient.ReceiveMessage(context.TODO(), &sqs.ReceiveMessageInput{
			QueueUrl:            aws.String(queueURL),
			MaxNumberOfMessages: 10,
			WaitTimeSeconds:     20,
		})

		if err != nil {
			slog.Error("Error receiving messages from SQS", slog.Any("error", err))
			time.Sleep(5 * time.Second)
			continue
		}

		if len(msgResult.Messages) == 0 {
			continue
		}

		for _, msg := range msgResult.Messages {
			go processSQSMessage(sqsClient, s3Client, snsClient, queueURL, *msg.Body, *msg.ReceiptHandle)
		}
	}
}

func processSQSMessage(sqsClient *sqs.Client, s3Client *s3.Client, snsClient *sns.Client, queueURL string, body string, receiptHandle string) {
	scanID := uuid.New().String()
	processed := processS3Event(s3Client, snsClient, body, scanID)
	if processed {
		deleteMessage(sqsClient, queueURL, receiptHandle)
	}
}

func processS3Event(s3Client *s3.Client, snsClient *sns.Client, body string, scanID string) bool {
	var s3Event S3Event
	if err := json.Unmarshal([]byte(body), &s3Event); err != nil {
		slog.Error("Failed to parse SQS message body", slog.String("scan_id", scanID), slog.Any("error", err))
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
		versionId := record.S3.Object.VersionId

		slog.Info("Started scanning S3 Object", 
			slog.String("scan_id", scanID), 
			slog.String("bucket", bucket), 
			slog.String("key", key),
			slog.String("version_id", versionId),
		)

		start := time.Now()

		objReq := &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		}
		if versionId != "" {
			objReq.VersionId = aws.String(versionId)
		}
		
		objResp, err := s3Client.GetObject(context.TODO(), objReq)
		if err != nil {
			slog.Error("Failed to fetch S3 object", slog.String("scan_id", scanID), slog.String("bucket", bucket), slog.String("key", key), slog.Any("error", err))
			continue
		}

		maxFileSizeBytes := parseSize(opts["MAX_FILE_SIZE"])
		if maxFileSizeBytes == 0 {
			maxFileSizeBytes = 100 * 1024 * 1024 // default 100M
		}
		limitedBody := http.MaxBytesReader(nil, objResp.Body, maxFileSizeBytes+1024*1024)

		c := clamd.NewClamd(opts["CLAMD_PORT"])
		var abort chan bool
		clamdResponse, err := c.ScanStream(limitedBody, abort)
		if err != nil {
			slog.Error("ScanStream error for S3 object", slog.String("scan_id", scanID), slog.String("bucket", bucket), slog.String("key", key), slog.Any("error", err))
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

		slog.Info("Finished scanning S3 Object", 
			slog.String("scan_id", scanID),
			slog.String("bucket", bucket),
			slog.String("key", key),
			slog.String("version_id", versionId),
			slog.String("result", scanStatus),
			slog.String("signature", scanSignature),
			slog.Duration("duration_ms", time.Since(start)),
		)

		// 3a. Retrieve existing tags to prevent overwriting user tags
		var finalTags []s3types.Tag
		getTagReq := &s3.GetObjectTaggingInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		}
		if versionId != "" {
			getTagReq.VersionId = aws.String(versionId)
		}
		
		existingTagsResp, err := s3Client.GetObjectTagging(context.TODO(), getTagReq)
		if err == nil && existingTagsResp.TagSet != nil {
			for _, t := range existingTagsResp.TagSet {
				if *t.Key != "av-status" && *t.Key != "av-signature" && *t.Key != "av-timestamp" {
					finalTags = append(finalTags, t)
				}
			}
		}

		// Append new tags
		timestamp := time.Now().UTC().Format("2006/01/02 15:04:05 UTC")
		finalTags = append(finalTags, s3types.Tag{Key: aws.String("av-status"), Value: aws.String(scanStatus)})
		finalTags = append(finalTags, s3types.Tag{Key: aws.String("av-signature"), Value: aws.String(scanSignature)})
		finalTags = append(finalTags, s3types.Tag{Key: aws.String("av-timestamp"), Value: aws.String(timestamp)})

		// 3b. Update tags
		tagReq := &s3.PutObjectTaggingInput{
			Bucket:  aws.String(bucket),
			Key:     aws.String(key),
			Tagging: &s3types.Tagging{TagSet: finalTags},
		}
		if versionId != "" {
			tagReq.VersionId = aws.String(versionId)
		}
		
		if _, err := s3Client.PutObjectTagging(context.TODO(), tagReq); err != nil {
			slog.Error("Failed to tag S3 object", slog.String("scan_id", scanID), slog.String("bucket", bucket), slog.String("key", key), slog.Any("error", err))
		} else {
			slog.Info("Successfully tagged S3 object", slog.String("scan_id", scanID), slog.String("bucket", bucket), slog.String("key", key), slog.String("result", scanStatus))
		}

		// 4. Optionally delete if infected
		if scanStatus == "INFECTED" && opts["DELETE_INFECTED_FILES"] == "true" {
			delReq := &s3.DeleteObjectInput{
				Bucket: aws.String(bucket),
				Key:    aws.String(key),
			}
			if versionId != "" {
				delReq.VersionId = aws.String(versionId)
			}
			_, err := s3Client.DeleteObject(context.TODO(), delReq)
			if err != nil {
				slog.Error("Failed to delete infected S3 object", slog.String("scan_id", scanID), slog.String("bucket", bucket), slog.String("key", key), slog.Any("error", err))
			} else {
				slog.Info("Deleted infected S3 object", slog.String("scan_id", scanID), slog.String("bucket", bucket), slog.String("key", key))
			}
		}

		// 5. Optionally publish to SNS
		if snsTopicARN, ok := opts["SNS_TOPIC_ARN"]; ok && snsTopicARN != "" {
			publish := true
			if opts["SNS_PUBLISH_INFECTED_ONLY"] == "true" && scanStatus != "INFECTED" {
				publish = false
			}
			if publish {
				snsPayload := map[string]string{
					"bucket":       bucket,
					"key":          key,
					"av-status":    scanStatus,
					"av-signature": scanSignature,
					"av-timestamp": timestamp,
				}
				msgBytes, _ := json.Marshal(snsPayload)
				msgBody := string(msgBytes)
				_, err := snsClient.Publish(context.TODO(), &sns.PublishInput{
					TopicArn: aws.String(snsTopicARN),
					Message:  aws.String(msgBody),
				})
				if err != nil {
					slog.Error("Failed to publish to SNS", slog.String("scan_id", scanID), slog.Any("error", err))
				} else {
					slog.Info("Published result to SNS", slog.String("scan_id", scanID), slog.String("topic", snsTopicARN))
				}
			}
		}

		// 6. Send Webhook
		webhookURL := getWebhookURL(objResp, opts["SQS_WEBHOOK_URL"])
		if webhookURL != "" && clamdResult != nil {
			sendWebhook(webhookURL, clamdResult, scanID, "s3://"+bucket+"/"+key)
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
		slog.Error("Failed to delete SQS message", slog.Any("error", err))
	}
}

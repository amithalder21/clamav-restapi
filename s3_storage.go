package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
)

// presignedURLTTL controls how long a download_url stays valid.
// Default: 15 minutes.
func presignedURLTTL() time.Duration {
	if v := opts["AWS_S3_PRESIGNED_URL_TTL_SECONDS"]; v != "" {
		var secs int
		if _, err := fmt.Sscanf(v, "%d", &secs); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return 15 * time.Minute
}

// s3ObjectKey builds a tenant/date-scoped key matching the existing quarantine
// key convention, so clean-bucket and quarantine-bucket objects are laid out
// consistently. originalName is sanitized with filepath.Base so a crafted
// caller-supplied filename (e.g. containing "../") can't escape the
// tenant/date-scoped prefix used for isolation - see the same fix applied to
// the existing quarantine path.
func s3ObjectKey(tenantID string, originalName string) string {
	dateStr := time.Now().Format("2006/01/02")
	safeName := filepath.Base(originalName)
	return tenantID + "/" + dateStr + "/" + uuid.New().String() + "-" + safeName
}

// persistScannedFile uploads the file to whichever bucket is appropriate for
// the (already-normalized, i.e. formatStatus'd) scan status - AWS_S3_CLEAN_BUCKET
// for "CLEAN", AWS_S3_QUARANTINE_BUCKET for "INFECTED" - and returns both the
// s3:// URI and a presigned download URL. Returns ("", "") if the relevant
// bucket isn't configured (nothing is uploaded), the status is neither CLEAN
// nor INFECTED (e.g. an engine ERROR - nothing meaningful to persist), or the
// upload/presign step fails.
func persistScannedFile(status string, tenantID string, originalName string, filePath string, requestID string) (s3Path string, downloadURL string) {
	var bucket string
	switch status {
	case "CLEAN":
		bucket = opts["AWS_S3_CLEAN_BUCKET"]
	case "INFECTED":
		bucket = opts["AWS_S3_QUARANTINE_BUCKET"]
	}
	if bucket == "" {
		return "", ""
	}
	key := s3ObjectKey(tenantID, originalName)
	url := uploadAndPresign(bucket, key, filePath, requestID)
	if url == "" {
		return "", ""
	}
	return "s3://" + bucket + "/" + key, url
}

// uploadAndPresign uploads the file at filePath to bucket/key and returns a
// presigned GET URL valid for presignedURLTTL(). "Presigned" here means a
// time-limited link, not single-use - S3 doesn't natively enforce one-time
// access; that would need additional infrastructure (e.g. a Lambda that
// deletes the object on first GET) layered on top of this.
//
// Returns "" (and logs) on any failure - a storage/presign problem should
// never block returning the scan verdict itself, so callers should treat an
// empty result as "no download_url this time" rather than a hard error.
func uploadAndPresign(bucket string, key string, filePath string, requestID string) string {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		slog.Error("Failed to load AWS config for S3 upload", slog.String("request_id", requestID), slog.Any("error", err))
		return ""
	}

	s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if os.Getenv("AWS_ENDPOINT_URL") != "" {
			o.UsePathStyle = true
		}
		// Since SDK v1.30/S3 v1.61, the default "WhenSupported" behavior signs
		// an x-amz-checksum-mode header into every request - including
		// presigned URLs. A plain HTTP client (curl, browser fetch, most
		// consumer code) won't send that exact header back, so the resulting
		// download_url fails with SignatureDoesNotMatch for anyone not using
		// the same AWS SDK. "WhenRequired" keeps checksums opt-in instead of
		// baking them into every signature.
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	})

	f, err := os.Open(filePath)
	if err != nil {
		slog.Error("Failed to open file for S3 upload", slog.String("request_id", requestID), slog.String("bucket", bucket), slog.String("key", key), slog.Any("error", err))
		return ""
	}
	defer f.Close()

	_, err = s3Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   f,
	})
	if err != nil {
		slog.Error("Failed to upload file to S3", slog.String("request_id", requestID), slog.String("bucket", bucket), slog.String("key", key), slog.Any("error", err))
		return ""
	}

	presignClient := s3.NewPresignClient(s3Client)
	ttl := presignedURLTTL()
	presigned, err := presignClient.PresignGetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}, s3.WithPresignExpires(ttl))
	if err != nil {
		slog.Error("Failed to presign S3 URL", slog.String("request_id", requestID), slog.String("bucket", bucket), slog.String("key", key), slog.Any("error", err))
		return ""
	}

	slog.Info("Uploaded file to S3 and generated presigned URL",
		slog.String("request_id", requestID), slog.String("bucket", bucket), slog.String("key", key), slog.Duration("ttl", ttl))
	return presigned.URL
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
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

// cleanFileTTL controls how long a CLEAN file is expected to live in
// AWS_S3_CLEAN_BUCKET before an S3 Lifecycle rule (configured on the bucket
// itself, not by this app) deletes it. This value is used only to compute
// the informational file_expires_at timestamp written into the audit
// record - it does NOT itself delete anything. The actual deletion is an
// AWS-side S3 Lifecycle Expiration rule scoped to the "files/" prefix; keep
// this in sync with whatever that rule is actually configured to. Default
// 24h (1 day), matching S3 Lifecycle's own day-granularity.
func cleanFileTTL() time.Duration {
	if v := opts["AWS_S3_CLEAN_FILE_TTL_HOURS"]; v != "" {
		var hours int
		if _, err := fmt.Sscanf(v, "%d", &hours); err == nil && hours > 0 {
			return time.Duration(hours) * time.Hour
		}
	}
	return 24 * time.Hour
}

// s3ObjectKey builds a tenant/date-scoped key for a given (pre-generated) id.
// originalName is sanitized with filepath.Base so a crafted caller-supplied
// filename (e.g. containing "../") can't escape the tenant/date-scoped
// prefix used for isolation.
func s3ObjectKey(tenantID string, dateStr string, id string, originalName string) string {
	safeName := filepath.Base(originalName)
	return tenantID + "/" + dateStr + "/" + id + "-" + safeName
}

// AuditRecord is the sidecar JSON written alongside every CLEAN upload to
// AWS_S3_CLEAN_BUCKET, under the "audit/" prefix - which, unlike "files/",
// carries no S3 Lifecycle expiration. The scanned file itself is deleted
// after cleanFileTTL(); this record is what survives that deletion, so
// "what happened to this file" remains answerable after the file is gone.
type AuditRecord struct {
	ScanID         string `json:"scan_id"`
	RequestID      string `json:"request_id"`
	TenantID       string `json:"tenant_id"`
	Filename       string `json:"filename"`
	SHA256         string `json:"sha256,omitempty"`
	Status         string `json:"av-status"`
	Signature      string `json:"av-signature"`
	FileS3Key      string `json:"file_s3_key"`
	FileUploadedAt string `json:"file_uploaded_at"`
	FileExpiresAt  string `json:"file_expires_at"`
}

// persistScannedFile uploads the file to whichever bucket is appropriate for
// the (already-normalized, i.e. formatStatus'd) scan status - AWS_S3_CLEAN_BUCKET
// for "CLEAN", AWS_S3_QUARANTINE_BUCKET for "INFECTED" - and returns the s3://
// URI. A presigned download URL is returned only for "CLEAN" - a confirmed
// INFECTED file is still uploaded to quarantine (s3Path lets a security team
// with their own S3 access retrieve it), but the API never hands back a
// direct download link for it, so this endpoint can't become an
// unintentional malware distribution channel for anyone who has the JSON
// response.
//
// CLEAN uploads go under a "files/" prefix (scoped by an S3 Lifecycle rule
// on AWS_S3_CLEAN_BUCKET to expire after cleanFileTTL()) and additionally
// get an audit JSON sidecar written under "audit/" (no expiration), so the
// scan's outcome remains traceable after the file itself is deleted.
// INFECTED uploads to the quarantine bucket are unaffected - flat key
// layout, retained indefinitely, no audit sidecar (nothing there ever gets
// deleted, so there's no "traceability survives deletion" problem to solve).
//
// scanID may be "" (sync scans have none) - the audit record then falls
// back to the same generated id used in the file's own S3 key, so every
// persisted file has a stable, unique identifier either way.
//
// Returns ("", "") if the relevant bucket isn't configured (nothing is
// uploaded), the status is neither CLEAN nor INFECTED (e.g. an engine ERROR
// - nothing meaningful to persist), or the upload/presign step fails.
func persistScannedFile(status string, tenantID string, originalName string, filePath string, requestID string, scanID string, description string) (s3Path string, downloadURL string) {
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

	id := uuid.New().String()
	dateStr := time.Now().Format("2006/01/02")
	key := s3ObjectKey(tenantID, dateStr, id, originalName)
	if status == "CLEAN" {
		key = "files/" + key
	}

	url := uploadAndPresign(bucket, key, filePath, requestID)
	if url == "" {
		return "", ""
	}
	s3Path = "s3://" + bucket + "/" + key

	if status == "INFECTED" {
		return s3Path, ""
	}

	auditScanID := scanID
	if auditScanID == "" {
		auditScanID = id
	}
	uploadedAt := time.Now().UTC()
	writeAuditRecord(bucket, tenantID, dateStr, auditScanID, AuditRecord{
		ScanID:         auditScanID,
		RequestID:      requestID,
		TenantID:       tenantID,
		Filename:       originalName,
		SHA256:         sha256OrEmpty(filePath, requestID),
		Status:         status,
		Signature:      descriptionOrClean(description),
		FileS3Key:      key,
		FileUploadedAt: uploadedAt.Format(time.RFC3339),
		FileExpiresAt:  uploadedAt.Add(cleanFileTTL()).Format(time.RFC3339),
	}, requestID)

	return s3Path, url
}

// sha256OrEmpty hashes filePath for the audit record, logging (not failing)
// on error - a hashing problem should never block persisting the file or
// returning the scan verdict.
func sha256OrEmpty(filePath string, requestID string) string {
	hash, err := sha256File(filePath)
	if err != nil {
		slog.Error("Failed to hash file for audit record", slog.String("request_id", requestID), slog.Any("error", err))
		return ""
	}
	return hash
}

// descriptionOrClean mirrors the same "CLEAN" fallback writeScanResponse/
// formatScanResponse use, so the audit record's av-signature matches what
// the caller actually saw in the API response.
func descriptionOrClean(description string) string {
	if description == "" {
		return "CLEAN"
	}
	return description
}

// writeAuditRecord uploads a CLEAN scan's audit JSON to
// audit/<tenant>/<date>/<scanID>.json in the same bucket the file itself
// was uploaded to. Logs (never returns an error to the caller) on failure -
// a failed audit write should never affect the scan verdict or the
// s3_path/download_url already returned to the client.
func writeAuditRecord(bucket string, tenantID string, dateStr string, scanID string, record AuditRecord, requestID string) {
	data, err := json.Marshal(record)
	if err != nil {
		slog.Error("Failed to marshal audit record", slog.String("request_id", requestID), slog.Any("error", err))
		return
	}

	key := "audit/" + tenantID + "/" + dateStr + "/" + scanID + ".json"

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		slog.Error("Failed to load AWS config for audit record upload", slog.String("request_id", requestID), slog.Any("error", err))
		return
	}
	s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if os.Getenv("AWS_ENDPOINT_URL") != "" {
			o.UsePathStyle = true
		}
	})

	_, err = s3Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(data),
		ContentType: aws.String("application/json"),
	})
	if err != nil {
		slog.Error("Failed to upload audit record", slog.String("request_id", requestID), slog.String("bucket", bucket), slog.String("key", key), slog.Any("error", err))
		return
	}

	slog.Info("Wrote audit record", slog.String("request_id", requestID), slog.String("bucket", bucket), slog.String("key", key))
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

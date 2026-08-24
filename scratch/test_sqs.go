package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
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

func main() {
	body := `{
		"Records": [
		  {
			"eventName": "ObjectCreated:Put",
			"s3": {
			  "bucket": {
				"name": "example-quarantine"
			  },
			  "object": {
				"key": "test%2Ffile+with+spaces.pdf"
			  }
			}
		  }
		]
	  }`

	var s3Event S3Event
	if err := json.Unmarshal([]byte(body), &s3Event); err != nil {
		fmt.Printf("Failed to parse: %v\n", err)
		return
	}

	for _, record := range s3Event.Records {
		if !strings.HasPrefix(record.EventName, "ObjectCreated") {
			continue
		}
		bucket := record.S3.Bucket.Name
		key, _ := url.QueryUnescape(record.S3.Object.Key)
		
		fmt.Printf("Parsed S3 Event successfully!\nBucket: %s\nKey: %s\n", bucket, key)
	}
}

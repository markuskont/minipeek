package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/ccdcoe/go-peek/pkg/events"
	"github.com/ccdcoe/go-peek/pkg/outputs"
	"github.com/go-redis/redis"
)

type Alerta struct {
	Attributes struct {
		Region string `json:"region"`
	} `json:"attributes,omitemtpty"`
	//Correlate   []string `json:"correlate,omitemtpty"`
	Environment string   `json:"environment"`
	Event       string   `json:"event"`
	Group       string   `json:"group"`
	Origin      string   `json:"origin"`
	Resource    string   `json:"resource"`
	Service     []string `json:"service,omitemtpty"`
	Severity    string   `json:"severity"`
	//Tags        []string `json:"tags,omitemtpty"`
	Text    string `json:"text"`
	Type    string `json:"type"`
	Value   string `json:"value"`
	Timeout int    `json:"timeout"`
}

func (a Alerta) Send(host string) error {
	out, err := json.Marshal(a)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(
		"POST",
		"http://localhost:8080/api/alert",
		bytes.NewBuffer(out),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf(string(body))
	}
	return nil
}

func NewClient() (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   0,
	})

	if _, err := client.Ping().Result(); err != nil {
		return nil, err
	}
	return client, nil
}

func main() {
	client, err := NewClient()
	if err != nil {
		panic(err)
	}
	defer client.Close()

	var asset string

	stream := client.Subscribe("suricata")
	defer stream.Close()

	report := time.NewTicker(3 * time.Second)
	flush := time.NewTicker(10 * time.Second)
	bulk := outputs.NewBulk([]string{"http://localhost:9200"}, nil)

	sent := 0
	all := 0

	go func() {
		for err := range bulk.Logger.Errors() {
			fmt.Fprintf(os.Stderr, "ERR: %s\n", err)
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			assets := map[string]string{
				"192.168.144.10": "minion",
				"192.168.144.15": "shadow",
				"192.168.144.5":  "pihole",
			}
			sevs := map[int]string{
				1: "major",
				2: "minor",
				3: "informational",
			}
		loop:
			for {
				select {
				case msg, ok := <-stream.Channel():
					if !ok {
						break loop
					}
					data, err := events.NewEVE([]byte(msg.Payload))
					if err != nil {
						fmt.Fprintf(os.Stderr, "ERR: %s\n", err.Error())
						continue loop
					}
					data.Timestamp = data.GetEventTime()
					processed, _ := data.JSON()
					bulk.AddIndex(
						processed,
						outputs.ElaIndex("suricata").Format(data.GetEventTime()),
					)
					all++
					if data.SrcIP == nil || data.DestIP == nil || data.Alert == nil {
						continue loop
					}

					if val, ok := assets[data.SrcIP.String()]; ok {
						asset = val
					} else if val, ok := assets[data.DestIP.String()]; ok {
						asset = val
					} else {
						asset = data.DestIP.String()
					}
					var sev string
					if val, ok := sevs[data.Alert.Severity]; ok {
						sev = val
					} else {
						sev = sevs[3]
					}

					err = Alerta{
						Event:       data.Alert.Signature,
						Service:     []string{asset},
						Environment: "Production",
						Resource:    asset,
						Text: fmt.Sprintf(
							"Alert from %s to %s",
							data.SrcIP.String(),
							data.DestIP.String(),
						),
						Severity: sev,
						Value:    strconv.Itoa(data.Alert.Severity),
						Timeout:  300,
					}.Send("localhost:8080/api/alert")
					if err != nil {
						fmt.Fprintf(os.Stderr, "%s\n", err.Error())
					} else {
						sent++
					}
				case <-report.C:
					fmt.Fprintf(os.Stdout, "Worker %d sent %d alerts to alerta\n", id, sent)
				}
			}
		}(i)
	}
	for {
		select {
		case <-flush.C:
			bulk.Flush()
			sent = 0
			all = 0
		}
	}
}

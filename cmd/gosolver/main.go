package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/cespare/xxhash"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
)

const (
	apikey = "rorm-8473d243-790d-9184-3fa2-76e4ff8424df"
	proapi = "https://pro.nocaptchaai.com/solve"
)

var (
	pm            = sync.Mutex{}
	hashlistMutex sync.RWMutex
)

type Base64JSON struct {
	Images  map[string]string `json:"images"`
	Target  string            `json:"target"`
	Method  string            `json:"method"`
	Sitekey string            `json:"sitekey"`
	Site    string            `json:"site"`
	Ln      string            `json:"ln"`
}

type NoCapAnswer struct {
	Answer         []any  `json:"answer"`
	ID             string `json:"id"`
	Message        string `json:"message"`
	ProcessingTime string `json:"processing_time"`
	Solution       []int  `json:"solution"`
	Status         string `json:"status"`
	Target         string `json:"target"`
	URL            string `json:"url"`
}

func HashExists(prompt string, contentHash uint64) bool {
	hashStr := fmt.Sprintf("%x", contentHash)

	hashlistMutex.RLock()
	defer hashlistMutex.RUnlock()

	hashes, exists := hashlist[prompt]
	if exists {
		for _, h := range hashes {
			if h == hashStr {
				return true
			}
		}
	}
	return false
}

func ParallelHashExists(prompt string, contentHash uint64, wg *sync.WaitGroup, resultChan chan<- bool) {
	defer wg.Done()

	result := HashExists(prompt, contentHash)
	resultChan <- result
}

func ParallelHashExistsAllThreads(prompt string, contentHash uint64) bool {
	hashStr := fmt.Sprintf("%x", contentHash)

	hashlistMutex.RLock()
	defer hashlistMutex.RUnlock()

	for otherPrompt, hashes := range hashlist {
		if otherPrompt != prompt && !strings.HasPrefix(prompt, "not_") {
			for _, h := range hashes {
				if h == hashStr {
					return true
				}
			}
		}
	}
	return false
}

func SolvePic(url, prompt string) (bool, error) {
	resp, err := http.Get(url)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	encodedImage := base64.StdEncoding.EncodeToString(body)

	base64_json := Base64JSON{
		Images: map[string]string{
			"0": encodedImage,
		},
		Target:  prompt,
		Method:  "hcaptcha_base64",
		Sitekey: "4c672d35-0701-42b2-88c3-78380b0db560",
		Site:    "discord.com",
		Ln:      "en",
	}
	jsonBody, _ := json.Marshal(base64_json)

	req, _ := http.NewRequest("POST", proapi, bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-type", "application/json")
	req.Header.Set("apikey", apikey)

	client := &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		fmt.Println(err)
		return false, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	var answer NoCapAnswer
	if err := json.Unmarshal(bodyBytes, &answer); err != nil {
		return false, err
	}

	if len(answer.Solution) > 0 {
		return true, nil
	}

	return false, nil
}

func DownloadAndClassify(url, key, prompt string, results chan<- Result, wg *sync.WaitGroup) {
	defer wg.Done()
	st := time.Now()

	resp, err := http.Get(url)
	if err != nil {
		results <- Result{Hash: "", Match: false, Err: err, Url: url, St: time.Since(st), Key: key}
		return
	}
	defer resp.Body.Close()

	buff := make([]byte, 650)
	_, err = io.ReadFull(resp.Body, buff)
	if err != nil {
		results <- Result{Hash: "", Match: false, Err: err, Url: url, St: time.Since(st), Key: key}
		return
	}

	contentHash := xxhash.Sum64(buff)
	hashStr := fmt.Sprintf("%x", contentHash)

	if HashExists(prompt, contentHash) {
		results <- Result{Hash: hashStr, Match: true, Err: nil, Url: url, St: time.Since(st), Key: key}
		return
	}

	if HashExists(fmt.Sprintf("not_%s", prompt), contentHash) {
		results <- Result{Hash: hashStr, Match: false, Err: nil, Url: url, St: time.Since(st), Key: key}
		return
	}

	if ParallelHashExistsAllThreads(prompt, contentHash) {
		results <- Result{Hash: hashStr, Match: false, Err: nil, Url: url, St: time.Since(st), Key: key}
		return
	}

	// if not solved
	/*answer, err := SolvePic(url, prompt)
	if err != nil {
		results <- Result{Hash: fmt.Sprintf("%x", contentHash), Match: false, Err: nil, Url: url, St: time.Since(st), Key: key}
		return
	}

	if answer {
		go func() {
			mu.Lock()
			defer mu.Unlock()

			hashlist[prompt] = append(hashlist[prompt], fmt.Sprintf("%x", contentHash))

			file, err := os.OpenFile("../../asset/hash.csv", os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				return
			}
			defer file.Close()

			file.WriteString(fmt.Sprintf("%s,%s", fmt.Sprintf("%x", contentHash), prompt) + "\n")
		}()
	} else {
		mu.Lock()
		defer mu.Unlock()
		hashlist["not_"+prompt] = append(hashlist["not_"+prompt], fmt.Sprintf("%x", contentHash))

		file, err := os.OpenFile("../../asset/hash.csv", os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return
		}
		defer file.Close()

		file.WriteString(fmt.Sprintf("%s,not_%s", fmt.Sprintf("%x", contentHash), prompt) + "\n")
	}*/

	answer := false

	results <- Result{Hash: fmt.Sprintf("%x", contentHash), Match: answer, Err: nil, Url: url, St: time.Since(st), Key: key}
}

func Task(task *BodyNewSolveTask) *SolveRepsonse {
	results := make(chan Result, len(task.TaskList))
	t := time.Now()

	if strings.Contains(task.Question, "Please click each image containing a ") {
		task.Question = strings.ReplaceAll(strings.Split(task.Question, "Please click each image containing a ")[1], " ", "_")
	}

	var wg sync.WaitGroup

	for _, t := range task.TaskList {
		wg.Add(1)
		go DownloadAndClassify(t.DatapointURI, t.TaskKey, task.Question, results, &wg)
	}

	wg.Wait()
	close(results)

	resp := map[string]string{}

	for result := range results {
		resp[result.Key] = fmt.Sprintf("%v", result.Match)

		if result.Err != nil {
			fmt.Println("Image download failed:", result.Err)
			return nil
		}

		/*logger.Info("Image classified",
			zap.String("hash", result.Hash),
			zap.String("prompt", task.Question),
			zap.Bool("match", result.Match),
			zap.Int64("st", result.St.Milliseconds()),
			//	zap.String("url", result.Url),
		)*/
	}

	logger.Info("Task classified",
		zap.Int64("st", time.Since(t).Milliseconds()),
		zap.String("prompt", task.Question),
	)

	return &SolveRepsonse{
		Success: true,
		Data:    resp,
	}
}

func HandlerSolve(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var requestBody BodyNewSolveTask

	err := decoder.Decode(&requestBody)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	defer r.Body.Close()

	resp := Task(&requestBody)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func main() {
	if _, err := toml.DecodeFile("../../scripts/config.toml", &Config); err != nil {
		panic(err)
	}
	LoadLogger()

	count, err := LoadHash()
	if err != nil {
		panic(err)
	}

	logger.Info("Loaded hash csv",
		zap.Int("count", count),
	)

	for k, v := range hashlist {
		logger.Info("Loaded hash",
			zap.String("prompt", k),
			zap.Int("count", len(v)),
		)
	}

	switch os.Args[1] {
	case "scrape":
		return
	case "server":
		r := chi.NewRouter()

		r.Use(middleware.Logger)
		r.Post("/solve", HandlerSolve)

		err = http.ListenAndServe(fmt.Sprintf(":%d", Config.Server.Port), r)
		if err != nil {
			panic(err)
		}

		logger.Info("server online", zap.Int("port", Config.Server.Port))
	}
}

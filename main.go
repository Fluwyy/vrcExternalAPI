package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

var authCookie string
var authToken string
var avatarID string
var userID string

var (
	Username string
	Password string
	code     string
)

var choice string

func getCurrentUserID(authToken string) (string, error) {
	req, err := http.NewRequest("GET", "https://api.vrchat.cloud/api/1/auth/user", nil)
	if err != nil {
		return "", fmt.Errorf("error creating HTTP request: %w", err)
	}

	req.Header.Set("Cookie", "auth="+authToken)
	req.Header.Add("User-Agent", "golang Client")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get user info. Status Code: %d, Response: %s", resp.StatusCode, string(respBody))
	}

	var userInfo struct {
		ID string `json:"id"`
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %w", err)
	}

	err = json.Unmarshal(respBody, &userInfo)
	if err != nil {
		return "", fmt.Errorf("error unmarshaling user info: %w, body: %s", err, string(respBody))
	}

	if userInfo.ID == "" {
		return "", fmt.Errorf("user ID not found in response, possibly due to pending 2FA or invalid token")
	}

	return userInfo.ID, nil
}

func main() {
	loadedAuthToken, err := loadAuthToken()
	if err != nil {
		fmt.Println(err)
	} else {
		authToken = loadedAuthToken
	}

	requires2FA := false

	for {
		if authToken != "" && !requires2FA && loginSessionCheck(authToken) {
			fmt.Println("Login session is valid")
			break
		}

		fmt.Println("Enter your username: ")
		fmt.Scan(&Username)
		fmt.Println("Enter your password: ")
		fmt.Scan(&Password)
		fmt.Println("Making POST request...")

		var loginErr error
		requires2FA, loginErr = Login(Username, Password)
		if loginErr != nil {
			fmt.Println("Login error:", loginErr)
			fmt.Println("Login failed. Would you like to retry? (y/n)")
			fmt.Scan(&choice)
			if choice != "y" {
				fmt.Println("Exiting program.")
				return
			}
			continue
		}

		if !requires2FA && authCookie != "" {
			authToken = authCookie
			break
		} else if requires2FA {
			authToken = authCookie
			break
		}

		fmt.Println("Unexpected login state. Retrying...")
	}

	for {
		if !requires2FA {
			break
		}
		if loginSessionCheck(authToken) {
			fmt.Println("2FA session is valid.")
			break
		}
		fmt.Println("Enter the 2FA email OTP code: ")
		fmt.Scan(&code)
		VerifyEmailOTP(code)
		if loginSessionCheck(authToken) {
			fmt.Println("2FA verification successful.")
			break
		}
		fmt.Println("2FA verification failed. Retrying...")
	}

	fmt.Println("Fetching current user ID...")
	fetchedUserID, err := getCurrentUserID(authToken)
	if err != nil {
		fmt.Println("Error fetching user ID:", err)
		return
	}
	userID = fetchedUserID
	fmt.Println("Current User ID:", userID)

	fmt.Println("Enter new pronouns (e.g., 'he/him', 'she/her', 'they/them'): ")
	var newPronouns string
	fmt.Scan(&newPronouns)

	changePronouns(authToken, userID, newPronouns)
}

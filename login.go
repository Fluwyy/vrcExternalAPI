package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
)

var authData AuthData

type AuthData struct {
	AuthToken string `json:"auth_token"`
}

func saveSessionCookie(authToken string) error {
	config := AuthData{AuthToken: authToken}

	file, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshalling JSON: %v", err)
	}

	err = ioutil.WriteFile("config.json", file, 0644)
	if err != nil {
		return fmt.Errorf("error writing to file: %v", err)
	}

	fmt.Println("Auth token saved to config.json")
	return nil
}

func loadAuthToken() (string, error) {
	file, err := ioutil.ReadFile("config.json")
	if err != nil {
		return "", fmt.Errorf("error reading config file: %v", err)
	}

	var config AuthData
	err = json.Unmarshal(file, &config)
	if err != nil {
		return "", fmt.Errorf("error unmarshalling JSON: %v", err)
	}

	fmt.Println("Loaded auth token from JSON:", config.AuthToken)
	return config.AuthToken, nil
}

// loginSessionCheck now explicitly checks for 2FA requirement in the response body.
func loginSessionCheck(authToken string) bool {
	if authToken == "" {
		fmt.Println("Auth token is empty for session check.")
		return false
	}

	getCurrentUser := "https://api.vrchat.cloud/api/1/auth/user"

	req, err := http.NewRequest("GET", getCurrentUser, nil)
	if err != nil {
		fmt.Println("Error creating HTTP request for session check:", err)
		return false
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "auth="+authToken)
	req.Header.Add("User-Agent", "golang Client")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request for session check:", err)
		return false
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body for session check:", err)
		return false
	}

	fmt.Println("Session Check Status:", resp.Status)
	fmt.Println("Session Check Response body:", string(respBody))

	if resp.StatusCode != http.StatusOK {
		fmt.Println("Session check failed. Status Code:", resp.StatusCode)
		return false
	}

	// Parse the response body to check for 2FA requirement
	var sessionCheckResponse map[string]interface{}
	if err := json.Unmarshal(respBody, &sessionCheckResponse); err != nil {
		fmt.Println("Warning: Could not unmarshal session check response:", err)
		// If unmarshaling fails, assume it's not a 2FA required response and proceed.
		return true
	}

	if requires2FA, ok := sessionCheckResponse["requiresTwoFactorAuth"]; ok {
		if authMethods, isArray := requires2FA.([]interface{}); isArray && len(authMethods) > 0 {
			fmt.Println("Session check indicates 2FA is still required.")
			return false // Session is not fully valid yet
		}
	}

	// If 200 OK and no requiresTwoFactorAuth, then the session is valid.
	return true
}

// Login performs the initial login and returns true if 2FA is required.
func Login(user string, password string) (bool, error) {
	loginURL := "https://api.vrchat.cloud/api/1/auth/user"

	req, err := http.NewRequest("GET", loginURL, nil)
	if err != nil {
		return false, fmt.Errorf("error creating HTTP request: %w", err)
	}

	req.SetBasicAuth(user, password)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("User-Agent", "golang Client")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("error sending HTTP request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("error reading response body: %w", err)
	}

	fmt.Println("Login Status:", resp.Status)
	fmt.Println("Login Response body:", string(respBody))

	// Extract auth cookie regardless of 2FA status, as it's needed for 2FA step
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "auth" {
			authCookie = cookie.Value
			authToken = cookie.Value
			break
		}
	}

	if authCookie == "" {
		return false, fmt.Errorf("login failed: no auth cookie obtained")
	}

	// Check if 2FA is required from the response body
	var loginResponse map[string]interface{}
	if err := json.Unmarshal(respBody, &loginResponse); err != nil {
		fmt.Println("Warning: Could not unmarshal login response to check for 2FA:", err)
		// If unmarshaling fails, assume no 2FA is explicitly indicated and proceed.
	} else {
		if requires2FA, ok := loginResponse["requiresTwoFactorAuth"]; ok {
			if authMethods, isArray := requires2FA.([]interface{}); isArray && len(authMethods) > 0 {
				fmt.Println("Two-factor authentication required.")
				saveSessionCookie(authToken) // Save the token for 2FA step
				return true, nil             // Indicate 2FA is required
			}
		}
	}

	// If we reach here, it means login was successful and no 2FA is required, or 2FA was not indicated.
	if resp.StatusCode == http.StatusOK {
		saveSessionCookie(authToken)
		return false, nil // Login successful, no 2FA required
	}

	return false, fmt.Errorf("login failed with status %d", resp.StatusCode)
}

func VerifyEmailOTP(code string) {
	emailOTPUrl := "https://api.vrchat.cloud/api/1/auth/twofactorauth/emailotp/verify"

	requestBody, err := json.Marshal(map[string]string{
		"code": code,
	})
	if err != nil {
		fmt.Println("Error encoding request body:", err)
		return
	}

	req, err := http.NewRequest("POST", emailOTPUrl, bytes.NewBuffer(requestBody))
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("User-Agent", "golang Client")
	if authCookie != "" {
		req.Header.Set("Cookie", "auth="+authCookie)
	} else {
		fmt.Println("Missing auth cookie. Please login first.")
		return
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	formattedData := formatJSON(respBody)
	fmt.Println("2FA Verification Status:", resp.Status)
	fmt.Println("2FA Verification Response body:", formattedData)

	if resp.StatusCode == http.StatusOK {
		// Extract and save the new auth cookie after successful 2FA
		for _, cookie := range resp.Cookies() {
			if cookie.Name == "auth" {
				authCookie = cookie.Value
				authToken = cookie.Value
				fmt.Println("2FA successful. New auth token obtained.")
				saveSessionCookie(authToken) // Save the new, fully authenticated token
				break
			}
		}
	} else {
		fmt.Println("2FA verification failed.")
	}
}

func formatJSON(data []byte) string {
	var out bytes.Buffer
	err := json.Indent(&out, data, "", " ")
	if err != nil {
		fmt.Println("Error formatting JSON:", err)
	}

	return out.String()
}

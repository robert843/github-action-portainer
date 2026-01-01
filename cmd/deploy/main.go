package main

// Complete Portainer deploy tool:
// - supports Git repo and string deploy (swarm type=1)
// - detects endpointId by name (--endpoint-name)
// - auth by API key or username/password (login -> JWT)
// - updates existing stack if present (find by name)
// - sets access: public | teams | admin (resolve teams by name)

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
	"net/url"
	"github.com/spf13/cobra"
)

var (
	// connection / auth
	portainerUrl string
	useHTTPS     bool
	apiKey       string
	username     string
	password     string

	// stack
	stackName        string
	deploymentMethod string // "repository" or "string"
	repositoryURL    string
	repositoryRef    string
	repositoryUser   string
	repositoryPass   string
	composeFilePath  string // path inside repo for git mode
	stackFile        string // local compose file for string mode

	// endpoint
	endpointName string

	// options
	envVarsJSON        string
	envFile            string
	prune              bool
	pullImage          bool
	autoUpdate         bool
	autoUpdateInterval string

	// access
	accessMode      string // public|teams|admin
	teamName        string
	additionalFiles []string
	// runtime
	httpClient = &http.Client{Timeout: 30 * time.Second}
)

type Stack struct {
	ID     int    `json:"Id"`
	Name   string `json:"Name"`
	Type   int    `json:"Type"`
	Status int    `json:"Status"`
}

type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type AutoUpdateConfig struct {
	Interval string `json:"interval"`
}

type StackCreateRequest struct {
	Name                     string            `json:"name"`
	RepositoryURL            string            `json:"repositoryURL,omitempty"`
	RepositoryReferenceName  string            `json:"repositoryReferenceName,omitempty"`
	RepositoryAuthentication bool              `json:"repositoryAuthentication,omitempty"`
	RepositoryUsername       string            `json:"repositoryUsername,omitempty"`
	RepositoryPassword       string            `json:"repositoryPassword,omitempty"`
	ComposeFile              string            `json:"composeFile,omitempty"`
	StackFileContent         string            `json:"stackFileContent,omitempty"`
	Env                      []EnvVar          `json:"env,omitempty"`
	SwarmID                  string            `json:"swarmID,omitempty"`
	AutoUpdate               *AutoUpdateConfig `json:"autoUpdate,omitempty"`
	AdditionalFiles          []string          `json:"additionalFiles,omitempty"`
}

type StackUpdateRequest struct {
	Env                      []EnvVar `json:"env,omitempty"`
	Prune                    bool     `json:"prune"`
	PullImage                bool     `json:"pullImage"`
	StackFileContent         string   `json:"stackFileContent,omitempty"`
	RepositoryReferenceName  string   `json:"repositoryReferenceName,omitempty"`
	RepositoryAuthentication bool     `json:"repositoryAuthentication,omitempty"`
	RepositoryUsername       string   `json:"repositoryUsername,omitempty"`
	RepositoryPassword       string   `json:"repositoryPassword,omitempty"`
}

type Team struct {
	ID   int    `json:"Id"`
	Name string `json:"Name"`
}
type SwarmInfo struct {
	ID string `json:"ID"`
}

func getSwarmID(baseURL, authKey, authVal string, endpointID int) (string, error) {
	url := fmt.Sprintf("%s/endpoints/%d/docker/swarm", baseURL, endpointID)
	resp, err := doRequest("GET", url, authKey, authVal, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("fetching SwarmID failed: %s", string(b))
	}

	var info SwarmInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", err
	}
	return info.ID, nil
}
func main() {
	root := &cobra.Command{
		Use:   "portainer-deploy",
		Short: "Deploy/update Portainer stacks (swarm) with access control",
		Run:   run,
	}

	// connection
	root.Flags().StringVar(&portainerUrl, "portainer-url", "", "Portainer host (host:port or hostname). Required")
	root.Flags().BoolVar(&useHTTPS, "use-https", true, "Use https to connect to Portainer")
	root.Flags().StringVar(&apiKey, "api-key", "", "Portainer API key (X-API-Key). If not provided, username+password will be used")
	root.Flags().StringVar(&username, "username", "", "Portainer username (used when api-key not provided)")
	root.Flags().StringVar(&password, "password", "", "Portainer password (used when api-key not provided)")

	// stack & deployment
	root.Flags().StringVar(&stackName, "stack-name", "", "Stack name to create/update. Required")
	root.Flags().StringVar(&deploymentMethod, "deployment-method", "repository", "Deployment method: repository | string")
	root.Flags().StringVar(&repositoryURL, "repository-url", "", "Repository URL (for repository mode)")
	root.Flags().StringVar(&repositoryRef, "repository-reference", "refs/heads/main", "Repository ref (branch/tag). Default: refs/heads/main")
	root.Flags().StringVar(&repositoryUser, "repository-username", "", "Repository username (if private)")
	root.Flags().StringVar(&repositoryPass, "repository-password", "", "Repository password (if private)")
	root.Flags().StringVar(&composeFilePath, "compose-file-path", "docker-compose.yml", "Compose file path in repository (repository mode)")
	root.Flags().StringVar(&stackFile, "stack-file", "docker-compose.yml", "Local stack file to use for string mode")

	// endpoint
	root.Flags().StringVar(&endpointName, "endpoint-name", "local", "Endpoint name to deploy to (auto-detected)")

	// extras
	root.Flags().StringVar(&envVarsJSON, "environment-variables", "[]", "JSON array of environment variables, e.g. '[{\"name\":\"FOO\",\"value\":\"bar\"}]'")
	root.Flags().StringVar(
    	&envFile,
    	"env-file",
    	"",
    	"Path to .env file (used if --environment-variables is empty)",
    )
	root.Flags().BoolVar(&prune, "prune", false, "Prune unused services on update")
	root.Flags().BoolVar(&pullImage, "pull-image", true, "Pull latest images on update")
	root.Flags().BoolVar(&autoUpdate, "auto-update", false, "Enable auto-update for repository stacks")
	root.Flags().StringVar(&autoUpdateInterval, "auto-update-interval", "5m", "Auto-update interval (e.g. 5m)")

	// access control
	root.Flags().StringVar(&accessMode, "access", "admin", "Access: public | teams | admin")
	root.Flags().StringVar(&teamName, "teams", "", "Teams name (used when --access=teams)")

	root.Flags().StringArrayVar(&additionalFiles, "additional-files", nil, "Additional compose override files (paths in repository)")
	if err := root.Execute(); err != nil {
		log.Fatal(err)
	}
}
func parseEnvFile(path string) ([]EnvVar, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var envs []EnvVar
	lines := strings.Split(string(data), "\n")

	for i, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// optional: allow "export KEY=value"
		line = strings.TrimPrefix(line, "export ")

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid env line %d: %s", i+1, line)
		}

		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		// strip quotes
		val = strings.Trim(val, `"'`)

		envs = append(envs, EnvVar{
			Name:  key,
			Value: val,
		})
	}

	return envs, nil
}

func run(cmd *cobra.Command, args []string) {
	if portainerUrl == "" || stackName == "" {
		log.Fatal("required flags: --portainer-url and --stack-name")
	}

	baseURL := fmt.Sprintf("%s/api", portainerUrl)

	// auth - choose API key if provided else username/password
	var authHeaderKey, authHeaderValue string
	if apiKey != "" {
		authHeaderKey = "X-API-Key"
		authHeaderValue = apiKey
	} else {
		if username == "" || password == "" {
			log.Fatal("either --api-key or --username AND --password must be provided")
		}
		jwt, err := login(baseURL, username, password)
		if err != nil {
			log.Fatalf("login failed: %v", err)
		}
		authHeaderKey = "Authorization"
		authHeaderValue = "Bearer " + jwt
	}

    var envVars []EnvVar

    jsonProvided := strings.TrimSpace(envVarsJSON) != "" && strings.TrimSpace(envVarsJSON) != "[]"

    switch {
    case jsonProvided:
        if err := json.Unmarshal([]byte(envVarsJSON), &envVars); err != nil {
            log.Fatalf("❌ invalid --environment-variables JSON: %v", err)
        }
        log.Printf("Loaded %d env vars from JSON\n", len(envVars))

    case envFile != "":
        var err error
        envVars, err = parseEnvFile(envFile)
        if err != nil {
            log.Fatalf("❌ cannot parse env-file '%s': %v", envFile, err)
        }
        log.Printf("Loaded %d env vars from env-file %s\n", len(envVars), envFile)

    default:
        log.Printf("No environment variables provided\n")
    }

	// find endpoint id by name
	endpointID, err := findEndpointID(baseURL, authHeaderKey, authHeaderValue, endpointName)
	if err != nil {
		log.Fatalf("cannot resolve endpoint '%s': %v", endpointName, err)
	}
	log.Printf("Using endpointId=%d (%s)\n", endpointID, endpointName)

	// check if stack exists
	stackID, found, err := findStack(baseURL, authHeaderKey, authHeaderValue, stackName)
	if err != nil {
		log.Fatalf("failed to list stacks: %v", err)
	}

	if deploymentMethod == "repository" {
		if repositoryURL == "" {
			log.Fatal("repository-mode requires --repository-url")
		}
		if found {
			log.Printf("Updating existing stack (git) id=%d\n", stackID)
			if err := updateStackGit(baseURL, authHeaderKey, authHeaderValue, stackID, endpointID, envVars, prune, pullImage); err != nil {
				log.Fatalf("update failed: %v", err)
			}
		} else {
			log.Printf("Creating stack from repository...\n")
			id, err := createStackGit(baseURL, authHeaderKey, authHeaderValue, endpointID, envVars)
			if err != nil {
				log.Fatalf("create failed: %v", err)
			}
			stackID = id
		}
	} else {
		// string mode
		content, err := os.ReadFile(stackFile)
		if err != nil {
			log.Fatalf("cannot read stack file '%s': %v", stackFile, err)
		}
		if found {
			log.Printf("Updating existing stack (string) id=%d\n", stackID)
			if err := updateStackString(baseURL, authHeaderKey, authHeaderValue, stackID, endpointID, string(content), envVars); err != nil {
				log.Fatalf("update failed: %v", err)
			}
		} else {
			log.Printf("Creating stack from content (string)...\n")
			id, err := createStackString(baseURL, authHeaderKey, authHeaderValue, endpointID, string(content), envVars)
			if err != nil {
				log.Fatalf("create failed: %v", err)
			}
			stackID = id
		}
	}

	// give Portainer a small moment
	time.Sleep(2 * time.Second)

	// rozdziela nazwy zespołów po przecinku i usuwa ewentualne spacje
	teamNames := []string{}
	for _, t := range strings.Split(teamName, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			teamNames = append(teamNames, t)
		}
	}

	// wywołanie funkcji
	if err := setStackAccess(baseURL, authHeaderKey, authHeaderValue, stackID, accessMode, teamNames); err != nil {
		log.Printf("⚠️ cannot set access: %v", err)
	} else {
		log.Printf("Access set: %s\n", accessMode)
	}

	fmt.Printf("Done. stack id: %d\n", stackID)
}

// -------------------- helpers & API calls --------------------

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

// login username/password -> jwt
func login(baseURL, user, pass string) (string, error) {
	// Some Portainer versions expect lowercase keys; try common payload
	jb, _ := json.Marshal(map[string]string{"Username": user, "Password": pass})
	req, _ := http.NewRequest("POST", baseURL+"/auth", bytes.NewReader(jb))
	req.Header.Set("Content-Type", "application/json")
	fmt.Println(map[string]string{"Username": user, "Password": pass})
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("auth failed: %s", string(b))
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	// common field names: jwt or jwt_token or token
	if v, ok := out["jwt"].(string); ok && v != "" {
		return v, nil
	}
	if v, ok := out["token"].(string); ok && v != "" {
		return v, nil
	}
	// sometimes returned in "jwt" under nested object
	if data, ok := out["data"].(map[string]any); ok {
		if v, ok := data["jwt"].(string); ok && v != "" {
			return v, nil
		}
	}
	return "", fmt.Errorf("no token in auth response")
}

// unified request helper (sets auth header)
func doRequest(method, url, authHeaderKey, authHeaderValue string, body interface{}) (*http.Response, error) {
	var rb io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rb = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rb)
	if err != nil {
		return nil, err
	}
	if authHeaderKey != "" && authHeaderValue != "" {
		req.Header.Set(authHeaderKey, authHeaderValue)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return httpClient.Do(req)
}

// find endpoint id by name
func findEndpointID(baseURL, authKey, authVal, endpointName string) (int, error) {
	params := url.Values{}
	params.Set("start", "1")
	params.Set("limit", "10")
	params.Set("order", "asc")
	params.Set("search", endpointName)
	params.Set("excludeSnapshotRaw", "true")

	reqURL := baseURL + "/endpoints?" + params.Encode()

	resp, err := doRequest("GET", reqURL, authKey, authVal, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("list endpoints failed: %s", string(b))
	}

	var endpoints []struct {
		ID   int    `json:"Id"`
		Name string `json:"Name"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&endpoints); err != nil {
		return 0, err
	}

	if len(endpoints) == 0 {
		return 0, fmt.Errorf("endpoint '%s' not found", endpointName)
	}

	return endpoints[0].ID, nil
}


// list stacks and find by name
func findStack(baseURL, authKey, authVal, name string) (int, bool, error) {
	resp, err := doRequest("GET", baseURL+"/stacks", authKey, authVal, nil)
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return 0, false, fmt.Errorf("list stacks failed: %s", string(b))
	}
	var stacks []Stack
	if err := json.NewDecoder(resp.Body).Decode(&stacks); err != nil {
		return 0, false, err
	}
	for _, s := range stacks {
		if s.Name == name {
			return s.ID, true, nil
		}
	}
	return 0, false, nil
}

// create stack from git repository (swarm)
func createStackGit(baseURL, authKey, authVal string, endpointID int, env []EnvVar) (int, error) {
	swarmID, err := getSwarmID(baseURL, authKey, authVal, endpointID)
	if err != nil {
		log.Fatalf("cannot get SwarmID: %v", err)
	}
	req := StackCreateRequest{
		Name:                    stackName,
		RepositoryURL:           repositoryURL,
		RepositoryReferenceName: repositoryRef,
		ComposeFile:             composeFilePath,
		Env:                     env,
		SwarmID:                 swarmID,
		AdditionalFiles:         additionalFiles,
	}
	fmt.Println(req)
	if repositoryUser != "" && repositoryPass != "" {
		req.RepositoryAuthentication = true
		req.RepositoryUsername = repositoryUser
		req.RepositoryPassword = repositoryPass
	}
	if autoUpdate {
		req.AutoUpdate = &AutoUpdateConfig{Interval: autoUpdateInterval}
	}
	url := fmt.Sprintf("%s/stacks/create/swarm/repository?endpointId=%d", baseURL, endpointID)
	fmt.Println(url)
	resp, err := doRequest("POST", url, authKey, authVal, req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("create stack (git) failed: %s", string(b))
	}
	var created Stack
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return 0, err
	}
	return created.ID, nil
}

// update stack from git (trigger git update)
func updateStackGit(baseURL, authKey, authVal string, stackID int, endpointID int, env []EnvVar, prune, pull bool) error {
	req := StackUpdateRequest{
		Env:       env,
		Prune:     prune,
		PullImage: pull,
	}
	if repositoryUser != "" && repositoryPass != "" {
		req.RepositoryAuthentication = true
		req.RepositoryUsername = repositoryUser
		req.RepositoryPassword = repositoryPass
	}
	url := fmt.Sprintf("%s/stacks/%d/git/redeploy?endpointId=%d", baseURL, stackID, endpointID)
	resp, err := doRequest("PUT", url, authKey, authVal, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update stack (git) failed: %s", string(b))
	}
	return nil
}

// create stack from string content (swarm)
func createStackString(baseURL, authKey, authVal string, endpointID int, content string, env []EnvVar) (int, error) {
	swarmID, err := getSwarmID(baseURL, authKey, authVal, endpointID)
	if err != nil {
		log.Fatalf("cannot get SwarmID: %v", err)
	}
	req := StackCreateRequest{
		Name:             stackName,
		StackFileContent: content,
		Env:              env,
		SwarmID:          swarmID,
	}
	url := fmt.Sprintf("%s/stacks/create/swarm/string?endpointId=%d", baseURL, endpointID)
	resp, err := doRequest("POST", url, authKey, authVal, req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("create stack (string) failed: %s", string(b))
	}
	var created Stack
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return 0, err
	}
	return created.ID, nil
}

// update stack from string (swarm)
func updateStackString(baseURL, authKey, authVal string, stackID, endpointID int, content string, env []EnvVar) error {
	req := StackUpdateRequest{
		StackFileContent: content,
		Env:              env,
		Prune:            prune,
		PullImage:        pullImage,
	}
	url := fmt.Sprintf("%s/stacks/%d?endpointId=%d", baseURL, stackID, endpointID)
	resp, err := doRequest("PUT", url, authKey, authVal, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update stack (string) failed: %s", string(b))
	}
	return nil
}

// resolve team name -> id
func resolveTeamID(baseURL, authKey, authVal, tName string) (int, error) {
	resp, err := doRequest("GET", baseURL+"/teams", authKey, authVal, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("list teams failed: %s", string(b))
	}
	var teams []Team
	if err := json.NewDecoder(resp.Body).Decode(&teams); err != nil {
		return 0, err
	}
	for _, t := range teams {
		if t.Name == tName {
			return t.ID, nil
		}
	}
	return 0, fmt.Errorf("team '%s' not found", tName)
}

type ResourceControl struct {
	ID    int `json:"Id"`
	Teams []struct {
		TeamID int `json:"TeamID"`
		Role   int `json:"Role"`
	} `json:"Teams"`
	Public bool `json:"Public"`
}

type ResourceControlTeam struct {
	TeamID int `json:"TeamID"`
	Role   int `json:"Role"` // 1 = member, 2 = admin
}

type ResourceControlPayload struct {
	Public             bool  `json:"Public"`
	Teams              []int `json:"Teams,omitempty"`
	Users              []int `json:"Users,omitempty"`
	AdministratorsOnly bool  `json:"AdministratorsOnly,omitempty"`
}

func setStackAccess(baseURL, authKey, authVal string, stackID int, accessMode string, teamNames []string) error {
	// 1️⃣ Pobierz stack, żeby dostać ResourceControl.Id
	stackURL := fmt.Sprintf("%s/stacks/%d", baseURL, stackID)
	resp, err := doRequest("GET", stackURL, authKey, authVal, nil)
	if err != nil {
		return fmt.Errorf("stack info request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("stack info failed: %s", string(b))
	}

	var stackResp struct {
		ResourceControl struct {
			ID int `json:"Id"`
		} `json:"ResourceControl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&stackResp); err != nil {
		return fmt.Errorf("cannot parse stack info: %v", err)
	}
	rcID := stackResp.ResourceControl.ID

	// 2️⃣ Przygotuj Teams payload
	// Change: Now it's an array of Team IDs (int)
	teamIDs := []int{}
	if accessMode == "teams" {
		for _, name := range teamNames {
			if name == "" {
				continue
			}
			id, err := resolveTeamID(baseURL, authKey, authVal, name)
			if err != nil {
				return fmt.Errorf("cannot resolve teams '%s': %v", name, err)
			}
			// Change: Append the ID directly
			teamIDs = append(teamIDs, id)
		}
	}

	payload := ResourceControlPayload{
		Public:             accessMode == "public",
		Teams:              teamIDs, // <--- Use the array of IDs
		Users:              []int{},
		AdministratorsOnly: accessMode == "admin",
	}
	// 3️⃣ PUT ResourceControl
	rcURL := fmt.Sprintf("%s/resource_controls/%d", baseURL, rcID)
	resp, err = doRequest("PUT", rcURL, authKey, authVal, payload)
	if err != nil {
		return fmt.Errorf("update resource control failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("PUT resource control failed: %s", string(b))
	}

	return nil
}

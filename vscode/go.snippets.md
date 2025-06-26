# Go Web API & Cloud Services Cheat Sheet

## Basic Web Server Setup

### Simple HTTP Server

```go
package main

import (
    "fmt"
    "log"
    "net/http"
)

func main() {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "Hello, World!")
    })

    log.Println("Server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

### Using Gorilla Mux Router

```go
import "github.com/gorilla/mux"

r := mux.NewRouter()
r.HandleFunc("/api/users/{id}", getUserHandler).Methods("GET")
r.HandleFunc("/api/users", createUserHandler).Methods("POST")
http.ListenAndServe(":8080", r)
```

### Using Gin Framework

```go
import "github.com/gin-gonic/gin"

r := gin.Default()
r.GET("/api/users/:id", getUserHandler)
r.POST("/api/users", createUserHandler)
r.Run(":8080")
```

## JSON Handling

### JSON Marshaling/Unmarshaling

```go
type User struct {
    ID    int    `json:"id"`
    Name  string `json:"name"`
    Email string `json:"email"`
}

// Marshal to JSON
user := User{ID: 1, Name: "John", Email: "john@example.com"}
jsonData, err := json.Marshal(user)

// Unmarshal from JSON
var user User
err := json.Unmarshal(jsonData, &user)

// Direct response encoding
func handler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(user)
}
```

## HTTP Client Requests

### Basic GET Request

```go
resp, err := http.Get("https://api.example.com/users")
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()

body, err := io.ReadAll(resp.Body)
```

### POST Request with JSON

```go
user := User{Name: "John", Email: "john@example.com"}
jsonData, _ := json.Marshal(user)

resp, err := http.Post("https://api.example.com/users",
    "application/json", bytes.NewBuffer(jsonData))
```

### Custom HTTP Client

```go
client := &http.Client{
    Timeout: 30 * time.Second,
}

req, _ := http.NewRequest("GET", "https://api.example.com/users", nil)
req.Header.Set("Authorization", "Bearer "+token)
req.Header.Set("Content-Type", "application/json")

resp, err := client.Do(req)
```

## Middleware

### Basic Middleware

```go
func loggingMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        log.Printf("%s %s", r.Method, r.URL.Path)
        next.ServeHTTP(w, r)
    })
}

// Usage
http.Handle("/", loggingMiddleware(http.HandlerFunc(handler)))
```

### CORS Middleware

```go
func corsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "*")
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

        if r.Method == "OPTIONS" {
            return
        }

        next.ServeHTTP(w, r)
    })
}
```

## AWS SDK v2

### AWS Configuration

```go
import (
    "context"
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/s3"
    "github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

// Load AWS config
cfg, err := config.LoadDefaultConfig(context.TODO(),
    config.WithRegion("us-west-2"),
)
```

### S3 Operations

```go
// Create S3 client
s3Client := s3.NewFromConfig(cfg)

// Upload file
_, err = s3Client.PutObject(context.TODO(), &s3.PutObjectInput{
    Bucket: aws.String("my-bucket"),
    Key:    aws.String("file.txt"),
    Body:   strings.NewReader("Hello, S3!"),
})

// Download file
result, err := s3Client.GetObject(context.TODO(), &s3.GetObjectInput{
    Bucket: aws.String("my-bucket"),
    Key:    aws.String("file.txt"),
})
defer result.Body.Close()

// List objects
listResult, err := s3Client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
    Bucket: aws.String("my-bucket"),
})
```

### DynamoDB Operations

```go
// Create DynamoDB client
dynamoClient := dynamodb.NewFromConfig(cfg)

// Put item
_, err = dynamoClient.PutItem(context.TODO(), &dynamodb.PutItemInput{
    TableName: aws.String("Users"),
    Item: map[string]types.AttributeValue{
        "id":    &types.AttributeValueMemberS{Value: "123"},
        "name":  &types.AttributeValueMemberS{Value: "John"},
        "email": &types.AttributeValueMemberS{Value: "john@example.com"},
    },
})

// Get item
result, err := dynamoClient.GetItem(context.TODO(), &dynamodb.GetItemInput{
    TableName: aws.String("Users"),
    Key: map[string]types.AttributeValue{
        "id": &types.AttributeValueMemberS{Value: "123"},
    },
})
```

### Lambda Function

```go
import (
    "context"
    "github.com/aws/aws-lambda-go/events"
    "github.com/aws/aws-lambda-go/lambda"
)

func handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
    return events.APIGatewayProxyResponse{
        StatusCode: 200,
        Body:       `{"message": "Hello from Lambda!"}`,
        Headers: map[string]string{
            "Content-Type": "application/json",
        },
    }, nil
}

func main() {
    lambda.Start(handler)
}
```

## Azure SDK

### Azure Configuration

```go
import (
    "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
    "github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
    "github.com/Azure/azure-sdk-for-go/sdk/data/aztables"
)

// Create credential
cred, err := azidentity.NewDefaultAzureCredential(nil)
```

### Azure Blob Storage

```go
// Create blob client
client, err := azblob.NewClient("https://myaccount.blob.core.windows.net/", cred, nil)

// Upload blob
_, err = client.UploadStream(context.TODO(), "container", "blob.txt",
    strings.NewReader("Hello, Azure!"), nil)

// Download blob
downloadResponse, err := client.DownloadStream(context.TODO(), "container", "blob.txt", nil)
defer downloadResponse.Body.Close()
```

### Azure Table Storage

```go
// Create table client
serviceClient, err := aztables.NewServiceClient("https://myaccount.table.core.windows.net/", cred, nil)
client := serviceClient.NewClient("mytable")

// Add entity
entity := map[string]interface{}{
    "PartitionKey": "partition1",
    "RowKey":      "row1",
    "Name":        "John",
    "Email":       "john@example.com",
}

_, err = client.AddEntity(context.TODO(), entity, nil)
```

### Azure Functions

```go
import (
    "context"
    "encoding/json"
    "net/http"
    "os"
)

func handler(w http.ResponseWriter, r *http.Request) {
    response := map[string]string{
        "message": "Hello from Azure Functions!",
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func main() {
    http.HandleFunc("/api/hello", handler)
    port := os.Getenv("FUNCTIONS_CUSTOMHANDLER_PORT")
    if port == "" {
        port = "8080"
    }
    http.ListenAndServe(":"+port, nil)
}
```

## Database Operations

### PostgreSQL with pgx

```go
import "github.com/jackc/pgx/v5/pgxpool"

// Create connection pool
pool, err := pgxpool.New(context.Background(), "postgres://user:password@localhost/dbname")
defer pool.Close()

// Query single row
var name string
err = pool.QueryRow(context.Background(), "SELECT name FROM users WHERE id = $1", 1).Scan(&name)

// Query multiple rows
rows, err := pool.Query(context.Background(), "SELECT id, name FROM users")
defer rows.Close()

for rows.Next() {
    var id int
    var name string
    err := rows.Scan(&id, &name)
    // Process row
}
```

### MongoDB

```go
import "go.mongodb.org/mongo-driver/mongo"

// Create client
client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI("mongodb://localhost:27017"))
collection := client.Database("mydb").Collection("users")

// Insert document
_, err = collection.InsertOne(context.TODO(), bson.M{
    "name":  "John",
    "email": "john@example.com",
})

// Find document
var result bson.M
err = collection.FindOne(context.TODO(), bson.M{"name": "John"}).Decode(&result)
```

## Environment Variables & Configuration

### Using godotenv

```go
import "github.com/joho/godotenv"

func init() {
    err := godotenv.Load()
    if err != nil {
        log.Fatal("Error loading .env file")
    }
}

// Usage
dbURL := os.Getenv("DATABASE_URL")
port := os.Getenv("PORT")
```

### Configuration Struct

```go
type Config struct {
    Port        string `env:"PORT" default:"8080"`
    DatabaseURL string `env:"DATABASE_URL" required:"true"`
    AWSRegion   string `env:"AWS_REGION" default:"us-west-2"`
}

func loadConfig() (*Config, error) {
    cfg := &Config{}
    if err := env.Parse(cfg); err != nil {
        return nil, err
    }
    return cfg, nil
}
```

## Error Handling & Logging

### Custom Error Types

```go
type APIError struct {
    Code    int    `json:"code"`
    Message string `json:"message"`
}

func (e APIError) Error() string {
    return e.Message
}

func errorHandler(w http.ResponseWriter, r *http.Request, err error) {
    var apiErr APIError
    if errors.As(err, &apiErr) {
        w.WriteHeader(apiErr.Code)
        json.NewEncoder(w).Encode(apiErr)
    } else {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(APIError{
            Code:    500,
            Message: "Internal server error",
        })
    }
}
```

### Structured Logging with slog

```go
import "log/slog"

// JSON logger
logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

// Usage
logger.Info("User created",
    slog.String("user_id", "123"),
    slog.String("email", "john@example.com"),
)

logger.Error("Database connection failed",
    slog.String("error", err.Error()),
)
```

## Testing

### HTTP Handler Testing

```go
func TestHandler(t *testing.T) {
    req := httptest.NewRequest("GET", "/api/users/123", nil)
    w := httptest.NewRecorder()

    handler(w, req)

    resp := w.Result()
    if resp.StatusCode != http.StatusOK {
        t.Errorf("Expected status 200, got %d", resp.StatusCode)
    }

    body, _ := io.ReadAll(resp.Body)
    // Assert response body
}
```

### Mock HTTP Server

```go
func TestAPICall(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte(`{"id": 1, "name": "John"}`))
    }))
    defer server.Close()

    // Use server.URL in your HTTP client
    resp, err := http.Get(server.URL + "/users/1")
    // Test the response
}
```

## Common Patterns

### Rate Limiting

```go
import "golang.org/x/time/rate"

var limiter = rate.NewLimiter(10, 1) // 10 requests per second, burst of 1

func rateLimitMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !limiter.Allow() {
            http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
            return
        }
        next.ServeHTTP(w, r)
    })
}
```

### JWT Authentication

```go
import "github.com/golang-jwt/jwt/v5"

func generateJWT(userID string) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "user_id": userID,
        "exp":     time.Now().Add(time.Hour * 24).Unix(),
    })

    return token.SignedString([]byte("secret"))
}

func validateJWT(tokenString string) (*jwt.Token, error) {
    return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        return []byte("secret"), nil
    })
}
```

### Graceful Shutdown

```go
func main() {
    srv := &http.Server{
        Addr:    ":8080",
        Handler: router,
    }

    go func() {
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatalf("listen: %s\n", err)
        }
    }()

    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    if err := srv.Shutdown(ctx); err != nil {
        log.Fatal("Server forced to shutdown:", err)
    }
}
```

## Useful Go Modules

```bash
# Web frameworks
go get github.com/gin-gonic/gin
go get github.com/gorilla/mux
go get github.com/labstack/echo/v4

# AWS SDK
go get github.com/aws/aws-sdk-go-v2/config
go get github.com/aws/aws-sdk-go-v2/service/s3
go get github.com/aws/aws-sdk-go-v2/service/dynamodb

# Azure SDK
go get github.com/Azure/azure-sdk-for-go/sdk/azidentity
go get github.com/Azure/azure-sdk-for-go/sdk/storage/azblob

# Database drivers
go get github.com/jackc/pgx/v5/pgxpool
go get go.mongodb.org/mongo-driver/mongo

# Utilities
go get github.com/joho/godotenv
go get github.com/golang-jwt/jwt/v5
go get golang.org/x/time/rate
```

## Environment Setup Tips

1. **VS Code Extensions**: Install Go extension pack
2. **Go modules**: Always use `go mod init` for new projects
3. **Air for hot reload**: `go install github.com/cosmtrek/air@latest`
4. **Delve debugger**: Built into VS Code Go extension
5. **gopls**: Language server (auto-installed with VS Code extension)

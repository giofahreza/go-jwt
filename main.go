package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"github.com/julienschmidt/httprouter"
)

func main() {
	// Load environment variables from .env file
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Retrieve the environment variable
	apiKey := os.Getenv("JWT_SECRET_KEY")
	if apiKey == "" {
		log.Fatal("JWT_SECRET_KEY) is not set in the .env file")
	}

	fmt.Println("JWT_SECRET_KEY:", apiKey)

	// Initialize the router
	router := httprouter.New()

	// Wrap the router with the logging middleware
	loggedRouter := logging(router)

	// Define your routes here
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintln(w, "Welcome to the API!")
	})

	router.POST("/login", login)

	router.POST("/dashboard", authentication(dashboard))

	router.POST("/user/all", authorization(authentication(getUser)))

	log.Fatal(http.ListenAndServe(":8080", loggedRouter))
}

func logging(router http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		router.ServeHTTP(w, r)
		log.Printf("Request: %s %s took %v", r.Method, r.URL.Path, time.Since(start))
	})
}

func authorization(next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// Check for authorization here
		// For example, check if the user has the required role to access the resource
		// Get DB
		// if authorized {
		// 	http.Error(w, "Forbidden", http.StatusForbidden)
		// 	return
		// }

		log.Print("Authorization middleware")
		// Call the next handler if authorized
		next(w, r, ps)
	}
}

func authentication(next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// Validate JWT token here
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		log.Println("Token:", token)

		// Parse the token
		parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			// Validate the token signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			// Return the secret key for validation

			return []byte(os.Getenv("JWT_SECRET_KEY")), nil
		})
		if err != nil {
			log.Println("Error parsing token:", err)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		log.Print("Authentication middleware")
		// Call the next handler if authenticated
		next(w, r, ps)
	}
}

func login(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	// Handle login logic here
	// For example, validate user credentials and generate JWT token
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Success
	if username == "admin" && password == "admin" {
		fmt.Fprintln(w, "Login successful!")

		// Generate JWT token and send it in the response
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": username,
			"exp":      jwt.TimeFunc().Add(time.Hour * 24).Unix(),
		})

		// Sign the token with your secret key
		jwtSecret := os.Getenv("JWT_SECRET_KEY")
		tokenstring, err := token.SignedString([]byte(jwtSecret))
		if err != nil {
			http.Error(w, "Error signing token", http.StatusInternalServerError)
			return
		}

		w.Write([]byte(tokenstring))

		return
	}

	http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	return
}

func dashboard(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	fmt.Fprintln(w, "Welcome to the dashboard!")
}

func getUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	fmt.Fprintln(w, "User information retrieved successfully!")
}

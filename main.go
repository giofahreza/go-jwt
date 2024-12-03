package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"github.com/julienschmidt/httprouter"
)

func main() {
	// Get env
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
	}

	// Get env by key
	fmt.Println("JWT Secret :", os.Getenv("JWT_SECRET"))

	// Create a new router
	router := httprouter.New()

	newrouter := logging(router)

	// Landing endpoint
	router.GET("/", welcome)

	// Login endpoint
	router.POST("/login", login)

	// Dashboard endpoint
	router.POST("/dashboard", authentication(dashboard))

	// Get all user endpoint
	router.POST("/user/all", authentication(authorization(getUser)))

	fmt.Println("Server running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", newrouter))
}

func logging(router http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// log.Println("Masuk pak eko")
		router.ServeHTTP(w, r)
	})
}

func authorization(next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// Check authorization
		// if authorized
		// next(w, r, ps)
		// else
		// w.WriteHeader(http.StatusUnauthorized)
		// w.Write([]byte("Unauthorized"))
		log.Print("Authorization")
		next(w, r, ps)
	}
}

func authentication(next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			log.Print("Token not found")
			return
		}

		// remove bearer from token
		tokenString = strings.Replace(tokenString, "Bearer ", "", 1)

		log.Print(os.Getenv("JWT_SECRET"))

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Unauthorized"))
				log.Print("Wrong token")
				return nil, fmt.Errorf("There was an error")
			}

			return []byte(os.Getenv("JWT_SECRET")), nil
		})

		if err == nil && token.Valid {
			next(w, r, ps)
		} else {
			log.Print(err)
			log.Print(token.Valid)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			log.Print("Token not valid")
			return
		}

		next(w, r, ps)
	}
}

// ------------------------------------------------------------------------------------

func welcome(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	w.Write([]byte("Welcome"))
}

func login(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	log.Println("Username :", username)
	log.Println("Password :", password)

	if username == "admin" && password == "admin" {
		// Create a new token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": username,
			"exp":      time.Now().Add(time.Hour * 24).Unix(),
		})

		log.Print(os.Getenv("JWT_SECRET"))

		// Sign the token with our secret
		tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))

		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Write([]byte(tokenString))
		return
	}

	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte("Wrong username or password"))
}

func dashboard(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	w.Write([]byte("Dashboard"))
}

func getUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	user := map[string]string{
		"username": "admin",
		"email":    "asd@mail.com",
	}

	w.Write([]byte(user["username"]))
}

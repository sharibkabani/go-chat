package main

import (
    "fmt"
    "log"
    "net/http"
    "go_chat/db"
    "go_chat/api"

    "github.com/gorilla/mux"
)

func main() {
    database, err := db.ConnectDB()
    if err != nil {
        log.Fatalf("Could not connect to database: %v", err)
    }
    defer database.Close()

    fmt.Println("Database connection initialized successfully!")

    handler := api.NewHandler(database)

    r := mux.NewRouter()
    r.HandleFunc("/users", handler.CreateUser).Methods("POST")
    r.HandleFunc("/users/{id}", handler.GetUser).Methods("GET")
    r.HandleFunc("/users/{id}", handler.UpdateUser).Methods("PUT")
    r.HandleFunc("/users/{id}", handler.DeleteUser).Methods("DELETE")
    r.HandleFunc("/login", handler.Login).Methods("POST")

    // Protect routes with JWT middleware
    r.Use(handler.AuthMiddleware)

    http.Handle("/", r)
    log.Fatal(http.ListenAndServe(":8080", nil))
}
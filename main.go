package main

import (
	"fmt"
	"log"
	"database/db"
)

func main() {
	// Initialize the database connection
	database, err := db.ConnectDB()
	if err != nil {
		log.Fatalf("Could not connect to database: %v", err)
	}
	defer database.Close()

	fmt.Println("Database connection initialized successfully!")
	// Proceed with the rest of your application
}

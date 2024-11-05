package db

import (
    "database/sql"
    "fmt"
    "log"
    "os"

    "github.com/joho/godotenv"
    _ "github.com/jackc/pgx/v5/stdlib" // Import the pgx driver
)

// ConnectDB initializes and returns a PostgreSQL database connection
func ConnectDB() (*sql.DB, error) {
    // Load environment variables
    if err := godotenv.Load(); err != nil {
        log.Printf("Error loading .env file: %v\n", err)
    }

    // Set up the connection string using environment variables
    connStr := fmt.Sprintf("postgres://%s:%s@%s:%s/%s",
        os.Getenv("DB_USER"),
        os.Getenv("DB_PASSWORD"),
        os.Getenv("DB_HOST"),
        os.Getenv("DB_PORT"),
        os.Getenv("DB_NAME"),
    )

    // Open the database connection using the pgx driver
    db, err := sql.Open("pgx", connStr)
    if err != nil {
        return nil, err
    }

    return db, nil
}


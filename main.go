package main

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID        string `json:"id"`
	IPAddress string `json:"ip_address"`
	Email     string `json:"email"`
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

var db *sql.DB

func main() {
	godotenv.Load()
	db, err := sql.Open("postgres", "user=myuser password=mypassword dbname=mydb sslmode=disable")
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	r := gin.Default()
	r.POST("/login", getTokens)
	r.POST("/refresh", refreshTokens)
	r.Run()
}

func getTokens(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	accessToken, refreshToken, err := generateTokens(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

func refreshTokens(c *gin.Context) {
	var tokenPair TokenPair
	if err := c.ShouldBindJSON(&tokenPair); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	claims, err := verifyRefreshToken(tokenPair.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	user := User{
		ID:        claims["id"].(string),
		IPAddress: claims["ip_address"].(string),
		Email:     claims["email"].(string),
	}

	newAccessToken, newRefreshToken, err := generateTokens(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if claims["ip_address"] != user.IPAddress {
		go sendIPWarningEmail(user.Email)
	}

	c.JSON(http.StatusOK, TokenPair{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	})
}

func generateTokens(user User) (string, string, error) {
	accessToken, err := generateAccessToken(user)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := generateRefreshToken(user)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func generateAccessToken(user User) (string, error) {
	claims := jwt.MapClaims{
		"id":         user.ID,
		"ip_address": user.IPAddress,
		"exp":        time.Now().Add(15 * time.Minute).Unix(),
		"email":      user.Email,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}

func generateRefreshToken(user User) (string, error) {
	refreshToken := base64.StdEncoding.EncodeToString([]byte(user.ID + "/" + user.IPAddress + "/" + user.Email))
	hash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	if err := storeRefreshTokenHash(user.ID, string(hash)); err != nil {
		return "", err
	}

	return refreshToken, nil
}

func verifyRefreshToken(refreshToken string) (jwt.MapClaims, error) {
	userId, ipAddress, email, err := parseRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	hash, err := getRefreshTokenHash(userId)
	if err != nil {
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(refreshToken)); err != nil {
		return nil, err
	}

	return jwt.MapClaims{
		"id":         userId,
		"ip_address": ipAddress,
		"email":      email,
	}, nil
}

func parseRefreshToken(refreshToken string) (string, string, string, error) {
	decodedToken, err := base64.StdEncoding.DecodeString(refreshToken)
	if err != nil {
		return "", "", "", err
	}

	parts := strings.Split(string(decodedToken), "/")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid refresh token format")
	}

	return parts[0], parts[1], parts[2], nil
}

func storeRefreshTokenHash(userId, hash string) error {
	_, err := db.Exec("INSERT INTO refresh_tokens (user_id, hash) VALUES ($1, $2)", userId, hash)
	return err
}

func getRefreshTokenHash(userId string) (string, error) {
	var hash string
	err := db.QueryRow("SELECT hash FROM refresh_tokens WHERE user_id = $1", userId).Scan(&hash)
	return hash, err
}

func sendIPWarningEmail(email string) {
	// mock
	log.Printf("Sending IP warning email to %s", email)
}

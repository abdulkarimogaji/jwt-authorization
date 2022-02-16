package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Abdoolkareem/utils"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var secretKey = []byte("MynameisAbdulkarim")

type DB struct {
	db *sql.DB
}

type TokenResponse struct {
	Token  string `json:"token"`
	Status string `json:"status"`
}

type htmlData struct {
	ButtonMessage string
	FormHeader    string
}

func loginPage(c *gin.Context) {
	a := htmlData{"Login", "Login Here"}
	c.HTML(http.StatusOK, "login.html", a)
}

func signupPage(c *gin.Context) {
	a := htmlData{"Signup", "Sign Up Here"}
	c.HTML(http.StatusOK, "login.html", a)
}

func (db *DB) signupHandler(c *gin.Context) {
	// add username and hashed password to the database
	username := c.Request.FormValue("username")
	password := c.Request.FormValue("password")
	// get the hash of the password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), 10)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// store in db
	stmt, _ := db.db.Prepare("INSERT INTO users (username, passwordHash) VALUES (?, ?)")
	_, err = stmt.Exec(username, passwordHash)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	// generate token
	claims := jwt.MapClaims{
		"username":  username,
		"ExpiresAt": 15000,
		"IssuedAt":  time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(secretKey)
	resp := TokenResponse{
		Token:  tokenString,
		Status: "success",
	}
	c.JSON(http.StatusCreated, gin.H{
		"message": "user created successfully",
		"status":  "success",
		"data":    resp,
	})
}

func (db *DB) loginHandler(c *gin.Context) {
	// check databse if username and password exists. if so return success and token
	username := c.Request.FormValue("username")
	password := c.Request.FormValue("password")
	var passordDb string
	err := db.db.QueryRow("SELECT passwordHash FROM users WHERE username = ?", username).Scan(&passordDb)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": fmt.Sprintf("username %v does not exist", username),
			"status":  "failure",
		})
		return
	}
	// validate user
	if err := bcrypt.CompareHashAndPassword([]byte(passordDb), []byte(password)); err != nil {
		c.JSON(http.StatusForbidden, gin.H{
			"message": "username and password does not match",
			"status":  "failure",
		})
		return
	}
	// generate token
	claims := jwt.MapClaims{
		"username":  username,
		"ExpiresAt": 15000,
		"IssuedAt":  time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(secretKey)
	resp := TokenResponse{
		Token:  tokenString,
		Status: "success",
	}

	c.JSON(http.StatusAccepted, gin.H{
		"message": "login successful",
		"status":  "success",
		"data":    resp,
	})
}

func (db *DB) getArticles(c *gin.Context) {
	user, err := authorizeClient(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "access denied",
			"status":  "failure",
			"error":   err.Error(),
		})
		return
	}

	var articles []utils.Article
	rows, err := db.db.Query("SELECT * FROM articles")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}
	for rows.Next() {
		var a utils.Article
		rows.Scan(&a.Id, &a.Title, &a.Author, &a.Url)
		articles = append(articles, a)
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "query successful",
		"status":  "success",
		"user":    user,
		"results": articles,
	})

}

func (db *DB) createArticle(c *gin.Context) {
	user, err := authorizeClient(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "access denied",
			"status":  "failure",
			"error":   err.Error(),
		})
		return
	}
	var a utils.Article
	err = c.BindJSON(&a)
	log.Println(a)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	stmt, err := db.db.Prepare("INSERT INTO articles (Title, Author, Url) VALUES (?, ?, ?);")
	if err != nil {
		log.Println(err)
	}
	result, err := stmt.Exec(a.Title, a.Author, a.Url)
	if err == nil {
		id, _ := result.LastInsertId()
		a.Id = int(id)
		c.JSON(http.StatusCreated, gin.H{
			"message": "article created successfully",
			"status":  "success",
			"data":    a.Id,
			"user":    user,
		})
	} else {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
	}
}

func authorizeClient(c *gin.Context) (interface{}, error) {
	tokenString := c.GetHeader("access_token")
	if tokenString == "" {
		return nil, fmt.Errorf("access token not provided with request header")
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", token.Header["alg"])
		}
		return secretKey, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims["username"].(string), nil
	} else {
		return nil, fmt.Errorf("invalid token")
	}

}

func main() {
	db, err := sql.Open("sqlite3", "./articles.db")
	if err != nil {
		log.Fatal("Failed to connect to database", err)
	}
	stmt, _ := db.Prepare(utils.Articles)
	_, err = stmt.Exec()
	if err != nil {
		log.Fatal("Failed to create tables")
	}
	stmt, _ = db.Prepare(utils.Users)
	_, err = stmt.Exec()
	if err != nil {
		log.Fatal("Failed to create tables")
	}
	driver := DB{db: db}
	r := gin.Default()
	r.LoadHTMLFiles("login.html")
	r.GET("/login", loginPage)
	r.POST("/login", driver.loginHandler)
	r.GET("/signup", signupPage)
	r.POST("/signup", driver.signupHandler)
	r.GET("api/v1/articles", driver.getArticles)
	r.POST("api/v1/articles", driver.createArticle)
	r.Run(":8000")
}
